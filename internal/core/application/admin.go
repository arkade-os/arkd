package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

type AdminService interface {
	Wallet() ports.WalletService
	GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error)
	GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error)
	GetRounds(
		ctx context.Context,
		after int64,
		before int64,
		withFailed, withCompleted bool,
	) ([]string, error)
	GetWalletAddress(ctx context.Context) (string, error)
	GetWalletStatus(ctx context.Context) (*WalletStatus, error)
	CreateNotes(ctx context.Context, amount uint32, quantity int) ([]string, error)
	GetScheduledSessionConfig(ctx context.Context) (*domain.ScheduledSession, error)
	UpdateScheduledSessionConfig(
		ctx context.Context, scheduledSessionStartTime, scheduledSessionEndTime time.Time,
		period, duration time.Duration, roundMinParticipantsCount, roundMaxParticipantsCount int64,
	) error
	ClearScheduledSessionConfig(ctx context.Context) error
	ListIntents(ctx context.Context, intentIds ...string) ([]IntentInfo, error)
	DeleteIntents(ctx context.Context, intentIds ...string) error
	GetConvictionsByIds(ctx context.Context, ids []string) ([]domain.Conviction, error)
	GetConvictions(ctx context.Context, from, to time.Time) ([]domain.Conviction, error)
	GetConvictionsByRound(ctx context.Context, roundID string) ([]domain.Conviction, error)
	GetActiveScriptConvictions(
		ctx context.Context, script string,
	) ([]domain.ScriptConviction, error)
	PardonConviction(ctx context.Context, id string) error
	BanScript(ctx context.Context, script, reason string, banDuration *time.Duration) error
	Sweep(
		ctx context.Context,
		withConnectors bool,
		commitmentTxids []string,
	) (string, string, error)
}

type adminService struct {
	walletSvc       ports.WalletService
	repoManager     ports.RepoManager
	txBuilder       ports.TxBuilder
	sweeperTimeUnit ports.TimeUnit
	liveStore       ports.LiveStore

	roundMinParticipantsCount int64
	roundMaxParticipantsCount int64
}

func NewAdminService(
	walletSvc ports.WalletService, repoManager ports.RepoManager, txBuilder ports.TxBuilder,
	liveStoreSvc ports.LiveStore, timeUnit ports.TimeUnit,
	roundMinParticipantsCount, roundMaxParticipantsCount int64,
) AdminService {
	return &adminService{
		walletSvc:                 walletSvc,
		repoManager:               repoManager,
		txBuilder:                 txBuilder,
		sweeperTimeUnit:           timeUnit,
		liveStore:                 liveStoreSvc,
		roundMinParticipantsCount: roundMinParticipantsCount,
		roundMaxParticipantsCount: roundMaxParticipantsCount,
	}
}

func (a *adminService) Sweep(
	ctx context.Context,
	withConnectors bool,
	commitmentTxids []string,
) (txid string, txhex string, err error) {
	inputs := make([]ports.TxInput, 0)

	if withConnectors {
		connectorAddresses, err := a.repoManager.Rounds().GetSweptRoundsConnectorAddress(ctx)
		if err != nil {
			return "", "", err
		}

		connectorUtxos := make([]ports.TxInput, 0)
		for _, connectorAddress := range connectorAddresses {
			utxos, err := a.walletSvc.ListConnectorUtxos(ctx, connectorAddress)
			if err != nil {
				return "", "", err
			}
			connectorUtxos = append(connectorUtxos, utxos...)
		}

		outpoints := make([]domain.Outpoint, 0)
		for _, utxo := range connectorUtxos {
			outpoints = append(outpoints, domain.Outpoint{
				Txid: utxo.Txid,
				VOut: utxo.Index,
			})
		}

		if err := a.walletSvc.LockConnectorUtxos(ctx, outpoints); err != nil {
			return "", "", err
		}

		inputs = append(inputs, connectorUtxos...)
	}

	now := time.Now()

	// keep round and vtxo tree for each commitment txid
	// we'll reuse them later to generate batch swept events
	batchInputs := make(map[string][]ports.TxInput)
	batchRounds := make(map[string]*domain.Round)
	batchVtxoTrees := make(map[string]*tree.TxTree)

	// for each commitment txid, find the sweepable outputs and add them to the inputs
	for _, commitmentTxid := range commitmentTxids {
		// Get the round first (contains VtxoTree)
		round, err := a.repoManager.Rounds().GetRoundWithCommitmentTxid(ctx, commitmentTxid)
		if err != nil {
			return "", "", fmt.Errorf(
				"failed to get round for commitment txid %s: %w",
				commitmentTxid,
				err,
			)
		}

		if round.Swept {
			return "", "", fmt.Errorf("commitment txid %s already swept", commitmentTxid)
		}

		vtxoTree, err := tree.NewTxTree(round.VtxoTree)
		if err != nil {
			return "", "", fmt.Errorf(
				"failed to create vtxo tree for commitment txid %s: %w",
				commitmentTxid,
				err,
			)
		}

		batchRounds[commitmentTxid] = round
		batchVtxoTrees[commitmentTxid] = vtxoTree

		sweepableOutputs, err := findSweepableOutputs(
			ctx,
			a.walletSvc,
			a.txBuilder,
			a.sweeperTimeUnit,
			vtxoTree,
		)
		if err != nil {
			return "", "", fmt.Errorf(
				"failed to find sweepable outputs for commitment txid %s: %w",
				commitmentTxid,
				err,
			)
		}

		batchInputsList := make([]ports.TxInput, 0)
		for expirationTime, batchOutputs := range sweepableOutputs {
			if time.Unix(expirationTime, 0).After(now) {
				continue
			}

			batchInputsList = append(batchInputsList, batchOutputs...)
			inputs = append(inputs, batchOutputs...)
		}

		if len(batchInputsList) > 0 {
			batchInputs[commitmentTxid] = batchInputsList
		}
	}

	if len(inputs) == 0 {
		return "", "", fmt.Errorf("no funds to sweep")
	}

	txid, txhex, err = a.txBuilder.BuildSweepTx(inputs)
	if err != nil {
		return
	}

	// broadcast the sweep transaction
	txid, err = a.walletSvc.BroadcastTransaction(ctx, txhex)
	if err != nil {
		return
	}

	log.Infof("sweep transaction %s broadcasted", txid)

	if len(batchInputs) > 0 {
		go a.saveBatchSweptEvents(batchInputs, batchRounds, batchVtxoTrees, txid, txhex)
	}

	return
}

func (a *adminService) saveBatchSweptEvents(
	batchInputs map[string][]ports.TxInput,
	batchRounds map[string]*domain.Round,
	batchVtxoTrees map[string]*tree.TxTree,
	txid, txhex string,
) {
	ctx := context.Background()

	for commitmentTxid, batchInputsList := range batchInputs {
		round := batchRounds[commitmentTxid]

		leafVtxos := make([]domain.Outpoint, 0)
		vtxoRepo := a.repoManager.Vtxos()

		commitmentRootSwept := false
		for _, input := range batchInputsList {
			if input.Txid == commitmentTxid {
				commitmentRootSwept = true
				break
			}
		}

		// find leaf vtxos for each input
		for _, input := range batchInputsList {
			vtxos, _ := vtxoRepo.GetVtxos(
				ctx,
				[]domain.Outpoint{
					{
						Txid: input.Txid,
						VOut: input.Index,
					},
				},
			)
			if len(vtxos) > 0 {
				if !vtxos[0].Swept && !vtxos[0].Unrolled {
					leafVtxos = append(leafVtxos, vtxos[0].Outpoint)
				}
			} else {
				vtxoTree, ok := batchVtxoTrees[commitmentTxid]
				if !ok {
					log.Errorf("vtxo tree for batch %s not found", commitmentTxid)
					continue
				}

				vtxosLeaves, err := findLeaves(vtxoTree, input.Txid, input.Index)
				if err != nil {
					log.WithError(err).Errorf(
						"failed to get leaves from vtxo tree of batch %s", commitmentTxid,
					)
					continue
				}

				for _, leaf := range vtxosLeaves {
					vtxo := domain.Outpoint{
						Txid: leaf.UnsignedTx.TxID(),
						VOut: 0,
					}
					leafVtxos = append(leafVtxos, vtxo)
				}
			}
		}

		// get preconfirmed vtxos
		preconfirmedVtxos := make([]domain.Outpoint, 0)
		if commitmentRootSwept {
			var err error
			preconfirmedVtxos, err = vtxoRepo.GetSweepableVtxosByCommitmentTxid(
				ctx,
				commitmentTxid,
			)
			if err != nil {
				log.WithError(err).
					Error("error while getting sweepable vtxos by commitment txid")
			}
		} else {
			seen := make(map[string]struct{})
			for _, leafVtxo := range leafVtxos {
				children, err := vtxoRepo.GetAllChildrenVtxos(ctx, leafVtxo.Txid)
				if err != nil {
					log.WithError(err).Error("error while getting children vtxos")
					continue
				}
				for _, child := range children {
					if _, ok := seen[child.String()]; !ok {
						preconfirmedVtxos = append(preconfirmedVtxos, child)
						seen[child.String()] = struct{}{}
					}
				}
			}
		}

		events, err := round.Sweep(
			leafVtxos,
			preconfirmedVtxos,
			txid,
			txhex,
		)
		if err != nil {
			log.WithError(err).Errorf("failed to sweep batch %s", commitmentTxid)
			continue
		}

		if len(events) > 0 {
			eventRepo := a.repoManager.Events()
			if err := eventRepo.Save(ctx, domain.RoundTopic, round.Id, events); err != nil {
				log.WithError(err).Errorf(
					"failed to save sweep events for batch %s", commitmentTxid,
				)
				continue
			}
		}
	}
}

func (a *adminService) Wallet() ports.WalletService {
	return a.walletSvc
}

func (a *adminService) GetRoundDetails(
	ctx context.Context, roundId string,
) (*RoundDetails, error) {
	round, err := a.repoManager.Rounds().GetRoundWithId(ctx, roundId)
	if err != nil {
		return nil, err
	}

	var totalForfeitAmount, totalVtxosAmount, totalExitAmount uint64
	exitAddresses := make([]string, 0)
	inputVtxos := make([]string, 0)
	outputVtxos := make([]string, 0)
	for _, intent := range round.Intents {
		// TODO: Add fees amount
		totalForfeitAmount += intent.TotalInputAmount()

		for _, receiver := range intent.Receivers {
			if receiver.IsOnchain() {
				totalExitAmount += receiver.Amount
				exitAddresses = append(exitAddresses, receiver.OnchainAddress)
				continue
			}

			totalVtxosAmount += receiver.Amount
		}

		for _, input := range intent.Inputs {
			inputVtxos = append(inputVtxos, input.Outpoint.String())
		}
	}

	vtxos, err := a.repoManager.Vtxos().GetLeafVtxosForBatch(ctx, round.CommitmentTxid)
	if err != nil {
		return nil, err
	}

	for _, vtxo := range vtxos {
		outputVtxos = append(outputVtxos, vtxo.Outpoint.String())
	}

	return &RoundDetails{
		RoundId:          round.Id,
		TxId:             round.CommitmentTxid,
		ForfeitedAmount:  totalForfeitAmount,
		TotalVtxosAmount: totalVtxosAmount,
		TotalExitAmount:  totalExitAmount,
		ExitAddresses:    exitAddresses,
		FeesAmount:       0,
		InputVtxos:       inputVtxos,
		OutputVtxos:      outputVtxos,
		StartedAt:        round.StartingTimestamp,
		EndedAt:          round.EndingTimestamp,
	}, nil
}

func (a *adminService) GetRounds(
	ctx context.Context,
	after, before int64,
	withFailed, withCompleted bool,
) ([]string, error) {
	return a.repoManager.Rounds().GetRoundIds(ctx, after, before, withFailed, withCompleted)
}

func (a *adminService) GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error) {
	sweepableRounds, err := a.repoManager.Rounds().GetSweepableRounds(ctx)
	if err != nil {
		return nil, err
	}

	scheduledSweeps := make([]ScheduledSweep, 0, len(sweepableRounds))
	for _, commitmentTxid := range sweepableRounds {
		scheduledSweep, err := a.getScheduledSweep(ctx, commitmentTxid)
		if err != nil {
			log.WithError(err).Errorf("failed to get scheduled sweep for round %s", commitmentTxid)
			continue
		}
		scheduledSweeps = append(scheduledSweeps, *scheduledSweep)
	}

	return scheduledSweeps, nil
}

func (a *adminService) GetWalletAddress(ctx context.Context) (string, error) {
	addresses, err := a.walletSvc.DeriveAddresses(ctx, 1)
	if err != nil {
		return "", err
	}

	return addresses[0], nil
}

func (a *adminService) GetWalletStatus(ctx context.Context) (*WalletStatus, error) {
	status, err := a.walletSvc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &WalletStatus{
		IsInitialized: status.IsInitialized(),
		IsUnlocked:    status.IsUnlocked(),
		IsSynced:      status.IsSynced(),
	}, nil
}

// CreateNotes generates random notes and create the associated vtxos in the database
func (a *adminService) CreateNotes(
	ctx context.Context, value uint32, quantity int,
) ([]string, error) {
	notes := make([]string, 0, quantity)
	vtxos := make([]domain.Vtxo, 0, quantity)

	now := time.Now().Unix()

	for i := 0; i < quantity; i++ {
		note, err := note.NewNote(value)
		if err != nil {
			return nil, err
		}

		outpoint, pInput, err := note.IntentProofInput()
		if err != nil {
			return nil, err
		}

		vtxo := domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: outpoint.Hash.String(),
				VOut: outpoint.Index,
			},
			Amount:    uint64(note.Value),
			PubKey:    hex.EncodeToString(pInput.WitnessUtxo.PkScript[2:]),
			CreatedAt: now,
		}

		notes = append(notes, note.String())
		vtxos = append(vtxos, vtxo)
	}

	vtxoRepo := a.repoManager.Vtxos()
	if err := vtxoRepo.AddVtxos(ctx, vtxos); err != nil {
		return nil, err
	}

	return notes, nil
}

func (s *adminService) GetScheduledSessionConfig(
	ctx context.Context,
) (*domain.ScheduledSession, error) {
	return s.repoManager.ScheduledSession().Get(ctx)
}

func (s *adminService) UpdateScheduledSessionConfig(
	ctx context.Context,
	scheduledSessionStartTime, scheduledSessionEndTime time.Time, period, duration time.Duration,
	roundMinParticipantsCount, roundMaxParticipantsCount int64,
) error {
	startTimeSet := !scheduledSessionStartTime.IsZero()
	endTimeSet := !scheduledSessionEndTime.IsZero()
	if startTimeSet != endTimeSet {
		return fmt.Errorf("scheduled session start time and end time must be set together")
	}

	scheduledSession, err := s.repoManager.ScheduledSession().Get(ctx)
	if err != nil {
		return err
	}

	if scheduledSession == nil {
		if scheduledSessionStartTime.IsZero() {
			return fmt.Errorf("missing scheduled session start time")
		}
		if scheduledSessionEndTime.IsZero() {
			return fmt.Errorf("missing scheduled session end time")
		}
		if period <= 0 {
			return fmt.Errorf("missing scheduled session period")
		}
		if duration <= 0 {
			return fmt.Errorf("missing scheduled session duration")
		}
		if roundMinParticipantsCount <= 0 {
			roundMinParticipantsCount = s.roundMinParticipantsCount
		}
		if roundMaxParticipantsCount <= 0 {
			roundMaxParticipantsCount = s.roundMaxParticipantsCount
		}
	}

	now := time.Now()
	if scheduledSessionStartTime.IsZero() {
		scheduledSessionStartTime = scheduledSession.StartTime
	} else if !scheduledSessionStartTime.After(now) {
		return fmt.Errorf("scheduled session start time must be in the future")
	}

	if scheduledSessionEndTime.IsZero() {
		scheduledSessionEndTime = scheduledSession.EndTime
	} else if !scheduledSessionEndTime.After(scheduledSessionStartTime) {
		return fmt.Errorf("scheduled session end time must be after start time")
	}
	if period <= 0 {
		period = scheduledSession.Period
	}
	if duration <= 0 {
		duration = scheduledSession.Duration
	}
	if roundMinParticipantsCount <= 0 {
		roundMinParticipantsCount = scheduledSession.RoundMinParticipantsCount
	}
	if roundMaxParticipantsCount <= 0 {
		roundMaxParticipantsCount = scheduledSession.RoundMaxParticipantsCount
	}
	if roundMaxParticipantsCount < roundMinParticipantsCount {
		return fmt.Errorf(
			"got round max participants %d, expected at least %d",
			roundMaxParticipantsCount, roundMinParticipantsCount,
		)
	}

	mh := domain.NewScheduledSession(
		scheduledSessionStartTime, scheduledSessionEndTime, period, duration,
		roundMinParticipantsCount, roundMaxParticipantsCount,
	)
	if err := s.repoManager.ScheduledSession().Upsert(ctx, *mh); err != nil {
		return fmt.Errorf("failed to upsert scheduled session: %w", err)
	}

	return nil
}

func (s *adminService) ClearScheduledSessionConfig(ctx context.Context) error {
	return s.repoManager.ScheduledSession().Clear(ctx)
}

func (s *adminService) ListIntents(
	ctx context.Context, intentIds ...string,
) ([]IntentInfo, error) {
	intents, err := s.liveStore.Intents().ViewAll(ctx, intentIds)
	if err != nil {
		return nil, err
	}

	intentsInfo := make([]IntentInfo, 0, len(intents))
	for _, intent := range intents {
		receivers := make([]Receiver, 0, len(intent.Receivers))
		for _, receiver := range intent.Receivers {
			if len(receiver.OnchainAddress) > 0 {
				receivers = append(receivers, Receiver{
					OnchainAddress: receiver.OnchainAddress,
					Amount:         receiver.Amount,
				})
				continue
			}

			pubkey, err := hex.DecodeString(receiver.PubKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode pubkey: %s", err)
			}

			vtxoTapKey, err := schnorr.ParsePubKey(pubkey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse pubkey: %s", err)
			}

			outScript, err := script.P2TRScript(vtxoTapKey)
			if err != nil {
				return nil, fmt.Errorf("failed to encode vtxo script: %s", err)
			}

			receivers = append(receivers, Receiver{
				VtxoScript: hex.EncodeToString(outScript),
				Amount:     receiver.Amount,
			})
		}

		intentsInfo = append(intentsInfo, IntentInfo{
			Id:             intent.Id,
			CreatedAt:      intent.Timestamp,
			Receivers:      receivers,
			Inputs:         intent.Inputs,
			BoardingInputs: intent.BoardingInputs,
			Cosigners:      intent.CosignersPublicKeys,
			Proof:          intent.Proof,
			Message:        intent.Message,
		})
	}

	return intentsInfo, nil
}

func (s *adminService) DeleteIntents(ctx context.Context, intentIds ...string) error {
	if len(intentIds) == 0 {
		return s.liveStore.Intents().DeleteAll(ctx)
	}
	return s.liveStore.Intents().Delete(ctx, intentIds)
}

// Conviction management methods
func (s *adminService) GetConvictionsByIds(
	ctx context.Context,
	ids []string,
) ([]domain.Conviction, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("missing conviction ids")
	}

	convictions := make([]domain.Conviction, 0, len(ids))
	for _, id := range ids {
		conviction, err := s.repoManager.Convictions().Get(ctx, id)
		if err != nil {
			return nil, err
		}
		convictions = append(convictions, conviction)
	}
	return convictions, nil
}

func (s *adminService) GetConvictions(
	ctx context.Context,
	from, to time.Time,
) ([]domain.Conviction, error) {
	return s.repoManager.Convictions().GetAll(ctx, from, to)
}

func (s *adminService) GetConvictionsByRound(
	ctx context.Context,
	roundID string,
) ([]domain.Conviction, error) {
	return s.repoManager.Convictions().GetByRoundID(ctx, roundID)
}

func (s *adminService) GetActiveScriptConvictions(
	ctx context.Context,
	script string,
) ([]domain.ScriptConviction, error) {
	return s.repoManager.Convictions().GetActiveScriptConvictions(ctx, script)
}

func (s *adminService) PardonConviction(ctx context.Context, id string) error {
	return s.repoManager.Convictions().Pardon(ctx, id)
}

func (s *adminService) BanScript(
	ctx context.Context,
	script, reason string,
	banDuration *time.Duration,
) error {
	crime := domain.Crime{
		Type:    domain.CrimeTypeManualBan,
		RoundID: "manual-ban",
		Reason:  reason,
	}

	conviction := domain.NewScriptConviction(script, crime, banDuration)
	return s.repoManager.Convictions().Add(ctx, conviction)
}

func (a *adminService) getScheduledSweep(
	ctx context.Context,
	commitmentTxid string,
) (*ScheduledSweep, error) {
	confirmed, _, _, err := a.walletSvc.IsTransactionConfirmed(ctx, commitmentTxid)
	if !confirmed || err != nil {
		return &ScheduledSweep{
			RoundId:          commitmentTxid,
			Confirmed:        false,
			SweepableOutputs: make([]SweepableOutput, 0),
		}, nil
	}

	round, err := a.repoManager.Rounds().GetRoundWithCommitmentTxid(ctx, commitmentTxid)
	if err != nil {
		return nil, err
	}

	vtxoTree, err := tree.NewTxTree(round.VtxoTree)
	if err != nil {
		return nil, err
	}

	batchOutsByExpiration, err := findSweepableOutputs(
		ctx, a.walletSvc, a.txBuilder, a.sweeperTimeUnit, vtxoTree,
	)
	if err != nil {
		return nil, err
	}

	batchOutputs := make([]SweepableOutput, 0)
	for expirationTime, inputs := range batchOutsByExpiration {
		for _, input := range inputs {
			batchOutputs = append(batchOutputs, SweepableOutput{
				TxInput:     input,
				ScheduledAt: expirationTime,
			})
		}
	}

	return &ScheduledSweep{
		RoundId:          round.Id,
		SweepableOutputs: batchOutputs,
		Confirmed:        true,
	}, nil
}

type Balance struct {
	Locked    uint64
	Available uint64
}

type ArkProviderBalance struct {
	MainAccountBalance       Balance
	ConnectorsAccountBalance Balance
}

type SweepableOutput struct {
	TxInput     ports.TxInput
	ScheduledAt int64
}

type ScheduledSweep struct {
	RoundId          string
	Confirmed        bool
	SweepableOutputs []SweepableOutput
}

type RoundDetails struct {
	RoundId          string
	TxId             string
	ForfeitedAmount  uint64
	TotalVtxosAmount uint64
	TotalExitAmount  uint64
	FeesAmount       uint64
	InputVtxos       []string
	OutputVtxos      []string
	ExitAddresses    []string
	StartedAt        int64
	EndedAt          int64
}

type Receiver struct {
	VtxoScript     string
	OnchainAddress string
	Amount         uint64
}

type IntentInfo struct {
	Id             string
	CreatedAt      time.Time
	Receivers      []Receiver
	Inputs         []domain.Vtxo
	BoardingInputs []ports.BoardingInput
	Cosigners      []string
	Proof          string
	Message        string
}
