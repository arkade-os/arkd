package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

const maxSweepInputs = 1000

type AdminService interface {
	Wallet() ports.WalletService
	GetScheduledSweeps(ctx context.Context, limit int64) ([]domain.ScheduledSweep, error)
	// GetRoundDetails accepts either a batch id or a commitment txid.
	GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error)
	// GetRoundIntents returns the intents registered in a batch as they were persisted,
	// so they can be inspected even if the batch failed. It accepts either a batch id or
	// a commitment txid.
	GetRoundIntents(ctx context.Context, roundId string) ([]IntentInfo, error)
	GetRounds(
		ctx context.Context, after, before int64, withFailed, withCompleted, onlyFailed bool,
		limit int64,
	) ([]domain.RoundSummary, error)
	GetOffchainTxs(
		ctx context.Context, after, before int64, onlyFailed, onlyCompleted bool, limit int64,
	) ([]*domain.OffchainTx, error)
	GetOffchainTxDetails(ctx context.Context, txid string) (*domain.OffchainTx, error)
	GetFeeRate(ctx context.Context) (uint64, error)
	GetExpiredRounds(ctx context.Context) ([]domain.ExpiredRound, error)
	GetWalletAddress(ctx context.Context) (string, error)
	GetWalletStatus(ctx context.Context) (*WalletStatus, error)
	GetMainAccountUtxos(ctx context.Context) ([]ports.WalletUtxo, error)
	CreateNotes(ctx context.Context, amount uint32, quantity int) ([]string, error)
	GetScheduledSession(ctx context.Context) (*domain.ScheduledSession, error)
	UpdateScheduledSession(ctx context.Context, updates domain.ScheduledSessionUpdate) error
	ClearScheduledSession(ctx context.Context) error
	ListIntents(ctx context.Context, intentIds ...string) ([]IntentInfo, error)
	DeleteIntents(ctx context.Context, intentIds ...string) error
	GetBatchFees(ctx context.Context) (*domain.BatchFees, error)
	UpdateBatchFees(ctx context.Context, updates domain.BatchFeesUpdate) error
	ClearBatchFees(ctx context.Context) error
	GetConvictionsByIds(ctx context.Context, ids []string) ([]domain.Conviction, error)
	GetConvictions(ctx context.Context, from, to time.Time) ([]domain.Conviction, error)
	GetConvictionsByRound(ctx context.Context, roundID string) ([]domain.Conviction, error)
	GetActiveScriptConvictions(
		ctx context.Context, script string,
	) ([]domain.ScriptConviction, error)
	PardonConviction(ctx context.Context, id string) error
	BanScript(ctx context.Context, script, reason string, banDuration *time.Duration) error
	Sweep(
		ctx context.Context, withConnectors bool, commitmentTxids []string,
	) (string, string, error)
	GetExpiringLiquidity(ctx context.Context, after, before int64) (uint64, error)
	GetRecoverableLiquidity(ctx context.Context) (uint64, error)
	GetSettings(ctx context.Context) (*domain.Settings, error)
	UpdateSettings(ctx context.Context, settings domain.SettingsUpdate) ([]string, error)
	GetCollectedFees(ctx context.Context, after, before int64) (uint64, error)
}

type adminService struct {
	walletSvc       ports.WalletService
	repoManager     ports.RepoManager
	txBuilder       ports.TxBuilder
	sweeperTimeUnit ports.TimeUnit
	liveStore       ports.LiveStore
	feeManager      ports.FeeManager
	// settingsMu serializes the read-modify-write cycles against the singleton
	// settings row (UpdateSettings and the scheduled-session/batch-fees mutators)
	// so concurrent admin calls can't lose each other's updates.
	settingsMu sync.Mutex
}

func NewAdminService(
	walletSvc ports.WalletService, repoManager ports.RepoManager, txBuilder ports.TxBuilder,
	liveStoreSvc ports.LiveStore, timeUnit ports.TimeUnit, feeManager ports.FeeManager,
) AdminService {
	return &adminService{
		walletSvc:       walletSvc,
		repoManager:     repoManager,
		txBuilder:       txBuilder,
		sweeperTimeUnit: timeUnit,
		liveStore:       liveStoreSvc,
		feeManager:      feeManager,
	}
}

func (a *adminService) Wallet() ports.WalletService {
	return a.walletSvc
}

func (a *adminService) GetMainAccountUtxos(ctx context.Context) ([]ports.WalletUtxo, error) {
	return a.walletSvc.GetMainAccountUtxos(ctx)
}

func (a *adminService) GetRoundDetails(
	ctx context.Context, roundId string,
) (*RoundDetails, error) {
	round, err := a.getRound(ctx, roundId)
	if err != nil {
		return nil, err
	}

	var totalForfeitAmount, totalVtxosAmount, totalExitAmount uint64
	exitAddresses := make([]string, 0)
	inputVtxos := make([]string, 0)
	outputVtxos := make([]string, 0)
	for _, intent := range round.Intents {
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
		RoundSummary:     roundSummary(round),
		ForfeitedAmount:  totalForfeitAmount,
		TotalVtxosAmount: totalVtxosAmount,
		TotalExitAmount:  totalExitAmount,
		ExitAddresses:    exitAddresses,
		FeesAmount:       round.CollectedFees,
		InputVtxos:       inputVtxos,
		OutputVtxos:      outputVtxos,
	}, nil
}

func (a *adminService) GetRoundIntents(
	ctx context.Context, roundId string,
) ([]IntentInfo, error) {
	round, err := a.getRound(ctx, roundId)
	if err != nil {
		return nil, err
	}

	intentsInfo := make([]IntentInfo, 0, len(round.Intents))
	for _, intent := range round.Intents {
		receivers, err := receiversInfo(intent.Receivers)
		if err != nil {
			return nil, err
		}

		// Boarding inputs and cosigner pubkeys are not persisted with the intent, they
		// only live in the intent queue, so they are left empty here.
		intentsInfo = append(intentsInfo, IntentInfo{
			Id:        intent.Id,
			Receivers: receivers,
			Inputs:    intent.Inputs,
			Proof:     intent.Proof,
			Message:   intent.Message,
		})
	}

	return intentsInfo, nil
}

// GetRounds lists batches. Filtering, ordering and the limit are pushed into the
// repository query, so a wide window costs one round trip rather than loading
// every round in the range.
func (a *adminService) GetRounds(
	ctx context.Context, after, before int64, withFailed, withCompleted, onlyFailed bool,
	limit int64,
) ([]domain.RoundSummary, error) {
	return a.repoManager.Rounds().GetRoundSummaries(
		ctx, after, before, withFailed, withCompleted, onlyFailed, limit,
	)
}

func (a *adminService) GetOffchainTxs(
	ctx context.Context, after, before int64, onlyFailed, onlyCompleted bool, limit int64,
) ([]*domain.OffchainTx, error) {
	txs, err := a.repoManager.OffchainTxs().GetOffchainTxsInRange(
		ctx, after, before, onlyFailed, onlyCompleted, limit,
	)
	if err != nil {
		return nil, err
	}

	sort.Slice(txs, func(i, j int) bool {
		return txs[i].StartingTimestamp > txs[j].StartingTimestamp
	})

	return txs, nil
}

func (a *adminService) GetOffchainTxDetails(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	return a.repoManager.OffchainTxs().GetAnyOffchainTx(ctx, txid)
}

func (a *adminService) GetFeeRate(ctx context.Context) (uint64, error) {
	return a.walletSvc.FeeRate(ctx)
}

// getRound loads a batch by its id, or by its commitment txid if the given value looks
// like one. Batch ids are uuids, so the two can never be confused.
func (a *adminService) getRound(ctx context.Context, id string) (*domain.Round, error) {
	if isTxid(id) {
		return a.repoManager.Rounds().GetRoundWithCommitmentTxid(ctx, id)
	}
	return a.repoManager.Rounds().GetRoundWithId(ctx, id)
}

func isTxid(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// receiversInfo turns the receivers of an intent into their inspectable form, encoding
// the offchain ones as vtxo scripts.
func receiversInfo(list []domain.Receiver) ([]Receiver, error) {
	receivers := make([]Receiver, 0, len(list))
	for _, receiver := range list {
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
	return receivers, nil
}

func roundSummary(round *domain.Round) domain.RoundSummary {
	return domain.RoundSummary{
		RoundId:        round.Id,
		CommitmentTxid: round.CommitmentTxid,
		StartedAt:      round.StartingTimestamp,
		EndedAt:        round.EndingTimestamp,
		Stage:          domain.RoundStage(round.Stage.Code).String(),
		Ended:          round.IsEnded(),
		Failed:         round.IsFailed(),
		Swept:          round.Swept,
		FailReason:     round.FailReason,
		TotalIntents:   int64(len(round.Intents)),
	}
}

// GetScheduledSweeps lists the batches awaiting a sweep, soonest due first.
func (a *adminService) GetScheduledSweeps(
	ctx context.Context, limit int64,
) ([]domain.ScheduledSweep, error) {
	return a.repoManager.Rounds().GetScheduledSweeps(ctx, limit)
}

// GetExpiredRounds returns the sweepable rounds (those with a vtxo tree) whose
// batch outputs have already expired but have not been swept yet. These are
// rounds for which the sweep should have happened but likely failed.
func (a *adminService) GetExpiredRounds(
	ctx context.Context,
) ([]domain.ExpiredRound, error) {
	return a.repoManager.Rounds().GetExpiredRounds(ctx, time.Now().Unix())
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

func (s *adminService) GetScheduledSession(
	ctx context.Context,
) (*domain.ScheduledSession, error) {
	settings, err := s.repoManager.Settings().Get(ctx)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		return nil, fmt.Errorf("settings not found")
	}
	return settings.ScheduledSession, nil
}

func (s *adminService) UpdateScheduledSession(
	ctx context.Context, updates domain.ScheduledSessionUpdate,
) error {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()

	settings, err := s.repoManager.Settings().Get(ctx)
	if err != nil {
		return err
	}
	if settings == nil {
		return fmt.Errorf("settings not found")
	}

	changelog, err := settings.UpdateScheduledSession(updates)
	if err != nil {
		return err
	}

	return s.repoManager.Settings().Upsert(ctx, *settings, changelog)
}

func (s *adminService) ClearScheduledSession(ctx context.Context) error {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()

	settings, err := s.repoManager.Settings().Get(ctx)
	if err != nil {
		return err
	}
	if settings == nil {
		return fmt.Errorf("settings not found")
	}

	changelog := settings.ClearScheduledSession()

	return s.repoManager.Settings().Upsert(ctx, *settings, changelog)
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
		receivers, err := receiversInfo(intent.Receivers)
		if err != nil {
			return nil, err
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

func (s *adminService) GetBatchFees(ctx context.Context) (*domain.BatchFees, error) {
	settings, err := s.repoManager.Settings().Get(ctx)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		return nil, fmt.Errorf("settings not found")
	}
	return &settings.BatchFees, nil
}

func (s *adminService) UpdateBatchFees(ctx context.Context, updates domain.BatchFeesUpdate) error {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()

	settings, err := s.repoManager.Settings().Get(ctx)
	if err != nil {
		return err
	}
	if settings == nil {
		return fmt.Errorf("settings not found")
	}

	changelog, err := settings.UpdateBatchFees(updates)
	if err != nil {
		return err
	}

	return s.repoManager.Settings().Upsert(ctx, *settings, changelog)
}

// Zeroes out fees
func (s *adminService) ClearBatchFees(ctx context.Context) error {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()

	settings, err := s.repoManager.Settings().Get(ctx)
	if err != nil {
		return err
	}
	if settings == nil {
		return fmt.Errorf("settings not found")
	}

	changelog := settings.ClearBatchFees()

	return s.repoManager.Settings().Upsert(ctx, *settings, changelog)
}

// Conviction management methods
func (s *adminService) GetConvictionsByIds(
	ctx context.Context, ids []string,
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
	ctx context.Context, from, to time.Time,
) ([]domain.Conviction, error) {
	return s.repoManager.Convictions().GetAll(ctx, from, to)
}

func (s *adminService) GetConvictionsByRound(
	ctx context.Context, roundID string,
) ([]domain.Conviction, error) {
	return s.repoManager.Convictions().GetByRoundID(ctx, roundID)
}

func (s *adminService) GetActiveScriptConvictions(
	ctx context.Context, script string,
) ([]domain.ScriptConviction, error) {
	return s.repoManager.Convictions().GetActiveScriptConvictions(ctx, script)
}

func (s *adminService) PardonConviction(ctx context.Context, id string) error {
	return s.repoManager.Convictions().Pardon(ctx, id)
}

func (s *adminService) BanScript(
	ctx context.Context, script, reason string, banDuration *time.Duration,
) error {
	crime := domain.Crime{
		Type:    domain.CrimeTypeManualBan,
		RoundID: "manual-ban",
		Reason:  reason,
	}

	conviction := domain.NewScriptConviction(script, crime, banDuration)
	return s.repoManager.Convictions().Add(ctx, conviction)
}

func (a *adminService) Sweep(
	ctx context.Context, withConnectors bool, commitmentTxids []string,
) (txid string, txhex string, err error) {
	inputs := make([]ports.TxInput, 0)
	connectorsToLock := make([]domain.Outpoint, 0)
	// truncated is set when the maxSweepInputs cap is reached while sweepable
	// outputs remain; those are left for a subsequent sweep call.
	truncated := false

	if withConnectors {
		connectorAddresses, err := a.repoManager.Rounds().GetSweptRoundsConnectorAddress(ctx)
		if err != nil {
			return "", "", err
		}

		connectorUtxos, err := a.walletSvc.ListConnectorUtxos(ctx, connectorAddresses)
		if err != nil {
			return "", "", err
		}

		for _, utxo := range connectorUtxos {
			if len(inputs) >= maxSweepInputs {
				truncated = true
				break
			}
			connectorsToLock = append(connectorsToLock, domain.Outpoint{
				Txid: utxo.Txid,
				VOut: utxo.Index,
			})
			inputs = append(inputs, utxo)
		}
	}

	now := time.Now()

	// keep round and vtxo tree for each commitment txid
	// we'll reuse them later to generate batch swept events
	batchInputs := make(map[string][]ports.TxInput)
	batchRounds := make(map[string]*domain.Round)
	batchVtxoTrees := make(map[string]*tree.TxTree)

	// for each commitment txid, find the sweepable outputs and add them to the inputs
	for _, commitmentTxid := range commitmentTxids {
		if len(inputs) >= maxSweepInputs {
			truncated = true
			break
		}

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
			ctx, a.walletSvc, a.txBuilder, a.sweeperTimeUnit, vtxoTree,
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

			for _, batchOutput := range batchOutputs {
				if len(inputs) >= maxSweepInputs {
					truncated = true
					break
				}
				batchInputsList = append(batchInputsList, batchOutput)
				inputs = append(inputs, batchOutput)
			}

			if truncated {
				break
			}
		}

		if len(batchInputsList) > 0 {
			batchInputs[commitmentTxid] = batchInputsList
		}
	}

	if len(inputs) == 0 {
		return "", "", fmt.Errorf("no funds to sweep")
	}

	if truncated {
		log.Warnf(
			"sweep: input count capped at %d; remaining sweepable outputs left for a subsequent sweep",
			maxSweepInputs,
		)
	}

	txid, txhex, err = a.txBuilder.BuildSweepTx(inputs)
	if err != nil {
		return
	}

	if len(connectorsToLock) > 0 {
		if err := a.walletSvc.LockConnectorUtxos(ctx, connectorsToLock); err != nil {
			return "", "", err
		}
	}

	// broadcast the sweep transaction
	txid, err = a.walletSvc.BroadcastTransaction(ctx, txhex)
	if err != nil {
		return
	}

	log.Infof("sweep transaction %s broadcasted", txid)

	if len(batchInputs) > 0 {
		go a.saveBatchSweptEvents(
			context.WithoutCancel(ctx), batchInputs, batchRounds, batchVtxoTrees, txid, txhex,
		)
	}

	return
}

func (a *adminService) GetExpiringLiquidity(
	ctx context.Context, after, before int64,
) (uint64, error) {
	return a.repoManager.Vtxos().GetExpiringLiquidity(ctx, after, before)
}

func (a *adminService) GetRecoverableLiquidity(ctx context.Context) (uint64, error) {
	return a.repoManager.Vtxos().GetRecoverableLiquidity(ctx)
}

func (a *adminService) GetSettings(ctx context.Context) (*domain.Settings, error) {
	return a.repoManager.Settings().Get(ctx)
}

func (a *adminService) UpdateSettings(
	ctx context.Context, updates domain.SettingsUpdate,
) ([]string, error) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()

	// Partial update: only the fields set on the request (non-nil pointers) are
	// applied to the stored settings; omitted fields are left unchanged. The
	// returned changelog lists exactly the fields that were updated.
	settings, err := a.repoManager.Settings().Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current settings: %w", err)
	}
	if settings == nil {
		return nil, fmt.Errorf("no settings found")
	}

	changelog, err := settings.Update(updates)
	if err != nil {
		return nil, err
	}

	if err := a.repoManager.Settings().Upsert(ctx, *settings, changelog); err != nil {
		return nil, fmt.Errorf("failed to update settings: %w", err)
	}

	return changelog, nil
}

// GetCollectedFees totals the fees recorded against batches finalized in the
// window. One indexed aggregate: it used to load every round in the window in
// full — intents, receivers, inputs, txs and vtxo trees — plus a wallet RPC per
// boarding input, to produce a single integer.
func (a *adminService) GetCollectedFees(
	ctx context.Context, after, before int64,
) (uint64, error) {
	return a.repoManager.Rounds().SumCollectedFees(ctx, after, before)
}

func (a *adminService) saveBatchSweptEvents(
	ctx context.Context,
	inputsByCommitmentTxid map[string][]ports.TxInput,
	batchesByCommitmentTxid map[string]*domain.Round,
	treesByCommitmentTxid map[string]*tree.TxTree,
	txid, txhex string,
) {
	for commitmentTxid, batchInputsList := range inputsByCommitmentTxid {
		round := batchesByCommitmentTxid[commitmentTxid]

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
				vtxoTree, ok := treesByCommitmentTxid[commitmentTxid]
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
					// The VTXO is the first non-anchor output; leaf txs can
					// carry an anchor at vout 0, so the VTXO is not always at
					// vout 0. extractVtxoOutpoint handles that.
					vtxo, err := extractVtxoOutpoint(leaf)
					if err != nil {
						log.WithError(err).Errorf(
							"failed to extract vtxo outpoint from leaf %s",
							leaf.UnsignedTx.TxID(),
						)
						continue
					}
					leafVtxos = append(leafVtxos, *vtxo)
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
				children, err := vtxoRepo.GetAllChildrenVtxos(ctx, leafVtxo)
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

		events, err := round.Sweep(leafVtxos, preconfirmedVtxos, txid, txhex)
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

type RoundDetails struct {
	domain.RoundSummary
	ForfeitedAmount  uint64
	TotalVtxosAmount uint64
	TotalExitAmount  uint64
	FeesAmount       uint64
	InputVtxos       []string
	OutputVtxos      []string
	ExitAddresses    []string
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
