package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

const maxSweepInputs = 1000

type AdminService interface {
	Wallet() ports.WalletService
	GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error)
	GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error)
	GetRounds(
		ctx context.Context, after, before int64, withFailed, withCompleted bool,
	) ([]string, error)
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
	round, err := a.repoManager.Rounds().GetRoundWithId(ctx, roundId)
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
		RoundId:          round.Id,
		TxId:             round.CommitmentTxid,
		ForfeitedAmount:  totalForfeitAmount,
		TotalVtxosAmount: totalVtxosAmount,
		TotalExitAmount:  totalExitAmount,
		ExitAddresses:    exitAddresses,
		FeesAmount:       round.CollectedFees,
		InputVtxos:       inputVtxos,
		OutputVtxos:      outputVtxos,
		StartedAt:        round.StartingTimestamp,
		EndedAt:          round.EndingTimestamp,
	}, nil
}

func (a *adminService) GetRounds(
	ctx context.Context, after, before int64, withFailed, withCompleted bool,
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

func (a *adminService) GetCollectedFees(
	ctx context.Context, after, before int64,
) (uint64, error) {
	roundIds, err := a.repoManager.Rounds().GetRoundIds(ctx, after, before, false, true)
	if err != nil {
		return 0, err
	}

	var total uint64
	// batchesToPatch is used to keep track of the batches for which we calculcated fees,
	// so we can lazily patch the missing info in storage for batches prior
	// https://github.com/arkade-os/arkd/pull/933.
	batchesToPatch := make(map[string]uint64)
	for _, id := range roundIds {
		round, err := a.repoManager.Rounds().GetRoundWithId(ctx, id)
		if err != nil {
			return 0, err
		}

		// Batches finalized before fee persistence have a zero (default) collected fee;
		// recompute it on the fly. Only patch (persist) when the recomputation is complete,
		// so we never persist a value that under-counts boarding.
		if round.CollectedFees == 0 {
			fees, complete := a.recomputeCollectedFees(ctx, round)
			total += fees
			if complete && fees > 0 {
				batchesToPatch[round.Id] = fees
			}
			continue
		}
		total += round.CollectedFees
	}

	if len(batchesToPatch) > 0 {
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if err := a.repoManager.Rounds().PatchCollectedFees(ctx, batchesToPatch); err != nil {
				log.WithError(err).WithField("patches", batchesToPatch).Warn(
					"failed to patch collected fees",
				)
			}
		}()
	}

	return total, nil
}

// recomputeCollectedFees recomputes the fees collected by the operator for a batch whose fee was
// not persisted (finalized before fee persistence). It recovers the boarding input amount from the
// finalized commitment tx and returns whether the recomputation was complete.
// When complete is false the boarding amount could not be recovered, so the returned value
// under-counts the real fee and must not be persisted (a later call can retry).
func (a *adminService) recomputeCollectedFees(
	ctx context.Context, round *domain.Round,
) (fees uint64, complete bool) {
	boardingInputAmount, err := a.boardingInputAmount(ctx, round.CommitmentTx)
	if err != nil {
		log.WithError(err).WithField("round_id", round.Id).Warn(
			"failed to recover boarding input amount, collected fees may be underestimated",
		)
		return calculateCollectedFees(round, 0), false
	}
	return calculateCollectedFees(round, boardingInputAmount), true
}

// boardingInputAmount computes the total amount (sats) of the boarding inputs of
// a finalized (raw) commitment tx. Boarding inputs are detected by their taproot
// script-path witness; since a raw tx carries no input amounts, each boarding
// input's value is looked up from its prevout via the wallet.
func (a *adminService) boardingInputAmount(
	ctx context.Context, commitmentTx string,
) (uint64, error) {
	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(commitmentTx))); err != nil {
		return 0, fmt.Errorf("failed to deserialize commitment tx: %w", err)
	}

	var total uint64
	for _, in := range tx.TxIn {
		if !isBoardingWitness(in.Witness) {
			continue
		}

		prevTxid := in.PreviousOutPoint.Hash.String()
		prevTxHex, err := a.walletSvc.GetTransaction(ctx, prevTxid)
		if err != nil {
			return 0, fmt.Errorf("failed to get boarding prevout tx %s: %w", prevTxid, err)
		}

		var prevTx wire.MsgTx
		if err := prevTx.Deserialize(hex.NewDecoder(strings.NewReader(prevTxHex))); err != nil {
			return 0, fmt.Errorf("failed to deserialize boarding prevout tx %s: %w", prevTxid, err)
		}

		vout := in.PreviousOutPoint.Index
		if int(vout) >= len(prevTx.TxOut) {
			return 0, fmt.Errorf(
				"boarding prevout %s:%d out of range", prevTxid, vout,
			)
		}
		total += uint64(prevTx.TxOut[vout].Value)
	}

	return total, nil
}

func (a *adminService) getScheduledSweep(
	ctx context.Context, commitmentTxid string,
) (*ScheduledSweep, error) {
	confirmed, _, err := a.walletSvc.IsTransactionConfirmed(ctx, commitmentTxid)
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
					// a leaf tx may pay multiple receivers, collect every vtxo outpoint it carries
					leafVtxos = append(leafVtxos, leafVtxoOutpoints(leaf)...)
				}
			}
		}

		preconfirmedVtxos := collectPreconfirmedVtxos(
			ctx, vtxoRepo, commitmentTxid, commitmentRootSwept, leafVtxos,
		)

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
