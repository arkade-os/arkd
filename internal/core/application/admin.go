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
)

type AdminService interface {
	Wallet() ports.WalletService
	GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error)
	GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error)
	GetRounds(ctx context.Context, after int64, before int64) ([]string, error)
	GetWalletAddress(ctx context.Context) (string, error)
	GetWalletStatus(ctx context.Context) (*WalletStatus, error)
	CreateNotes(ctx context.Context, amount uint32, quantity int) ([]string, error)
	GetMarketHourConfig(ctx context.Context) (*domain.MarketHour, error)
	UpdateMarketHourConfig(
		ctx context.Context,
		marketHourStartTime, marketHourEndTime time.Time, period, roundInterval time.Duration,
	) error
	ListIntents(ctx context.Context, intentIds ...string) ([]IntentInfo, error)
	DeleteIntents(ctx context.Context, intentIds ...string) error
}

type adminService struct {
	walletSvc       ports.WalletService
	repoManager     ports.RepoManager
	txBuilder       ports.TxBuilder
	sweeperTimeUnit ports.TimeUnit
	liveStore       ports.LiveStore
}

func NewAdminService(
	walletSvc ports.WalletService, repoManager ports.RepoManager, txBuilder ports.TxBuilder,
	liveStoreSvc ports.LiveStore, timeUnit ports.TimeUnit,
) AdminService {
	return &adminService{
		walletSvc:       walletSvc,
		repoManager:     repoManager,
		txBuilder:       txBuilder,
		sweeperTimeUnit: timeUnit,
		liveStore:       liveStoreSvc,
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

func (a *adminService) GetRounds(ctx context.Context, after, before int64) ([]string, error) {
	return a.repoManager.Rounds().GetRoundIds(ctx, after, before)
}

func (a *adminService) GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error) {
	sweepableRounds, err := a.repoManager.Rounds().GetSweepableRounds(ctx)
	if err != nil {
		return nil, err
	}

	scheduledSweeps := make([]ScheduledSweep, 0, len(sweepableRounds))
	for _, commitmentTxid := range sweepableRounds {
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
					SweepableOutput: input,
					ScheduledAt:     expirationTime,
				})
			}
		}

		scheduledSweeps = append(scheduledSweeps, ScheduledSweep{
			RoundId:          round.Id,
			SweepableOutputs: batchOutputs,
		})
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

		bip322Input, err := note.BIP322Input()
		if err != nil {
			return nil, err
		}

		vtxo := domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: bip322Input.OutPoint.Hash.String(),
				VOut: bip322Input.OutPoint.Index,
			},
			Amount:    uint64(note.Value),
			PubKey:    hex.EncodeToString(bip322Input.WitnessUtxo.PkScript[2:]),
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

func (s *adminService) GetMarketHourConfig(ctx context.Context) (*domain.MarketHour, error) {
	return s.repoManager.MarketHourRepo().Get(ctx)
}

func (s *adminService) UpdateMarketHourConfig(
	ctx context.Context,
	marketHourStartTime, marketHourEndTime time.Time, period, roundInterval time.Duration,
) error {
	if marketHourStartTime.IsZero() && marketHourEndTime.IsZero() &&
		period <= 0 && roundInterval <= 0 {
		return fmt.Errorf("missing market hour config")
	}
	startTimeSet := !marketHourStartTime.IsZero()
	endTimeSet := !marketHourEndTime.IsZero()
	if startTimeSet != endTimeSet {
		return fmt.Errorf("market hour start time and end time must be set together")
	}

	marketHour, err := s.repoManager.MarketHourRepo().Get(ctx)
	if err != nil {
		return err
	}

	if marketHour == nil {
		if marketHourStartTime.IsZero() {
			return fmt.Errorf("missing market hour start time")
		}
		if marketHourEndTime.IsZero() {
			return fmt.Errorf("missing market hour end time")
		}
		if period <= 0 {
			return fmt.Errorf("missing market hour period")
		}
		if roundInterval <= 0 {
			return fmt.Errorf("missing market hour round interval")
		}
	}

	now := time.Now()
	if marketHourStartTime.IsZero() {
		marketHourStartTime = marketHour.StartTime
	} else if !marketHourStartTime.After(now) {
		return fmt.Errorf("market hour start time must be in the future")
	}

	if marketHourEndTime.IsZero() {
		marketHourEndTime = marketHour.EndTime
	} else if !marketHourEndTime.After(marketHourStartTime) {
		return fmt.Errorf("market hour end time must be after start time")
	}
	if period <= 0 {
		period = marketHour.Period
	}
	if roundInterval <= 0 {
		roundInterval = marketHour.RoundInterval
	}

	mh := domain.NewMarketHour(marketHourStartTime, marketHourEndTime, period, roundInterval)
	if err := s.repoManager.MarketHourRepo().Upsert(ctx, *mh); err != nil {
		return fmt.Errorf("failed to upsert market hours: %w", err)
	}

	return nil
}

func (s *adminService) ListIntents(
	ctx context.Context, intentIds ...string,
) ([]IntentInfo, error) {
	intents, err := s.liveStore.Intents().ViewAll(intentIds)
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
		return s.liveStore.Intents().DeleteAll()
	}
	return s.liveStore.Intents().Delete(intentIds)
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
	ports.SweepableOutput
	ScheduledAt int64
}

type ScheduledSweep struct {
	RoundId          string
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
