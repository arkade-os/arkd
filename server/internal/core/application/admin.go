package application

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
)

type Balance struct {
	Locked    uint64
	Available uint64
}

type ArkProviderBalance struct {
	MainAccountBalance       Balance
	ConnectorsAccountBalance Balance
}

type SweepableOutput struct {
	TxId        string
	Vout        uint32
	Amount      uint64
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
	InputsVtxos      []string
	OutputsVtxos     []string
	ExitAddresses    []string
}

type AdminService interface {
	Wallet() ports.WalletService
	GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error)
	GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error)
	GetRounds(ctx context.Context, after int64, before int64) ([]string, error)
	GetWalletAddress(ctx context.Context) (string, error)
	GetWalletStatus(ctx context.Context) (*WalletStatus, error)
	CreateNotes(ctx context.Context, amount uint32, quantity int) ([]string, error)
}

type adminService struct {
	walletSvc       ports.WalletService
	repoManager     ports.RepoManager
	txBuilder       ports.TxBuilder
	sweeperTimeUnit ports.TimeUnit
}

func NewAdminService(walletSvc ports.WalletService, repoManager ports.RepoManager, txBuilder ports.TxBuilder, timeUnit ports.TimeUnit) AdminService {
	return &adminService{
		walletSvc:       walletSvc,
		repoManager:     repoManager,
		txBuilder:       txBuilder,
		sweeperTimeUnit: timeUnit,
	}
}

func (a *adminService) Wallet() ports.WalletService {
	return a.walletSvc
}

func (a *adminService) GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error) {
	round, err := a.repoManager.Rounds().GetRoundWithId(ctx, roundId)
	if err != nil {
		return nil, err
	}

	roundDetails := &RoundDetails{
		RoundId:          round.Id,
		TxId:             round.Txid,
		ForfeitedAmount:  0,
		TotalVtxosAmount: 0,
		TotalExitAmount:  0,
		ExitAddresses:    []string{},
		FeesAmount:       0,
		InputsVtxos:      []string{},
		OutputsVtxos:     []string{},
	}

	for _, request := range round.TxRequests {
		// TODO: Add fees amount
		roundDetails.ForfeitedAmount += request.TotalInputAmount()

		for _, receiver := range request.Receivers {
			if receiver.IsOnchain() {
				roundDetails.TotalExitAmount += receiver.Amount
				roundDetails.ExitAddresses = append(roundDetails.ExitAddresses, receiver.OnchainAddress)
				continue
			}

			roundDetails.TotalVtxosAmount += receiver.Amount
		}

		for _, input := range request.Inputs {
			roundDetails.InputsVtxos = append(roundDetails.InputsVtxos, input.Txid)
		}
	}

	vtxos, err := a.repoManager.Vtxos().GetVtxosForRound(ctx, round.Txid)
	if err != nil {
		return nil, err
	}

	for _, vtxo := range vtxos {
		roundDetails.OutputsVtxos = append(roundDetails.OutputsVtxos, vtxo.Txid)
	}

	return roundDetails, nil
}

func (a *adminService) GetRounds(ctx context.Context, after int64, before int64) ([]string, error) {
	return a.repoManager.Rounds().GetRoundsIds(ctx, after, before)
}

func (a *adminService) GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error) {
	sweepableRounds, err := a.repoManager.Rounds().GetUnsweptRoundsTxid(ctx)
	if err != nil {
		return nil, err
	}

	scheduledSweeps := make([]ScheduledSweep, 0, len(sweepableRounds))

	for _, txid := range sweepableRounds {
		round, err := a.repoManager.Rounds().GetRoundWithTxid(ctx, txid)
		if err != nil {
			return nil, err
		}

		vtxoTree, err := tree.NewTxGraph(round.VtxoTree)
		if err != nil {
			return nil, err
		}

		sweepable, err := findSweepableOutputs(
			ctx, a.walletSvc, a.txBuilder, a.sweeperTimeUnit, vtxoTree,
		)
		if err != nil {
			return nil, err
		}

		sweepableOutputs := make([]SweepableOutput, 0)
		for expirationTime, inputs := range sweepable {
			for _, input := range inputs {
				sweepableOutputs = append(sweepableOutputs, SweepableOutput{
					TxId:        input.GetHash().String(),
					Vout:        input.GetIndex(),
					Amount:      input.GetAmount(),
					ScheduledAt: expirationTime,
				})
			}
		}

		scheduledSweeps = append(scheduledSweeps, ScheduledSweep{
			RoundId:          round.Id,
			SweepableOutputs: sweepableOutputs,
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
func (a *adminService) CreateNotes(ctx context.Context, value uint32, quantity int) ([]string, error) {
	notes := make([]string, 0, quantity)
	vtxos := make([]domain.Vtxo, 0, quantity)

	now := time.Now().Unix()

	for i := 0; i < quantity; i++ {
		note, err := note.New(value)
		if err != nil {
			return nil, err
		}

		bip322Input, err := note.BIP322Input()
		if err != nil {
			return nil, err
		}

		vtxo := domain.Vtxo{
			VtxoKey: domain.VtxoKey{
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
