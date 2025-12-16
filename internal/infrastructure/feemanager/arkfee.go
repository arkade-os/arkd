package feemanager

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/btcsuite/btcd/wire"
)

type arkFeeManager struct {
	arkfee.Estimator
}

func NewArkFeeManager(config arkfee.Config) (ports.FeeManager, error) {
	estimator, err := arkfee.New(config)
	if err != nil {
		return nil, err
	}

	return &arkFeeManager{Estimator: *estimator}, nil
}

func (a arkFeeManager) GetFeesFromIntent(
	ctx context.Context,
	boardingInputs []wire.TxOut, vtxoInputs []domain.Vtxo,
	onchainOutputs []wire.TxOut, offchainOutputs []wire.TxOut,
) (int64, error) {
	offchainInputs := make([]arkfee.OffchainInput, 0, len(vtxoInputs))
	for _, input := range vtxoInputs {
		offchainInputs = append(offchainInputs, toArkFeeOffchainInput(input))
	}

	onchainInputs := make([]arkfee.OnchainInput, 0, len(boardingInputs))
	for _, input := range boardingInputs {
		onchainInputs = append(onchainInputs, toArkFeeOnchainInput(input))
	}

	arkfeeOffchainOutputs := make([]arkfee.Output, 0, len(offchainOutputs))
	for _, output := range offchainOutputs {
		arkfeeOffchainOutputs = append(arkfeeOffchainOutputs, toArkFeeOffchainOutput(output))
	}

	arkfeeOnchainOutputs := make([]arkfee.Output, 0, len(onchainOutputs))
	for _, output := range onchainOutputs {
		arkfeeOnchainOutputs = append(arkfeeOnchainOutputs, toArkFeeOnchainOutput(output))
	}

	fee, err := a.Eval(offchainInputs, onchainInputs, arkfeeOffchainOutputs, arkfeeOnchainOutputs)
	if err != nil {
		return 0, err
	}

	return fee.ToSatoshis(), nil
}

func (a arkFeeManager) GetIntentFees(ctx context.Context) (*domain.IntentFees, error) {
	return &domain.IntentFees{
		OffchainInputFee:  a.Config.IntentOffchainInputProgram,
		OnchainInputFee:   a.Config.IntentOnchainInputProgram,
		OffchainOutputFee: a.Config.IntentOffchainOutputProgram,
		OnchainOutputFee:  a.Config.IntentOnchainOutputProgram,
	}, nil
}

func (a *arkFeeManager) UpsertIntentFees(ctx context.Context, fees domain.IntentFees) error {
	// Only update if non-empty to allow partial updates
	if fees.OffchainInputFee != "" {
		a.Config.IntentOffchainInputProgram = fees.OffchainInputFee
	}
	if fees.OnchainInputFee != "" {
		a.Config.IntentOnchainInputProgram = fees.OnchainInputFee
	}
	if fees.OffchainOutputFee != "" {
		a.Config.IntentOffchainOutputProgram = fees.OffchainOutputFee
	}
	if fees.OnchainOutputFee != "" {
		a.Config.IntentOnchainOutputProgram = fees.OnchainOutputFee
	}

	estimator, err := arkfee.New(a.Config)
	if err != nil {
		return err
	}
	a.Estimator = *estimator

	return nil
}

func (a *arkFeeManager) ClearIntentFees(ctx context.Context) error {
	a.Config.IntentOffchainInputProgram = "0.0"
	a.Config.IntentOnchainInputProgram = "0.0"
	a.Config.IntentOffchainOutputProgram = "0.0"
	a.Config.IntentOnchainOutputProgram = "0.0"

	estimator, err := arkfee.New(a.Config)
	if err != nil {
		return err
	}
	a.Estimator = *estimator

	return nil
}

func toArkFeeOffchainOutput(output wire.TxOut) arkfee.Output {
	return arkfee.Output{
		Amount: uint64(output.Value),
		Script: hex.EncodeToString(output.PkScript),
	}
}

func toArkFeeOnchainOutput(output wire.TxOut) arkfee.Output {
	return arkfee.Output{
		Amount: uint64(output.Value),
		Script: hex.EncodeToString(output.PkScript),
	}
}

func toArkFeeOnchainInput(input wire.TxOut) arkfee.OnchainInput {
	return arkfee.OnchainInput{
		Amount: uint64(input.Value),
	}
}

func toArkFeeOffchainInput(input domain.Vtxo) arkfee.OffchainInput {
	t := arkfee.VtxoTypeVtxo
	if input.Swept {
		t = arkfee.VtxoTypeRecoverable
	} else if input.IsNote() {
		t = arkfee.VtxoTypeNote
	}

	return arkfee.OffchainInput{
		Amount: input.Amount,
		Expiry: time.Unix(input.ExpiresAt, 0),
		Birth:  time.Unix(input.CreatedAt, 0),
		Type:   t,
	}
}
