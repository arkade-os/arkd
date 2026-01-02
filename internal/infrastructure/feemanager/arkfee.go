package feemanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
	"github.com/btcsuite/btcd/wire"
)

type arkFeeManager struct {
	repo domain.FeeRepository
}

func NewArkFeeManager(repo domain.FeeRepository) (ports.FeeManager, error) {
	return &arkFeeManager{repo}, nil
}

// calculates fees using intent fee programs applied to a particular set of inputs and outputs (an intent)
func (a *arkFeeManager) ComputeIntentFees(
	ctx context.Context,
	boardingInputs []wire.TxOut, vtxoInputs []domain.Vtxo,
	onchainOutputs []wire.TxOut, offchainOutputs []wire.TxOut,
) (int64, error) {
	currIntentFees, err := a.repo.GetIntentFees(ctx)
	if err != nil {
		return -1, err
	}

	config := arkfee.Config{
		IntentOffchainInputProgram:  currIntentFees.OffchainInputFee,
		IntentOnchainInputProgram:   currIntentFees.OnchainInputFee,
		IntentOffchainOutputProgram: currIntentFees.OffchainOutputFee,
		IntentOnchainOutputProgram:  currIntentFees.OnchainOutputFee,
	}
	estimator, err := arkfee.New(config)
	if err != nil {
		return -1, err
	}
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

	fee, err := estimator.Eval(
		offchainInputs,
		onchainInputs,
		arkfeeOffchainOutputs,
		arkfeeOnchainOutputs,
	)
	if err != nil {
		return -1, err
	}

	return fee.ToSatoshis(), nil
}

func (a *arkFeeManager) Validate(fees domain.IntentFees) error {
	if fees.OnchainInputFee != "" {
		if _, err := arkfee.Parse(fees.OnchainInputFee, celenv.IntentOnchainInputEnv); err != nil {
			return fmt.Errorf("invalid onchain input fee program: %w", err)
		}
	}
	if fees.OffchainInputFee != "" {
		if _, err := arkfee.Parse(
			fees.OffchainInputFee, celenv.IntentOffchainInputEnv,
		); err != nil {
			return fmt.Errorf("invalid offchain input fee program: %w", err)
		}
	}
	if fees.OnchainOutputFee != "" {
		if _, err := arkfee.Parse(fees.OnchainOutputFee, celenv.IntentOutputEnv); err != nil {
			return fmt.Errorf("invalid onchain output fee program: %w", err)
		}
	}
	if fees.OffchainOutputFee != "" {
		if _, err := arkfee.Parse(fees.OffchainOutputFee, celenv.IntentOutputEnv); err != nil {
			return fmt.Errorf("invalid offchain output fee program: %w", err)
		}
	}
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
