package ports

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/cel-go/cel"
)

type FeeManager interface {
	ComputeIntentFees(
		ctx context.Context,
		boardingInputs []wire.TxOut, vtxoInputs []domain.Vtxo,
		onchainOutputs, offchainOutputs []wire.TxOut,
	) (int64, error)
	Validate(feeProgram string, celEnv *cel.Env) error
}
