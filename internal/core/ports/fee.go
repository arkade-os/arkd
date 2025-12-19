package ports

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/wire"
)

type FeeManager interface {
	GetIntentFees(
		ctx context.Context,
		boardingInputs []wire.TxOut, vtxoInputs []domain.Vtxo,
		onchainOutputs, offchainOutputs []wire.TxOut,
	) (int64, error)
}
