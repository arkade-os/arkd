package ports

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/wire"
)

type FeeManager interface {
	GetFeesFromIntent(
		ctx context.Context,
		boardingInputs []wire.TxOut, vtxoInputs []domain.Vtxo,
		onchainOutputs, offchainOutputs []wire.TxOut,
	) (int64, error)
	GetIntentFees(ctx context.Context) (*domain.IntentFees, error)
	UpsertIntentFees(ctx context.Context, fees domain.IntentFees) error
	ClearIntentFees(ctx context.Context) error
}
