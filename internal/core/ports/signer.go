package ports

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
)

type SignerService interface {
	IsReady(ctx context.Context) (bool, error)
	GetPubkey(ctx context.Context) (*btcec.PublicKey, error)
	SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error)
	SignTransactionTapscript(
		ctx context.Context, partialTx string, inputIndexes []int, // inputIndexes == nil means sign all inputs
	) (string, error)
}
