package ports

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
)

type DeprecatedSignerPubkey struct {
	PubKey *btcec.PublicKey
	// unix timestamp after which the key is no longer accepted, 0 if unset
	CutoffDate int64
}

type SignerService interface {
	IsReady(ctx context.Context) (bool, error)
	GetPubkey(ctx context.Context) (*btcec.PublicKey, error)
	GetDeprecatedPubkeys(ctx context.Context) ([]DeprecatedSignerPubkey, error)
	SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error)
	SignTransactionTapscript(
		ctx context.Context, partialTx string, inputIndexes []int, // inputIndexes == nil means sign all inputs
	) (string, error)
}
