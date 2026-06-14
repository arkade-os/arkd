package sqlitedb

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
)

// GetVtxoPubKeysByCommitmentTxidsBatched exposes the unexported batching
// helper to tests in sibling packages. The _test.go suffix keeps this out
// of the production binary.
func GetVtxoPubKeysByCommitmentTxidsBatched(
	ctx context.Context,
	repo domain.VtxoRepository,
	commitmentTxids []string,
	withMinimumAmount uint64,
	batchSize int,
) ([]string, error) {
	return repo.(*vtxoRepository).getVtxoPubKeysByCommitmentTxidsBatched(
		ctx, commitmentTxids, withMinimumAmount, batchSize,
	)
}
