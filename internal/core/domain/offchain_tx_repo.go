package domain

import (
	"context"
	"fmt"
)

type OffchainTxRepository interface {
	AddOrUpdateOffchainTx(ctx context.Context, offchainTx *OffchainTx) error
	GetOffchainTxs(ctx context.Context, filter OffchainTxFilter) ([]*OffchainTx, error)
	Close()
}

// OffchainTxFilter narrows the rows returned by
// OffchainTxRepository.GetOffchainTxs. A zero-value filter selects all
// non-failed offchain txs.
//
// WithPacket maps a packet type (the int byte value carried in the ARK
// OP_RETURN extension) to an optional hex-encoded payload. When the payload
// is empty, the row matches if it carries a packet of that type. When the
// payload is non-empty, the row must additionally carry a packet of that
// type whose serialized bytes contain the given hex-decoded payload.
type OffchainTxFilter struct {
	WithTxids      []string
	WithExtension  bool
	WithPacket     map[int]string
	WithAfterDate  int64
	WithBeforeDate int64
}

// Validate enforces the structural invariants of the filter. The empty
// filter is allowed. WithAfterDate / WithBeforeDate may be set together
// (forming a "within" range) or individually, but their values must be
// non-negative and consistent.
func (f OffchainTxFilter) Validate() error {
	if f.WithAfterDate < 0 {
		return fmt.Errorf("with_after_date must be non-negative")
	}
	if f.WithBeforeDate < 0 {
		return fmt.Errorf("with_before_date must be non-negative")
	}
	if f.WithAfterDate > 0 && f.WithBeforeDate > 0 && f.WithBeforeDate <= f.WithAfterDate {
		return fmt.Errorf("with_before_date must be greater than with_after_date")
	}
	return nil
}
