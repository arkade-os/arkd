package domain

import (
	"context"
	"fmt"
)

type OffchainTxRepository interface {
	AddOrUpdateOffchainTx(ctx context.Context, offchainTx *OffchainTx) error
	GetOffchainTxs(ctx context.Context, filter OffchainTxFilter) ([]*OffchainTx, error)
	GetOffchainTxsByTxids(ctx context.Context, txids []string) ([]*OffchainTx, error)
	Close()
}

// OffchainTxsScanLimit caps the worst-case rows returned by a single
// GetOffchainTxs call when the filter does not pin the result set with
// txids. It is a safety bound to keep an unconstrained query from
// loading the whole table into memory while pagination is still
// applied in Go. SQL pushdown of pagination is a separate follow-up.
const OffchainTxsScanLimit = 10000

// OffchainTxFilter narrows the rows returned by
// OffchainTxRepository.GetOffchainTxs. A zero-value filter selects all
// non-failed offchain txs.
//
// WithPacket maps a packet type (the int byte value carried in the ARK
// OP_RETURN extension) to an optional hex-encoded payload. When the
// payload is empty, the row matches if it carries a packet of that
// type. When the payload is non-empty, the row must additionally carry
// a packet of that type whose serialized bytes, hex-encoded, equal the
// payload exactly. This matches the SubscriptionFilter streaming
// semantics for `tx.extension[N] == 'hex'`.
type OffchainTxFilter struct {
	WithTxids      []string
	WithExtension  bool
	WithPacket     map[int]string
	WithAfterDate  int64
	WithBeforeDate int64
}

// Validate enforces the structural invariants of the filter. The empty
// filter is allowed. WithAfterDate / WithBeforeDate may be set together
// (forming a "within" range) or individually. Bounds are inclusive on
// both sides, so before == after is permitted and selects rows whose
// starting_timestamp equals that value.
func (f OffchainTxFilter) Validate() error {
	if f.WithAfterDate < 0 {
		return fmt.Errorf("with_after_date must be non-negative")
	}
	if f.WithBeforeDate < 0 {
		return fmt.Errorf("with_before_date must be non-negative")
	}
	if f.WithAfterDate > 0 && f.WithBeforeDate > 0 && f.WithBeforeDate < f.WithAfterDate {
		return fmt.Errorf("with_before_date must be greater than or equal to with_after_date")
	}
	return nil
}
