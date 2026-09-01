package domain

import (
	"context"
	"fmt"
)

type OffchainTxRepository interface {
	AddOrUpdateOffchainTx(ctx context.Context, offchainTx *OffchainTx) error
	GetOffchainTxs(ctx context.Context, filter OffchainTxFilter) ([]*OffchainTx, error)
	GetOffchainTxsByTxids(ctx context.Context, txids []string) ([]*OffchainTx, error)
	// GetAnyOffchainTx returns the offchain tx whatever its stage, including the ones that
	// failed before being accepted. Unlike GetOffchainTx it must not be used to detect
	// duplicates, as a tx failed at request stage is meant to be retriable.
	GetAnyOffchainTx(ctx context.Context, txid string) (*OffchainTx, error)
	// GetOffchainTxsInRange returns the offchain txs started within the given time range
	// (0 means unbounded). When limit is > 0 only the most recent ones are returned, but
	// the order of the returned slice is unspecified.
	GetOffchainTxsInRange(
		ctx context.Context, after, before int64, onlyFailed, onlyCompleted bool, limit int64,
	) ([]*OffchainTx, error)
	Close()
}

// OffchainTxsScanLimit caps the worst-case rows returned by a single
// GetOffchainTxs call. It is a safety bound to keep a query from loading the
// whole table into memory while pagination is still applied in Go. SQL
// pushdown of pagination is a separate follow-up.
//
// It applies to the txid-filtered path too. A caller-supplied txid list looks
// like it bounds the result but does not: in withheld and private exposure an
// empty request is backfilled from the auth token's whitelist, which is built
// by an unbounded vtxo chain walk, so the list grows with chain depth.
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
//
// WithPacketContains maps a packet type to hex-encoded substrings that
// must all appear within the serialized packet bytes. This matches the
// streaming `tx.extension[N].contains('hex')` semantics: the substring
// is compared byte-aligned against the decoded packet, not against the
// base64 PSBT, so there is no base64-alignment ambiguity.
type OffchainTxFilter struct {
	WithTxids          []string
	WithExtension      bool
	WithPacket         map[int]string
	WithPacketContains map[int][]string
	WithAfterDate      int64
	WithBeforeDate     int64
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
