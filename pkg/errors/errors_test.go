package errors

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	grpccodes "google.golang.org/grpc/codes"
)

// legacyNotFoundRe is the message pattern SDKs used to detect a stale
// subscription before structured error codes existed (see ts-sdk#600). The
// SUBSCRIPTION_NOT_FOUND message must keep matching it so those SDKs keep
// working.
var legacyNotFoundRe = regexp.MustCompile(`(?i)subscription\s+\S+\s+not\s+found`)

func TestSubscriptionNotFoundError(t *testing.T) {
	err := SUBSCRIPTION_NOT_FOUND.
		New("subscription %s not found", "stale-id").
		WithMetadata(SubscriptionMetadata{SubscriptionId: "stale-id"})

	if got := err.Code(); got != 50 {
		t.Fatalf("Code() = %d, want 50", got)
	}
	if got := err.CodeName(); got != "SUBSCRIPTION_NOT_FOUND" {
		t.Fatalf("CodeName() = %q, want SUBSCRIPTION_NOT_FOUND", got)
	}
	if got := err.GrpcCode(); got != grpccodes.NotFound {
		t.Fatalf("GrpcCode() = %v, want NotFound", got)
	}
	if got := err.Metadata()["subscription_id"]; got != "stale-id" {
		t.Fatalf("Metadata()[subscription_id] = %q, want stale-id", got)
	}
	if !legacyNotFoundRe.MatchString(err.Error()) {
		t.Fatalf("Error() = %q does not match legacy SDK pattern %q", err.Error(), legacyNotFoundRe)
	}
}

// legacyFiltersLimitRe is the message pattern clients could match on before
// the structured code existed.
var legacyFiltersLimitRe = regexp.MustCompile(`tx filters per subscription limit \(\d+\) exceeded`)

func TestTxFiltersLimitExceededError(t *testing.T) {
	err := TX_FILTERS_LIMIT_EXCEEDED.
		New("tx filters per subscription limit (%d) exceeded", 64).
		WithMetadata(TxFiltersLimitMetadata{
			SubscriptionId: "sub-id",
			MaxTxFilters:   64,
			GotTxFilters:   65,
		})

	if got := err.Code(); got != 51 {
		t.Fatalf("Code() = %d, want 51", got)
	}
	if got := err.CodeName(); got != "TX_FILTERS_LIMIT_EXCEEDED" {
		t.Fatalf("CodeName() = %q, want TX_FILTERS_LIMIT_EXCEEDED", got)
	}
	if got := err.GrpcCode(); got != grpccodes.InvalidArgument {
		t.Fatalf("GrpcCode() = %v, want InvalidArgument", got)
	}
	if got := err.Metadata()["subscription_id"]; got != "sub-id" {
		t.Fatalf("Metadata()[subscription_id] = %q, want sub-id", got)
	}
	if got := err.Metadata()["max_tx_filters"]; got != "64" {
		t.Fatalf("Metadata()[max_tx_filters] = %q, want 64", got)
	}
	if got := err.Metadata()["got_tx_filters"]; got != "65" {
		t.Fatalf("Metadata()[got_tx_filters] = %q, want 65", got)
	}
	if !legacyFiltersLimitRe.MatchString(err.Error()) {
		t.Fatalf(
			"Error() = %q does not match legacy pattern %q", err.Error(), legacyFiltersLimitRe,
		)
	}
}

func TestInvalidTxFilterError(t *testing.T) {
	err := INVALID_TX_FILTER.
		New("invalid tx filter %q: %s", "&&&", "compile failed").
		WithMetadata(TxFilterMetadata{Expression: "&&&"})

	if got := err.Code(); got != 52 {
		t.Fatalf("Code() = %d, want 52", got)
	}
	if got := err.CodeName(); got != "INVALID_TX_FILTER" {
		t.Fatalf("CodeName() = %q, want INVALID_TX_FILTER", got)
	}
	if got := err.GrpcCode(); got != grpccodes.InvalidArgument {
		t.Fatalf("GrpcCode() = %v, want InvalidArgument", got)
	}
	if got := err.Metadata()["expression"]; got != "&&&" {
		t.Fatalf("Metadata()[expression] = %q, want &&&", got)
	}
}

func TestQueryFilterLimitExceededError(t *testing.T) {
	err := QUERY_FILTER_LIMIT_EXCEEDED.
		New("too many %s in filter: %d, max %d", "outpoints", 101, 100).
		WithMetadata(QueryFilterLimitMetadata{
			Filter:   "outpoints",
			MaxItems: 100,
			GotItems: 101,
		})

	if got := err.Code(); got != 58 {
		t.Fatalf("Code() = %d, want 58", got)
	}
	if got := err.CodeName(); got != "QUERY_FILTER_LIMIT_EXCEEDED" {
		t.Fatalf("CodeName() = %q, want QUERY_FILTER_LIMIT_EXCEEDED", got)
	}
	if got := err.GrpcCode(); got != grpccodes.InvalidArgument {
		t.Fatalf("GrpcCode() = %v, want InvalidArgument", got)
	}
	if got := err.Metadata()["filter"]; got != "outpoints" {
		t.Fatalf("Metadata()[filter] = %q, want outpoints", got)
	}
	if got := err.Metadata()["max_items"]; got != "100" {
		t.Fatalf("Metadata()[max_items] = %q, want 100", got)
	}
	if got := err.Metadata()["got_items"]; got != "101" {
		t.Fatalf("Metadata()[got_items] = %q, want 101", got)
	}
}

func TestErrorMetadata(t *testing.T) {
	err := VTXO_ALREADY_SPENT.
		New("vtxo(s) already spent").
		WithMetadata(VtxoMetadata{VtxoOutpoints: []string{"aa:0", "bb:1"}})

	if got := err.Metadata()["vtxo_outpoint"]; got != "aa:0" {
		t.Fatalf("Metadata()[vtxo_outpoint] = %q, want aa:0", got)
	}
	if got := err.Metadata()["vtxo_outpoints"]; got != "[aa:0 bb:1]" {
		t.Fatalf("Metadata()[vtxo_outpoints] = %q, want [aa:0 bb:1]", got)
	}
}

// The internal cause of an error is meant for the server only: it must never show up in what is
// returned to clients, Error() and Metadata(), while InternalCause() and Log() expose it.
func TestInternalCause(t *testing.T) {
	t.Run("without internal cause", func(t *testing.T) {
		err := INTERNAL_ERROR.New("something went wrong")

		require.Equal(t, err, err.InternalCause())
		require.NotContains(t, err.Log().Data, "cause")
	})

	t.Run("with internal cause", func(t *testing.T) {
		internal := fmt.Errorf("reason")
		err := INTERNAL_ERROR.New("something went wrong").
			WithMetadata(map[string]any{"arg": "val"}).
			WithInternalCause(internal)

		require.Equal(t, "INTERNAL_ERROR (0): something went wrong", err.Error())
		require.NotContains(t, err.Error(), "reason")
		for _, v := range err.Metadata() {
			require.NotContains(t, v, "reason")
		}
		require.Equal(t, "val", err.Metadata()["arg"])
		require.Equal(t, internal, err.InternalCause())
		require.Equal(t, internal.Error(), err.Log().Data["cause"])
	})
}
