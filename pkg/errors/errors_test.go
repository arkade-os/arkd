package errors

import (
	"regexp"
	"testing"

	grpccodes "google.golang.org/grpc/codes"
)

// legacyNotFoundRe is the message pattern SDKs used to detect a stale
// subscription before structured error codes existed (see ts-sdk#600). The
// SUBSCRIPTION_NOT_FOUND message must keep matching it so those SDKs keep
// working.
var legacyNotFoundRe = regexp.MustCompile(`(?i)subscription\s+\S+\s+not\s+found`)

func TestSubscriptionNotFoundContract(t *testing.T) {
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
// the structured code existed. The TX_FILTERS_LIMIT_EXCEEDED message must
// keep matching it so those clients keep working.
var legacyFiltersLimitRe = regexp.MustCompile(`tx filters per subscription limit \(\d+\) exceeded`)

func TestTxFiltersLimitExceededContract(t *testing.T) {
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

func TestInvalidTxFilterContract(t *testing.T) {
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
