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
