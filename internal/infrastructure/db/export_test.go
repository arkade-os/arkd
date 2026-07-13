package db

import (
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
)

// Test-only seams. This file is compiled only into the test binary, so it adds
// nothing to the shipped package. It lets external db_test cases drive the
// projection handlers synchronously and swap in a fault-injecting store to
// exercise the failure paths that real backends cannot be made to hit.

// ApplyOffchainTxEventsForTest runs the offchain-tx projection synchronously
// (the store writes happen before the async dispatch), so callers can assert on
// the resulting DB state immediately.
func ApplyOffchainTxEventsForTest(rm ports.RepoManager, events []domain.Event) {
	rm.(*service).updateProjectionsAfterOffchainTxEvents(events)
}

// SetMarkerStoreForTest replaces the marker store, e.g. with a wrapper that
// forces a specific write to fail mid-projection.
func SetMarkerStoreForTest(rm ports.RepoManager, m domain.MarkerRepository) {
	rm.(*service).markerStore = m
}
