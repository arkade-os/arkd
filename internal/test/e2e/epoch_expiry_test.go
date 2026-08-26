package e2e_test

import (
	"flag"
	"strconv"
	"strings"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	"github.com/stretchr/testify/require"
)

// NOTE: these tests have never been executed, so every assertion below is
// authored against the harness rather than verified by it. Treat the first run
// as part of review, not as a regression check.
//
// To run them on a Windows dev box: nigiri lives in WSL, but Docker Desktop's
// WSL integration has to be enabled (Settings -> Resources -> WSL Integration)
// or nigiri cannot reach the daemon. CI has its own nigiri stack and is
// unaffected.
//
// Epoch expiry is deliberately timestamp-based - a calendar epoch wants a
// calendar unit - and settings validation refuses to enable it on a block-height
// deployment. So these tests cannot mine their way to a boundary the way a CSV
// test can; they wait real seconds. The epoch parameters are therefore set as
// small as the validation constraints allow (0 < cutoff < rollover < length).

var runEpoch = flag.Bool("epoch", false, "run the epoch expiry e2e tests")

const (
	// Tiny so the tests finish. Production defaults are 28 days, 7 days and
	// 12 hours respectively.
	epochTestLength   = 600 // 10 minutes
	epochTestRollover = 300 // 5 minutes
	epochTestCutoff   = 60  // 1 minute
	epochTestGrace    = 512 // BIP68 seconds granularity
)

func skipUnlessEpoch(t *testing.T) {
	t.Helper()
	if !flag.Parsed() {
		flag.Parse()
	}
	if !*runEpoch {
		t.Skip("skip epoch expiry e2e test (pass -epoch to run)")
	}
}

// enableEpochExpiry switches the running arkd over to epoch expiry and restores
// the previous mode on cleanup. Returns the anchor it configured.
func enableEpochExpiry(t *testing.T) int64 {
	t.Helper()

	// Anchor on an exact multiple of the epoch length so boundaries are
	// predictable from the test's own clock.
	now := time.Now().Unix()
	anchor := now - (now % epochTestLength)

	_, err := runDockerExec(
		"arkd", "arkd", "settings", "update",
		"--epoch-expiry-enabled",
		"--epoch-anchor", strconv.FormatInt(anchor, 10),
		"--epoch-length", strconv.Itoa(epochTestLength),
		"--rollover-window", strconv.Itoa(epochTestRollover),
		"--settlement-cutoff", strconv.Itoa(epochTestCutoff),
		"--unroll-grace", strconv.Itoa(epochTestGrace),
	)
	require.NoError(t, err, "failed to enable epoch expiry")

	t.Cleanup(func() {
		if _, err := runDockerExec(
			"arkd", "arkd", "settings", "update", "--epoch-expiry-enabled=false",
		); err != nil {
			t.Logf("failed to restore non-epoch settings: %v", err)
		}
	})

	return anchor
}

// expectedBoundary mirrors domain.EpochSchedule.BoundaryAfter: the first boundary
// at least the rollover window away from at.
func expectedBoundary(anchor, at int64) int64 {
	target := at + epochTestRollover
	if target <= anchor {
		return anchor
	}
	elapsed := target - anchor
	n := elapsed / epochTestLength
	if elapsed%epochTestLength != 0 {
		n++
	}
	return anchor + n*epochTestLength
}

// TestEpochVtxosShareAnExpiryDate is the core claim of the whole design: vtxos
// minted in the same window carry the same expiry, which is what makes them
// expiry-fungible and what stops consolidation stranding time value.
func TestEpochVtxosShareAnExpiryDate(t *testing.T) {
	skipUnlessEpoch(t)
	anchor := enableEpochExpiry(t)

	alice := setupClientWallet(t)
	bob := setupClientWallet(t)

	aliceVtxo := faucetOffchain(t, alice, 0.0001)
	bobVtxo := faucetOffchain(t, bob, 0.0001)

	require.False(t, aliceVtxo.ExpiresAt.IsZero())
	require.Equal(t, aliceVtxo.ExpiresAt.Unix(), bobVtxo.ExpiresAt.Unix(),
		"vtxos minted in the same window must share an expiry date")

	require.Equal(t,
		expectedBoundary(anchor, time.Now().Unix()), aliceVtxo.ExpiresAt.Unix(),
		"the shared date must be the first boundary at least a rollover window away",
	)
}

// TestEpochRenewalOutsideRolloverWindowIsRefused pins the admission window's
// upper bound. A fresh vtxo expires a full epoch away, so renewing it now would
// hand back the same date while still making the operator fund a second batch
// output against a still-locked one.
func TestEpochRenewalOutsideRolloverWindowIsRefused(t *testing.T) {
	skipUnlessEpoch(t)
	enableEpochExpiry(t)

	alice := setupClientWallet(t)
	vtxo := faucetOffchain(t, alice, 0.0001)

	remaining := time.Until(vtxo.ExpiresAt)
	require.Greater(t, remaining, time.Duration(epochTestRollover)*time.Second,
		"precondition: the fresh vtxo must sit outside the rollover window")

	_, err := alice.Settle(t.Context())
	require.Error(t, err, "a renewal outside the rollover window must be refused")
	require.Contains(t, strings.ToLower(err.Error()), "too early")
}

// TestEpochExitIsAllowedOutsideRolloverWindow is the other half of the window:
// the upper bound applies only to renewals, so a collaborative exit stays
// available for the whole epoch.
func TestEpochExitIsAllowedOutsideRolloverWindow(t *testing.T) {
	skipUnlessEpoch(t)
	enableEpochExpiry(t)

	alice := setupClientWallet(t)
	vtxo := faucetOffchain(t, alice, 0.0001)
	require.Greater(t, time.Until(vtxo.ExpiresAt),
		time.Duration(epochTestRollover)*time.Second)

	onchainAddr, _, _, err := alice.Receive(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, onchainAddr)

	// A settle whose outputs are all onchain is an exit, not a renewal.
	_, err = alice.CollaborativeExit(t.Context(), onchainAddr, vtxo.Amount)
	require.NoError(t, err, "a collaborative exit must stay available all epoch")
}

// TestLegacyAndEpochBatchesCoexist covers the cutover drain: a batch created
// before the flag was flipped keeps its own relative schedule while new ones use
// the shared date, and the sweeper has to handle both at once.
func TestLegacyAndEpochBatchesCoexist(t *testing.T) {
	skipUnlessEpoch(t)

	// minted while epoch expiry is still off
	legacyClient := setupClientWallet(t)
	legacyVtxo := faucetOffchain(t, legacyClient, 0.0001)

	anchor := enableEpochExpiry(t)

	epochClient := setupClientWallet(t)
	epochVtxo := faucetOffchain(t, epochClient, 0.0001)

	require.Equal(t,
		expectedBoundary(anchor, time.Now().Unix()), epochVtxo.ExpiresAt.Unix(),
		"a post-cutover vtxo must carry the shared epoch date",
	)
	require.NotEqual(t, legacyVtxo.ExpiresAt.Unix(), epochVtxo.ExpiresAt.Unix(),
		"a pre-cutover vtxo must keep its own relative expiry",
	)
}

// TestEpochBatchSweepsAtTheBoundary walks a batch to its sweep.
//
// The extra blocks after the boundary are for median-time-past: an nLockTime
// timestamp is compared against MTP, which trails wall clock, so the sweep cannot
// confirm at the boundary instant even though it is scheduled there. This is the
// behaviour the ErrNonFinalCLTV retry exists to survive.
func TestEpochBatchSweepsAtTheBoundary(t *testing.T) {
	skipUnlessEpoch(t)
	enableEpochExpiry(t)

	alice := setupClientWallet(t)
	vtxo := faucetOffchain(t, alice, 0.0001)

	sleepUntilBoundary(t, vtxo.ExpiresAt)

	// Regtest MTP is the median of the last 11 block times, so several blocks are
	// needed before it catches up with wall clock.
	for range 12 {
		require.NoError(t, generateBlocks(1))
		time.Sleep(time.Second)
	}

	require.Eventually(t, func() bool {
		return vtxoIsSwept(t, alice, vtxo)
	}, 5*time.Minute, 10*time.Second,
		"batch was never swept after its epoch boundary")
}

func vtxoIsSwept(t *testing.T, client wallet.Wallet, target clientlib.Vtxo) bool {
	t.Helper()

	spendable, spent, err := client.ListVtxos(t.Context())
	if err != nil {
		t.Logf("failed to list vtxos: %v", err)
		return false
	}
	for _, v := range append(append([]clientlib.Vtxo{}, spendable...), spent...) {
		if v.Txid == target.Txid && v.VOut == target.VOut {
			return v.IsRecoverable()
		}
	}
	return false
}

func sleepUntilBoundary(t *testing.T, deadline time.Time) {
	t.Helper()
	if d := time.Until(deadline); d > 0 {
		t.Logf("waiting %s for the epoch boundary", d.Round(time.Second))
		time.Sleep(d)
	}
}
