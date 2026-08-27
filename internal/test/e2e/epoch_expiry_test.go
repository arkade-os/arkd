package e2e_test

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	"github.com/stretchr/testify/require"
)

// NOTE: no assertion below has yet been reached. The first CI runs failed in
// enableEpochExpiry - first because the admin CLI could not encode the flag at
// all, then because the deployment is block-based - so the bodies are still
// authored against the harness rather than verified by it. Treat the first run
// that gets past setup as part of review, not as a regression check.
//
// A failure here is more likely to be design-level than flaky. These are the
// only tests that exercise the maturity arithmetic against a real chain: every
// unit test around it works in seconds, and a unit-mixing bug - block heights
// compared against unix timestamps - survived all of them precisely because of
// that. Read a failure as "the scheme may be wrong" before "the test is wrong".
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
//
// They have their own deployment and their own CI job: make docker-run-epoch
// boots arkd with seconds-based delays, make epochtest runs them. On the default
// block-based stack they skip, with the reason, because epoch expiry genuinely
// cannot be enabled there - see skipUnlessSecondsBased.
//
// They were gated behind a -epoch flag at first, which make integrationtest
// never passes, so they would have been skipped everywhere while looking
// present. That is worth avoiding: the boundary sweep test below is the only
// thing that exercises the path where two scheduling bugs were found by reading
// rather than by testing.

const (
	// As small as the constraints allow, so the tests finish. Production defaults
	// are 28 days, 7 days and 12 hours respectively.
	//
	// The floor is the unroll grace: BIP68 encodes a seconds-based sequence in
	// 512-second steps, so 512 is the smallest non-zero grace, and the grace has
	// to be shorter than the rollover window or untouched batches stop maturing
	// at their epoch date - which is what the first version of these constants
	// got wrong, with a 512s grace against a 300s window.
	epochTestLength   = 2048
	epochTestRollover = 1024
	epochTestCutoff   = 512
	epochTestGrace    = 512

	// Batches minted within this long of enableEpochExpiry share a boundary. The
	// anchor is placed so the first boundary lands here, which both keeps the
	// shared-date assertions honest and bounds what the sweep test waits.
	epochTestMintWindow = 120
)

// These constants are already at their floor - do not shrink them to speed the
// job up, because they cannot go lower without breaking the scheme.
//
// The chain is forced: BIP68 encodes a seconds-based sequence in 512-second
// steps, so 512 is the smallest non-zero unroll grace. The grace must be
// strictly shorter than the rollover window, so the window cannot go below
// 1024. A batch is minted at least a rollover window before its date, so
// TestEpochBatchSweepsAtTheBoundary cannot wait less than ~1024 seconds no
// matter how the anchor is placed - BoundaryAfter guarantees it. Roughly
// seventeen minutes of waiting is therefore the hard floor for this job, and
// the rest of its runtime is stack setup and the four fast tests.
//
// The only way to make it cheaper is to run it less often - it is a separate
// CI job precisely so that choice is available without touching these values.

// enableEpochExpiry switches the running arkd over to epoch expiry and restores
// the previous mode on cleanup. Returns the anchor it configured.
//
// Requires a deployment that booted with seconds-based delays. The sweep
// scheduler is chosen once at startup from the configured locktime type, so a
// block-based arkd cannot run epoch expiry no matter what the settings say -
// an epoch date is a unix timestamp, and a block-height scheduler would read it
// as a block roughly 1.8 billion ahead. Both settings validation and the admin
// API refuse the pairing, which is why this needs its own compose environment
// (make docker-run-epoch) rather than the default block-based one.
func enableEpochExpiry(t *testing.T) int64 {
	t.Helper()

	skipUnlessSecondsBased(t)

	// Put boundary zero exactly one rollover window plus the mint margin ahead.
	// BoundaryAfter returns the anchor itself for any t whose t+rollover has not
	// passed it, so every batch minted inside the margin commits to this same
	// date - which is what the shared-expiry assertions are about - and the
	// boundary sweep test waits a predictable rollover+margin rather than
	// anywhere up to a full epoch on top.
	now := time.Now().Unix()
	anchor := now + epochTestRollover + epochTestMintWindow

	out, err := runDockerExec(
		"arkd", "arkd", "settings", "update",
		"--epoch-expiry-enabled",
		"--epoch-anchor", strconv.FormatInt(anchor, 10),
		"--epoch-length", strconv.Itoa(epochTestLength),
		"--rollover-window", strconv.Itoa(epochTestRollover),
		"--settlement-cutoff", strconv.Itoa(epochTestCutoff),
		"--unroll-grace", strconv.Itoa(epochTestGrace),
	)
	require.NoError(
		t, err,
		"failed to enable epoch expiry - is arkd running with seconds-based delays? "+
			"(make docker-run-epoch). output: %s", out,
	)

	// A round reads its settings once, when it starts, and the batch that mints a
	// test's vtxo is very likely to be one already in flight when the flag flips -
	// it would build against the pre-update settings and hand back a legacy
	// relative expiry. Waiting a session duration is the same bound
	// requirePairedBatch uses for the participant count, for the same reason.
	//
	// Without this the epoch tests fail in ways that look like epoch bugs: vtxos
	// whose dates differ by the gap between two rounds, an admission window that
	// never applies. They are just legacy batches.
	roundSettings, err := getRoundSettings()
	require.NoError(t, err, "failed to read the session duration")
	time.Sleep(roundSettings.sessionDuration)

	// Confirm the flag actually took, so a settings path that silently drops it
	// fails here rather than as a puzzling assertion three tests later.
	enabled, err := getEpochExpiryEnabledSetting()
	require.NoError(t, err, "failed to read back the epoch settings")
	require.True(t, enabled, "epoch expiry did not take effect: %s", out)

	t.Cleanup(func() {
		// Fail rather than log: this flips a setting shared by every other test in
		// the package, so a restore that quietly failed would leave the rest of the
		// suite running under epoch expiry while this test still reported success.
		out, err := runDockerExec(
			"arkd", "arkd", "settings", "update", "--epoch-expiry-enabled=false",
		)
		if err != nil {
			t.Errorf("failed to restore non-epoch settings: %v (output: %s)", err, out)
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
	// Before anything else. This is the one epoch test that does real work before
	// enabling the flag, so without an early check it would fund a wallet and mint
	// a batch on the shared arkd and only then skip - paying for a test that never
	// runs, on every integration job.
	skipUnlessSecondsBased(t)

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

// minAllowedSequence mirrors arklib.MinAllowedSequence: at or above it a
// relative locktime is seconds, below it blocks.
const minAllowedSequence = 512

// skipUnlessSecondsBased skips when arkd booted with block-based locktimes.
//
// This is not a convenience skip. The sweep scheduler is selected once at
// startup from the configured locktime type, so on a block-based deployment
// epoch expiry is genuinely unavailable - the admin API refuses to enable it,
// because an epoch date is a unix timestamp that a block-height scheduler would
// read as a block roughly 1.8 billion ahead. The default e2e stack is
// block-based on purpose, so that the rest of the suite can mine past its
// timelocks instead of waiting real seconds.
//
// These tests get their own deployment and their own job: make docker-run-epoch
// then make epochtest.
func skipUnlessSecondsBased(t *testing.T) {
	t.Helper()

	expiry, err := getVtxoTreeExpirySetting()
	require.NoError(t, err, "failed to read the deployment's vtxo tree expiry")

	if expiry < minAllowedSequence {
		t.Skipf(
			"deployment is block-based (vtxo_tree_expiry=%d); epoch expiry needs a "+
				"time-based sweep scheduler - run 'make docker-run-epoch && make epochtest'",
			expiry,
		)
	}
}

// vtxoTreeExpirySetting mirrors the one settings field that tells us which
// scheduler arkd is running. Int64 proto fields are JSON-encoded as strings.
type vtxoTreeExpirySetting struct {
	Settings struct {
		VtxoTreeExpiry string `json:"vtxoTreeExpiry"`
	} `json:"settings"`
}

func getVtxoTreeExpirySetting() (int64, error) {
	url := fmt.Sprintf("%s/v1/admin/settings", adminUrl)
	resp, err := get[vtxoTreeExpirySetting](
		&http.Client{Timeout: 15 * time.Second}, url, "settings",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get settings: %w", err)
	}
	return parseSettingsInt(resp.Settings.VtxoTreeExpiry)
}

// epochEnabledSetting mirrors the one settings field that says whether epoch
// expiry is live. Bool proto fields are JSON-encoded as booleans.
type epochEnabledSetting struct {
	Settings struct {
		EpochExpiryEnabled bool `json:"epochExpiryEnabled"`
	} `json:"settings"`
}

func getEpochExpiryEnabledSetting() (bool, error) {
	url := fmt.Sprintf("%s/v1/admin/settings", adminUrl)
	resp, err := get[epochEnabledSetting](
		&http.Client{Timeout: 15 * time.Second}, url, "settings",
	)
	if err != nil {
		return false, fmt.Errorf("failed to get settings: %w", err)
	}
	return resp.Settings.EpochExpiryEnabled, nil
}
