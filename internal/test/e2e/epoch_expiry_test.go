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
// They run as part of the normal integration suite rather than behind a flag.
// They were gated behind -epoch at first, which make integrationtest never
// passes, so they would have been skipped in CI while looking present - and the
// boundary sweep test below is the only one that exercises the path where two
// scheduling bugs were found by reading rather than by testing. Waiting for a
// real boundary costs this package several minutes; that is the price of the
// only coverage the epoch sweep path has.

const (
	// Tiny so the tests finish. Production defaults are 28 days, 7 days and
	// 12 hours respectively.
	epochTestLength   = 600 // 10 minutes
	epochTestRollover = 300 // 5 minutes
	epochTestCutoff   = 60  // 1 minute
	epochTestGrace    = 512 // BIP68 seconds granularity
)

// Seconds-based replacements for the deployment's block-based delays, applied
// for the duration of an epoch test. All are multiples of 512, the granularity
// BIP68 gives a seconds-based sequence, and they satisfy the cross-field rules
// in Settings.Validate: every delay shares the vtxo tree expiry's type, the
// public unilateral delay is at least the internal one, and the boarding delay
// differs from the unilateral one.
const (
	epochTestTreeExpiry     = 1024
	epochTestUnilateral     = 512
	epochTestPublicExit     = 1024
	epochTestBoardingExit   = 1536
	epochTestCheckpointExit = 512
)

// enableEpochExpiry switches the running arkd over to epoch expiry and restores
// the previous mode on cleanup. Returns the anchor it configured.
//
// The e2e stack is configured with block-based delays (ARKD_VTXO_TREE_EXPIRY=40
// and exit delays of 10-30, all below MinAllowedSequence), and settings
// validation refuses epoch expiry on such a deployment - an epoch date is a unix
// timestamp, and a block-height sweep scheduler would read it as a block roughly
// 1.8 billion ahead, so the batch would never be swept. So the delays have to
// move to seconds first. That is one update rather than several because
// Settings.Update validates a copy and commits only if the whole set is
// coherent; changing them one at a time would be rejected at the first step for
// mixing types.
func enableEpochExpiry(t *testing.T) int64 {
	t.Helper()

	previous, err := getEpochTestDelays()
	require.NoError(t, err, "failed to read the delays to restore")

	// Anchor on an exact multiple of the epoch length so boundaries are
	// predictable from the test's own clock.
	now := time.Now().Unix()
	anchor := now - (now % epochTestLength)

	_, err = runDockerExec(
		"arkd", "arkd", "settings", "update",
		"--epoch-expiry-enabled",
		"--epoch-anchor", strconv.FormatInt(anchor, 10),
		"--epoch-length", strconv.Itoa(epochTestLength),
		"--rollover-window", strconv.Itoa(epochTestRollover),
		"--settlement-cutoff", strconv.Itoa(epochTestCutoff),
		"--unroll-grace", strconv.Itoa(epochTestGrace),
		"--vtxo-tree-expiry", strconv.Itoa(epochTestTreeExpiry),
		"--unilateral-exit-delay", strconv.Itoa(epochTestUnilateral),
		"--public-unilateral-exit-delay", strconv.Itoa(epochTestPublicExit),
		"--boarding-exit-delay", strconv.Itoa(epochTestBoardingExit),
		"--checkpoint-exit-delay", strconv.Itoa(epochTestCheckpointExit),
	)
	require.NoError(t, err, "failed to enable epoch expiry")

	t.Cleanup(func() {
		// Restore in one update for the same reason, and put the block-based
		// delays back before any later test builds a batch against them.
		if _, err := runDockerExec(
			"arkd", "arkd", "settings", "update",
			"--epoch-expiry-enabled=false",
			"--vtxo-tree-expiry", strconv.FormatInt(previous.VtxoTreeExpiry, 10),
			"--unilateral-exit-delay", strconv.FormatInt(previous.UnilateralExitDelay, 10),
			"--public-unilateral-exit-delay",
			strconv.FormatInt(previous.PublicUnilateralExitDelay, 10),
			"--boarding-exit-delay", strconv.FormatInt(previous.BoardingExitDelay, 10),
			"--checkpoint-exit-delay", strconv.FormatInt(previous.CheckpointExitDelay, 10),
			"--unroll-grace", strconv.FormatInt(previous.UnrollGrace, 10),
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

// epochTestDelays are the locktime settings an epoch test has to move to
// seconds and put back afterwards.
type epochTestDelays struct {
	VtxoTreeExpiry            int64
	UnilateralExitDelay       int64
	PublicUnilateralExitDelay int64
	BoardingExitDelay         int64
	CheckpointExitDelay       int64
	UnrollGrace               int64
}

// epochDelaySettings mirrors only the locktime fields of the admin settings
// response. Int64 proto fields are JSON-encoded as strings.
type epochDelaySettings struct {
	Settings struct {
		VtxoTreeExpiry            string `json:"vtxoTreeExpiry"`
		UnilateralExitDelay       string `json:"unilateralExitDelay"`
		PublicUnilateralExitDelay string `json:"publicUnilateralExitDelay"`
		BoardingExitDelay         string `json:"boardingExitDelay"`
		CheckpointExitDelay       string `json:"checkpointExitDelay"`
		UnrollGrace               string `json:"unrollGrace"`
	} `json:"settings"`
}

// getEpochTestDelays reads the delays currently configured on the running arkd.
func getEpochTestDelays() (*epochTestDelays, error) {
	url := fmt.Sprintf("%s/v1/admin/settings", adminUrl)
	resp, err := get[epochDelaySettings](
		&http.Client{Timeout: 15 * time.Second}, url, "settings",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	out := &epochTestDelays{}
	// Every one of these is restored verbatim on cleanup, so an absent value is an
	// error rather than a zero: restoring 0 would leave the deployment with no
	// exit delay at all.
	for _, f := range []struct {
		name  string
		value string
		into  *int64
	}{
		{"vtxoTreeExpiry", resp.Settings.VtxoTreeExpiry, &out.VtxoTreeExpiry},
		{"unilateralExitDelay", resp.Settings.UnilateralExitDelay, &out.UnilateralExitDelay},
		{
			"publicUnilateralExitDelay", resp.Settings.PublicUnilateralExitDelay,
			&out.PublicUnilateralExitDelay,
		},
		{"boardingExitDelay", resp.Settings.BoardingExitDelay, &out.BoardingExitDelay},
		{"checkpointExitDelay", resp.Settings.CheckpointExitDelay, &out.CheckpointExitDelay},
		{"unrollGrace", resp.Settings.UnrollGrace, &out.UnrollGrace},
	} {
		parsed, err := parseSettingsInt(f.value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", f.name, err)
		}
		*f.into = parsed
	}

	return out, nil
}
