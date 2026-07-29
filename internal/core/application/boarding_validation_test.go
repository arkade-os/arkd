package application

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Two boarding inputs can share one funding tx while carrying different
// tapscripts, exit delays and amounts, so every check in validateBoardingInput
// is per-output. These tests pin that: the same funding tx and block timestamp
// yield different verdicts depending only on which output is being spent.
func TestValidateBoardingInput(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signer := signerKey.PubKey()

	ownerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	owner := ownerKey.PubKey()

	now := time.Now()
	// Confirmed an hour ago. CSV seconds must be a multiple of 512 (BIP68), so
	// 7168s (~2h) is still locked while 1536s (~25m) has already matured.
	confirmedAt := now.Add(-time.Hour)
	blockTimestamp := &ports.BlockTimestamp{Height: 100, Time: confirmedAt.Unix()}
	tip := &ports.BlockTimestamp{Height: 200, Time: now.Unix()}

	longDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
	shortDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1536}

	longScript := script.NewDefaultVtxoScript(owner, signer, longDelay)
	shortScript := script.NewDefaultVtxoScript(owner, signer, shortDelay)

	longTapscripts, err := longScript.Encode()
	require.NoError(t, err)
	shortTapscripts, err := shortScript.Encode()
	require.NoError(t, err)

	// One funding tx with two outputs, spent by two different boarding inputs.
	tx := &wire.MsgTx{
		TxOut: []*wire.TxOut{
			{Value: 100_000},
			{Value: 100_000},
		},
	}

	settings := ports.Settings{
		SignerPubkey: signer,
	}
	settings.BoardingExitDelay = shortDelay
	settings.UnilateralExitDelay = shortDelay
	settings.UtxoMinAmount = 1_000
	settings.UtxoMaxAmount = 1_000_000

	t.Run("vout 0 with a still-locked exit path passes", func(t *testing.T) {
		err := validateBoardingInput(tx, blockTimestamp, tip, boardingInput(0, longTapscripts), now, settings)
		require.NoError(t, err)
	})

	// The regression this guards: validation used to be memoized per funding
	// txid, so a second input on the same tx skipped its own expiry check and a
	// matured exit path slipped through.
	t.Run("vout 1 with a matured exit path is rejected", func(t *testing.T) {
		err := validateBoardingInput(tx, blockTimestamp, tip, boardingInput(1, shortTapscripts), now, settings)
		require.ErrorContains(t, err, "expired")
	})

	t.Run("amount bounds are checked against the spent output", func(t *testing.T) {
		tooSmall := &wire.MsgTx{
			TxOut: []*wire.TxOut{{Value: 100_000}, {Value: 10}},
		}
		err := validateBoardingInput(
			tooSmall, blockTimestamp, tip, boardingInput(1, longTapscripts), now, settings,
		)
		require.ErrorContains(t, err, "lower than min utxo amount")

		tooBig := &wire.MsgTx{
			TxOut: []*wire.TxOut{{Value: 100_000}, {Value: 9_000_000}},
		}
		err = validateBoardingInput(
			tooBig, blockTimestamp, tip, boardingInput(1, longTapscripts), now, settings,
		)
		require.ErrorContains(t, err, "higher than max utxo amount")
	})

	t.Run("vout past the end of the tx is rejected", func(t *testing.T) {
		err := validateBoardingInput(
			tx, blockTimestamp, tip, boardingInput(5, longTapscripts), now, settings,
		)
		require.ErrorContains(t, err, "invalid vout index")
	})

	t.Run("unrolled vtxo needs margin before its exit matures", func(t *testing.T) {
		withMargin := settings
		withMargin.UnrolledVtxoMinExpiryMargin = 4 * time.Hour

		in := boardingInput(0, longTapscripts)
		in.isUnrolledVtxo = true

		// The long delay leaves 1h of lock, which is inside a 4h margin.
		err := validateBoardingInput(tx, blockTimestamp, tip, in, now, withMargin)
		require.ErrorContains(t, err, "expires too soon")
	})

	// The unrolled-vtxo margin used to be measured against a csvExpiresAt built
	// from RelativeLocktime.Seconds(), so a block-typed delay was read at
	// SECONDS_PER_BLOCK = 1: a 144-block exit looked like it matured 144 seconds
	// after confirmation, and every unrolled vtxo on a block-typed config was
	// rejected as "expires too soon". Regtest runs block-typed
	// (ARKD_VTXO_TREE_EXPIRY=40 is under the 512 threshold), so this was live.
	t.Run("unrolled vtxo with a block-typed delay is measured in blocks", func(t *testing.T) {
		blockDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
		blockScript := script.NewDefaultVtxoScript(owner, signer, blockDelay)
		blockTapscripts, err := blockScript.Encode()
		require.NoError(t, err)

		blockSettings := settings
		blockSettings.BoardingExitDelay = blockDelay
		blockSettings.UnilateralExitDelay = blockDelay
		blockSettings.VtxoTreeExpiry = blockDelay // makes AllowCSVBlockType() true
		blockSettings.UnrolledVtxoMinExpiryMargin = 5 * time.Minute

		in := boardingInput(0, blockTapscripts)
		in.isUnrolledVtxo = true

		// Confirmed at 100, matures at 244. A 5m margin is one block, so the
		// threshold is tip+1+1 >= 244. At tip 200 there are ~43 blocks to go and
		// the input must be accepted, which the seconds reading got wrong.
		err = validateBoardingInput(tx, blockTimestamp, tip, in, now, blockSettings)
		require.NoError(t, err)

		// At tip 242 the margin block bites: 242+1+1 == 244.
		nearTip := &ports.BlockTimestamp{Height: 242, Time: now.Unix()}
		err = validateBoardingInput(tx, blockTimestamp, nearTip, in, now, blockSettings)
		require.ErrorContains(t, err, "expires too soon")
	})
}

// boardingInput builds a boarding input for the given output index, with the
// locktime check disabled so tests exercise one rule at a time.
func boardingInput(vout uint32, tapscripts []string) boardingIntentInput {
	in := boardingIntentInput{locktimeDisabled: true}
	in.VOut = vout
	in.Txid = "0000000000000000000000000000000000000000000000000000000000000001"
	in.Tapscripts = tapscripts
	return in
}

// Block-typed relative locktimes must be evaluated in blocks. Routing them
// through RelativeLocktime.Seconds() converts at SECONDS_PER_BLOCK = 1, which
// would mature a 144-block exit 144 seconds after confirmation.
func TestExitPathAvailable(t *testing.T) {
	now := time.Now()
	conf := &ports.BlockTimestamp{Height: 100, Time: now.Add(-time.Hour).Unix()}
	blockDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}

	// Per BIP68 an input confirmed at H with N blocks first becomes spendable
	// in block H+N, so it is available once tip+1 >= H+N. Here H+N = 244.
	t.Run("block delay boundary", func(t *testing.T) {
		for _, tc := range []struct {
			tipHeight uint32
			available bool
		}{
			{242, false}, // next block 243 < 244
			{243, true},  // next block 244 == 244, first available tip
			{244, true},
		} {
			got, err := exitPathAvailable(
				conf, &ports.BlockTimestamp{Height: tc.tipHeight}, blockDelay, 0, now,
			)
			require.NoError(t, err)
			require.Equalf(t, tc.available, got, "tip=%d", tc.tipHeight)
		}
	})

	t.Run("margin rejects earlier than plain maturity", func(t *testing.T) {
		tip := &ports.BlockTimestamp{Height: 240}
		plain, err := exitPathAvailable(conf, tip, blockDelay, 0, now)
		require.NoError(t, err)
		require.False(t, plain)

		// 240+1+3 == 244, so a 3-block margin trips at a tip that is otherwise fine.
		withMargin, err := exitPathAvailable(conf, tip, blockDelay, 3*targetBlockInterval, now)
		require.NoError(t, err)
		require.True(t, withMargin)
	})

	// The margin is a duration, so against a block-typed delay it has to be
	// converted. Rounding down would silently drop every margin shorter than one
	// block interval, which is most of them: the default is 5 minutes.
	t.Run("duration margin converts to whole blocks, rounding up", func(t *testing.T) {
		for _, tc := range []struct {
			margin time.Duration
			blocks int64
		}{
			{0, 0},
			{time.Nanosecond, 1},
			{5 * time.Minute, 1},
			{targetBlockInterval, 1},
			{targetBlockInterval + time.Nanosecond, 2},
			{3 * targetBlockInterval, 3},
			{-time.Hour, 0},
		} {
			require.Equalf(
				t, tc.blocks, blocksForDuration(tc.margin), "margin=%s", tc.margin,
			)
		}
	})

	t.Run("block delay needs a tip and a real confirmation height", func(t *testing.T) {
		_, err := exitPathAvailable(conf, nil, blockDelay, 0, now)
		require.ErrorContains(t, err, "chain tip")

		_, err = exitPathAvailable(
			&ports.BlockTimestamp{Height: 0}, &ports.BlockTimestamp{Height: 200},
			blockDelay, 0, now,
		)
		require.ErrorContains(t, err, "confirmation height")
	})

	t.Run("seconds delay keeps wall-clock semantics", func(t *testing.T) {
		secondsDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1536}
		// Confirmed an hour ago, so a 1536s lock has matured.
		got, err := exitPathAvailable(conf, nil, secondsDelay, 0, now)
		require.NoError(t, err)
		require.True(t, got)

		longDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
		got, err = exitPathAvailable(conf, nil, longDelay, 0, now)
		require.NoError(t, err)
		require.False(t, got)
	})

	t.Run("seconds delay honours the margin", func(t *testing.T) {
		// 7168s from an hour ago leaves ~59m of lock.
		longDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}

		got, err := exitPathAvailable(conf, nil, longDelay, 30*time.Minute, now)
		require.NoError(t, err)
		require.False(t, got)

		got, err = exitPathAvailable(conf, nil, longDelay, 2*time.Hour, now)
		require.NoError(t, err)
		require.True(t, got)
	})
}
