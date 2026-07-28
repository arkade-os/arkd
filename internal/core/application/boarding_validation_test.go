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
		err := validateBoardingInput(tx, blockTimestamp, boardingInput(0, longTapscripts), now, settings)
		require.NoError(t, err)
	})

	// The regression this guards: validation used to be memoized per funding
	// txid, so a second input on the same tx skipped its own expiry check and a
	// matured exit path slipped through.
	t.Run("vout 1 with a matured exit path is rejected", func(t *testing.T) {
		err := validateBoardingInput(tx, blockTimestamp, boardingInput(1, shortTapscripts), now, settings)
		require.ErrorContains(t, err, "expired")
	})

	t.Run("amount bounds are checked against the spent output", func(t *testing.T) {
		tooSmall := &wire.MsgTx{
			TxOut: []*wire.TxOut{{Value: 100_000}, {Value: 10}},
		}
		err := validateBoardingInput(
			tooSmall, blockTimestamp, boardingInput(1, longTapscripts), now, settings,
		)
		require.ErrorContains(t, err, "lower than min utxo amount")

		tooBig := &wire.MsgTx{
			TxOut: []*wire.TxOut{{Value: 100_000}, {Value: 9_000_000}},
		}
		err = validateBoardingInput(
			tooBig, blockTimestamp, boardingInput(1, longTapscripts), now, settings,
		)
		require.ErrorContains(t, err, "higher than max utxo amount")
	})

	t.Run("vout past the end of the tx is rejected", func(t *testing.T) {
		err := validateBoardingInput(
			tx, blockTimestamp, boardingInput(5, longTapscripts), now, settings,
		)
		require.ErrorContains(t, err, "invalid vout index")
	})

	t.Run("unrolled vtxo needs margin before its exit matures", func(t *testing.T) {
		withMargin := settings
		withMargin.UnrolledVtxoMinExpiryMargin = 4 * time.Hour

		in := boardingInput(0, longTapscripts)
		in.isUnrolledVtxo = true

		// The long delay leaves 1h of lock, which is inside a 4h margin.
		err := validateBoardingInput(tx, blockTimestamp, in, now, withMargin)
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
