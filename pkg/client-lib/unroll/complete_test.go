package unroll

import (
	"context"
	"encoding/hex"
	"math"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestCompleteUnroll(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		// The fee is higher than the balance: the subtraction used to wrap and let
		// the flow continue with a negative output value instead of erroring out.
		t.Run("fee higher than balance", func(t *testing.T) {
			args := newTestCompleteUnrollArgs(t, 1000, 20)

			_, err := CompleteUnroll(context.Background(), args)
			require.Error(t, err)
			require.Contains(t, err.Error(), "not enough funds to cover network fees")
		})
	})
}

func TestBumpAnchorTx(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			utxoAmounts    []uint64
			feeRate        float64
			expectedErr    error
			expectedErrMsg string
		}{
			{
				name:           "negative fee",
				utxoAmounts:    []uint64{1000},
				feeRate:        -5,
				expectedErrMsg: "invalid fee amount",
			},
			{
				name:           "NaN fee",
				utxoAmounts:    []uint64{1000},
				feeRate:        math.NaN(),
				expectedErrMsg: "invalid fee amount",
			},
			{
				name:           "no onchain funds",
				feeRate:        10,
				expectedErr:    ErrInsufficientOnchainFunds,
				expectedErrMsg: "none available",
			},
			{
				name:           "not enough onchain funds",
				utxoAmounts:    []uint64{100, 200},
				feeRate:        10,
				expectedErr:    ErrInsufficientOnchainFunds,
				expectedErrMsg: "more sat",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				args, parent := newTestBumpAnchorArgs(t, tc.utxoAmounts, tc.feeRate)

				_, _, err := bumpAnchorTx(t.Context(), args, parent)
				if tc.expectedErr != nil {
					require.ErrorIs(t, err, tc.expectedErr)
				}
				require.ErrorContains(t, err, tc.expectedErrMsg)
			})
		}
	})
}

// testTxid is a valid txid used as previous outpoint of the test utxo.
const testTxid = "0000000000000000000000000000000000000000000000000000000000000001"

// stubExplorer returns a fixed fee rate, no other explorer method is expected
// to be called by the tests.
type stubExplorer struct {
	clientlib.Explorer
	feeRate float64
}

func (e stubExplorer) GetFeeRate() (float64, error) {
	return e.feeRate, nil
}

// bumpStubExplorer additionally serves utxos to the bump coin selection.
type bumpStubExplorer struct {
	stubExplorer
	utxos []clientlib.ExplorerUtxo
}

func (e bumpStubExplorer) GetUtxos(_ []string) ([]clientlib.ExplorerUtxo, error) {
	return e.utxos, nil
}

// newTestBumpAnchorArgs returns args holding one utxo per given amount with the
// explorer stubbed to the given fee rate, plus a parent tx carrying an anchor
// output for the bump to spend.
func newTestBumpAnchorArgs(
	t *testing.T, utxoAmounts []uint64, feeRate float64,
) (UnrollArgs, *wire.MsgTx) {
	t.Helper()

	bumpKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	netParams := clientlib.ToBitcoinNetwork(arklib.BitcoinRegTest)
	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(bumpKey.PubKey()), &netParams,
	)
	require.NoError(t, err)

	parent := wire.NewMsgTx(2)
	parent.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	parent.AddTxOut(txutils.AnchorOutput())

	utxos := make([]clientlib.ExplorerUtxo, 0, len(utxoAmounts))
	for i, amount := range utxoAmounts {
		utxos = append(utxos, clientlib.ExplorerUtxo{
			Txid: testTxid, Vout: uint32(i), Amount: amount,
		})
	}

	args := UnrollArgs{
		Explorer: bumpStubExplorer{
			stubExplorer: stubExplorer{feeRate: feeRate},
			utxos:        utxos,
		},
		ServerParams: clientlib.ServerParams{
			Network: arklib.BitcoinRegTest,
			Dust:    546,
		},
		BumpAddr:   addr.EncodeAddress(),
		BumpPubKey: bumpKey.PubKey(),
		SignTx: func(context.Context, string) (string, error) {
			t.Fatal("sign tx must not be called")
			return "", nil
		},
	}
	return args, parent
}

// newTestCompleteUnrollArgs returns args spending a single mature utxo of the
// given amount, with the explorer stubbed to the given fee rate. SignTx makes
// the test fail if the flow gets past the fee check.
func newTestCompleteUnrollArgs(
	t *testing.T, amount uint64, feeRate float64,
) CompleteUnrollArgs {
	t.Helper()

	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signer, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	vtxoScript := script.NewDefaultVtxoScript(owner.PubKey(), signer.PubKey(), exitDelay)

	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)

	tapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)

	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	netParams := clientlib.ToBitcoinNetwork(arklib.BitcoinRegTest)
	addr, err := address.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &netParams)
	require.NoError(t, err)

	return CompleteUnrollArgs{
		Explorer: stubExplorer{feeRate: feeRate},
		SignTx: func(context.Context, string) (string, error) {
			t.Fatal("sign tx must not be called")
			return "", nil
		},
		ServerParams: clientlib.ServerParams{
			Network: arklib.BitcoinRegTest,
			Dust:    546,
		},
		Utxos: []clientlib.Utxo{
			{
				Outpoint:   clientlib.Outpoint{Txid: testTxid, VOut: 0},
				Amount:     amount,
				Script:     hex.EncodeToString(pkScript),
				Delay:      exitDelay,
				Tapscripts: tapscripts,
			},
		},
		Receiver: addr.EncodeAddress(),
	}
}
