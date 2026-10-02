package offchain

import (
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestBuildArkTxRejectsMixedLocktimeTypes(t *testing.T) {
	newInput := func(locktime arklib.AbsoluteLocktime, index uint32) VtxoInput {
		closure := &script.CLTVMultisigClosure{
			Locktime: locktime,
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{script.UnspendableKey()},
			},
		}
		revealedScript, err := closure.Script()
		require.NoError(t, err)

		return VtxoInput{
			Outpoint: &wire.OutPoint{Index: index},
			Amount:   1_000,
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock: &txscript.ControlBlock{
					InternalKey: script.UnspendableKey(),
					LeafVersion: txscript.BaseLeafVersion,
				},
				RevealedScript: revealedScript,
			},
			RevealedTapscripts: []string{hex.EncodeToString(revealedScript)},
		}
	}

	zero := newInput(0, 0)
	timestamp := newInput(1_700_000_000, 1)
	for _, test := range []struct {
		name   string
		inputs []VtxoInput
	}{
		{name: "zero first", inputs: []VtxoInput{zero, timestamp}},
		{name: "timestamp first", inputs: []VtxoInput{timestamp, zero}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildArkTx(test.inputs, nil)
			require.EqualError(t, err, "mixed absolute locktime types")
		})
	}
}

func TestBuildTxs(t *testing.T) {
	vtxos, outputScript, unrollScript := testBuildTxsArgs(t)

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name         string
			outputAmount int64
		}{
			{
				name:         "output amount equal to input amount",
				outputAmount: testInputAmount,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				outputs := []*wire.TxOut{{Value: tt.outputAmount, PkScript: outputScript}}

				arkTx, checkpointTxs, err := BuildTxs(vtxos, outputs, unrollScript)
				require.NoError(t, err)
				require.Len(t, checkpointTxs, len(vtxos))
				require.Equal(t, testInputAmount, checkpointTxs[0].UnsignedTx.TxOut[0].Value)
				require.Equal(t, testInputAmount, arkTx.Inputs[0].WitnessUtxo.Value)
				require.Equal(t, tt.outputAmount, arkTx.UnsignedTx.TxOut[0].Value)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name         string
			outputAmount int64
			expectedErr  string
		}{
			{
				name:         "output amount lower than input amount",
				outputAmount: testInputAmount - 1,
				expectedErr:  "input amount is not equal to output amount",
			},
			{
				name:         "output amount exceeding input amount",
				outputAmount: testInputAmount + 1,
				expectedErr:  "output amount exceeds input amount",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				outputs := []*wire.TxOut{{Value: tt.outputAmount, PkScript: outputScript}}

				arkTx, checkpointTxs, err := BuildTxs(vtxos, outputs, unrollScript)
				require.EqualError(t, err, tt.expectedErr)
				require.Nil(t, arkTx)
				require.Nil(t, checkpointTxs)
			})
		}
	})
}

func TestBuildTxsWithFee(t *testing.T) {
	vtxos, outputScript, unrollScript := testBuildTxsArgs(t)

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name         string
			outputAmount int64
		}{
			{
				name:         "output amount lower than input amount",
				outputAmount: testInputAmount - 1,
			},
			{
				name:         "output amount equal to input amount",
				outputAmount: testInputAmount,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				outputs := []*wire.TxOut{{Value: tt.outputAmount, PkScript: outputScript}}

				arkTx, checkpointTxs, err := BuildTxsWithFee(vtxos, outputs, unrollScript)
				require.NoError(t, err)
				require.Len(t, checkpointTxs, len(vtxos))
				require.Equal(t, testInputAmount, checkpointTxs[0].UnsignedTx.TxOut[0].Value)
				require.Equal(t, testInputAmount, arkTx.Inputs[0].WitnessUtxo.Value)
				require.Equal(t, tt.outputAmount, arkTx.UnsignedTx.TxOut[0].Value)

				anchor := arkTx.UnsignedTx.TxOut[1]
				require.Equal(t, txutils.ANCHOR_PKSCRIPT, anchor.PkScript)
				require.Equal(t, testInputAmount-tt.outputAmount, anchor.Value)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name         string
			outputAmount int64
			expectedErr  string
		}{
			{
				name:         "output amount exceeding input amount",
				outputAmount: testInputAmount + 1,
				expectedErr:  "output amount exceeds input amount",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				outputs := []*wire.TxOut{{Value: tt.outputAmount, PkScript: outputScript}}

				arkTx, checkpointTxs, err := BuildTxsWithFee(vtxos, outputs, unrollScript)
				require.EqualError(t, err, tt.expectedErr)
				require.Nil(t, arkTx)
				require.Nil(t, checkpointTxs)
			})
		}
	})
}

const testInputAmount = int64(616)

// testBuildTxsArgs returns a vtxo of testInputAmount to spend, the script of the
// output to create and the signer unroll script.
func testBuildTxsArgs(t *testing.T) ([]VtxoInput, []byte, []byte) {
	t.Helper()
	key := script.UnspendableKey()
	ownerScript, err := (&script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{key},
	}).Script()
	require.NoError(t, err)
	unrollScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{key}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	}).Script()
	require.NoError(t, err)
	outputScript, err := script.P2TRScript(key)
	require.NoError(t, err)

	vtxos := []VtxoInput{{
		Outpoint: &wire.OutPoint{},
		Amount:   testInputAmount,
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock: &txscript.ControlBlock{
				InternalKey: key,
				LeafVersion: txscript.BaseLeafVersion,
			},
			RevealedScript: ownerScript,
		},
		RevealedTapscripts: []string{hex.EncodeToString(ownerScript)},
	}}
	return vtxos, outputScript, unrollScript
}
