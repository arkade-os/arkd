package txutils_test

import (
	"testing"

	common "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestPsbtCustomUnknownFields(t *testing.T) {
	t.Run("condition witness", func(t *testing.T) {
		// Create a new PSBT
		ptx, err := psbt.New(nil, nil, 2, 0, nil)
		require.NoError(t, err)

		// Add an empty input since we need at least one
		ptx.UnsignedTx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			Sequence:         0,
		}}
		ptx.Inputs = []psbt.PInput{{}}

		// Create a sample witness
		witness := wire.TxWitness{
			[]byte{0x01, 0x02},
			[]byte{0x03, 0x04},
		}

		// Add witness to input 0
		err = txutils.SetArkPsbtField(ptx, 0, txutils.ConditionWitnessField, witness)
		require.NoError(t, err)

		// Get witness back and verify
		fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.ConditionWitnessField)
		require.NotNil(t, fields)
		require.Len(t, fields, 1)
		require.NoError(t, err)
		require.Equal(t, len(witness), len(fields[0]))

		for i := range witness {
			require.Equal(t, witness[i], fields[0][i])
		}
	})

	t.Run("vtxo tree expiry", func(t *testing.T) {
		// Create a new PSBT
		ptx, err := psbt.New(nil, nil, 2, 0, nil)
		require.NoError(t, err)

		// Add an empty input
		ptx.UnsignedTx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			Sequence:         0,
		}}
		ptx.Inputs = []psbt.PInput{{}}

		// Add vtxo tree expiry
		vtxoTreeExpiry := common.RelativeLocktime{
			Type:  common.LocktimeTypeBlock,
			Value: 144, // 1 day worth of blocks
		}
		err = txutils.SetArkPsbtField(ptx, 0, txutils.VtxoTreeExpiryField, vtxoTreeExpiry)
		require.NoError(t, err)

		// Get vtxo tree expiry back and verify
		fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.VtxoTreeExpiryField)
		require.NotNil(t, fields)
		require.Len(t, fields, 1)
		require.NoError(t, err)
		require.Equal(t, vtxoTreeExpiry.Type, fields[0].Type)
		require.Equal(t, vtxoTreeExpiry.Value, fields[0].Value)
	})

	t.Run("cosigner keys", func(t *testing.T) {
		// Create a new PSBT
		ptx, err := psbt.New(nil, nil, 2, 0, nil)
		require.NoError(t, err)

		// Add an empty input
		ptx.UnsignedTx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			Sequence:         0,
		}}
		ptx.Inputs = []psbt.PInput{{}}

		// Create and add 40 cosigner keys
		var keys []*btcec.PublicKey
		for i := range 40 {
			key, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			keys = append(keys, key.PubKey())

			err = txutils.SetArkPsbtField(ptx, 0, txutils.CosignerPublicKeyField, txutils.IndexedCosignerPublicKey{
				Index:     i,
				PublicKey: key.PubKey(),
			})
			require.NoError(t, err)
		}

		// Get cosigner keys back and verify
		fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.CosignerPublicKeyField)
		require.NotNil(t, fields)
		require.Len(t, fields, 40)
		require.NoError(t, err)

		// Verify each key matches and is in the correct order
		for i := range 40 {
			require.Equal(t, keys[i].SerializeCompressed(), fields[i].PublicKey.SerializeCompressed())
		}
	})

	t.Run("tapscripts", func(t *testing.T) {
		// Create a new PSBT
		ptx, err := psbt.New(nil, nil, 2, 0, nil)
		require.NoError(t, err)

		// Add an empty input
		ptx.UnsignedTx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			Sequence:         0,
		}}
		ptx.Inputs = []psbt.PInput{{}}

		// Test cases with various tapscripts
		testCases := [][]string{
			{},
			{"51201234567890abcdef"},
			{
				"51201234567890abcdef",
				"522103deadbeef",
				"76a914123456789012345678901234567890",
			},
		}

		for _, scripts := range testCases {
			// Add tapscripts to input 0
			err = txutils.SetArkPsbtField(ptx, 0, txutils.VtxoTaprootTreeField, scripts)
			require.NoError(t, err)

			// Get tapscripts back and verify
			fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.VtxoTaprootTreeField)
			require.NotNil(t, fields)
			require.Len(t, fields, 1)
			require.NoError(t, err)
			require.Equal(t, len(scripts), len(fields[0]))

			for i := range scripts {
				require.Equal(t, scripts[i], fields[0][i])
			}

			// Clear the unknowns for next test case
			ptx.Inputs[0].Unknowns = nil
		}
	})
}
