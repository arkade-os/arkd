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
		err = txutils.AddConditionWitness(0, ptx, witness)
		require.NoError(t, err)

		// Get witness back and verify
		retrievedWitness, err := txutils.GetConditionWitness(ptx.Inputs[0])
		require.NoError(t, err)
		require.Equal(t, len(witness), len(retrievedWitness))

		for i := range witness {
			require.Equal(t, witness[i], retrievedWitness[i])
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
		err = txutils.AddVtxoTreeExpiry(0, ptx, vtxoTreeExpiry)
		require.NoError(t, err)

		// Get vtxo tree expiry back and verify
		retrievedVtxoTreeExpiry, err := txutils.GetVtxoTreeExpiry(ptx.Inputs[0])
		require.NoError(t, err)
		require.NotNil(t, retrievedVtxoTreeExpiry)
		require.Equal(t, vtxoTreeExpiry.Type, retrievedVtxoTreeExpiry.Type)
		require.Equal(t, vtxoTreeExpiry.Value, retrievedVtxoTreeExpiry.Value)
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
		for i := 0; i < 40; i++ {
			key, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			keys = append(keys, key.PubKey())

			err = txutils.AddCosignerKey(0, ptx, key.PubKey())
			require.NoError(t, err)
		}

		// Get cosigner keys back and verify
		retrievedKeys, err := txutils.GetCosignerKeys(ptx.Inputs[0])
		require.NoError(t, err)
		require.Len(t, retrievedKeys, 40)

		// Verify each key matches and is in the correct order
		for i := 0; i < 40; i++ {
			require.Equal(t, keys[i].SerializeCompressed(), retrievedKeys[i].SerializeCompressed())
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
			err = txutils.AddTaprootTree(0, ptx, scripts)
			require.NoError(t, err)

			// Get tapscripts back and verify
			retrievedScripts, err := txutils.GetTaprootTree(ptx.Inputs[0])
			require.NoError(t, err)
			require.Equal(t, len(scripts), len(retrievedScripts))

			for i := range scripts {
				require.Equal(t, scripts[i], retrievedScripts[i])
			}

			// Clear the unknowns for next test case
			ptx.Inputs[0].Unknowns = nil
		}
	})
}
