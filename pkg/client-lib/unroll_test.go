package arksdk

import (
	"context"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestAddInputsPerUtxoScript(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownerKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownerKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}

	vtxoScript1 := script.NewDefaultVtxoScript(ownerKey1.PubKey(), signerKey.PubKey(), exitDelay)
	vtxoScript2 := script.NewDefaultVtxoScript(ownerKey2.PubKey(), signerKey.PubKey(), exitDelay)

	tapscripts1, err := vtxoScript1.Encode()
	require.NoError(t, err)
	tapscripts2, err := vtxoScript2.Encode()
	require.NoError(t, err)

	// Scripts must differ because the owner keys differ.
	require.NotEqual(t, tapscripts1, tapscripts2)

	// Build a minimal PSBT with one output so the updater is valid.
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00}))

	pkt, err := psbt.New(nil, tx.TxOut, 2, 0, nil)
	require.NoError(t, err)

	updater, err := psbt.NewUpdater(pkt)
	require.NoError(t, err)

	utxos := []types.Utxo{
		{
			Outpoint:   types.Outpoint{Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VOut: 0},
			Tapscripts: tapscripts1,
			Delay:      exitDelay,
		},
		{
			Outpoint:   types.Outpoint{Txid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", VOut: 1},
			Tapscripts: tapscripts2,
			Delay:      exitDelay,
		},
	}

	svc := &service{}
	err = svc.addInputs(context.Background(), updater, utxos)
	require.NoError(t, err)

	// Each utxo should produce its own PSBT input.
	require.Len(t, updater.Upsbt.Inputs, 2)

	// Each input must have a taproot leaf script.
	require.Len(t, updater.Upsbt.Inputs[0].TaprootLeafScript, 1)
	require.Len(t, updater.Upsbt.Inputs[1].TaprootLeafScript, 1)

	// The leaf scripts must differ because the owner keys are different.
	script0 := updater.Upsbt.Inputs[0].TaprootLeafScript[0].Script
	script1 := updater.Upsbt.Inputs[1].TaprootLeafScript[0].Script
	require.NotEqual(t, script0, script1,
		"each PSBT input must use its own utxo's tapscript, not a shared one")

	// The control blocks must also differ (different internal keys).
	cb0 := updater.Upsbt.Inputs[0].TaprootLeafScript[0].ControlBlock
	cb1 := updater.Upsbt.Inputs[1].TaprootLeafScript[0].ControlBlock
	require.NotEqual(t, cb0, cb1)
}
