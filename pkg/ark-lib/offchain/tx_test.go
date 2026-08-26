package offchain

import (
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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
