package txbuilder_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestVerifyForfeitTxsPrevoutBinding pins that the psbt prevout metadata of a forfeit tx is
// bound to what the operator knows. The txid comparison alone does not cover it: a txid commits
// to the wire tx only, so a client can leave the tx itself correct and forge the WitnessUtxo the
// sighash is computed over, yielding a forfeit tx the operator accepts but bitcoin rejects.
func TestVerifyForfeitTxsPrevoutBinding(t *testing.T) {
	t.Run("valid forfeit tx is accepted", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		valid, err := builder.VerifyForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.NoError(t, err)
		require.Len(t, valid, 1)
	})

	t.Run("forged witness utxo amount is refused", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		txidBefore := forfeit.UnsignedTx.TxID()
		forfeit.Inputs[0].WitnessUtxo.Value += 100_000_000
		require.Equal(t, txidBefore, forfeit.UnsignedTx.TxID(),
			"forging the prevout must not change the txid, otherwise the txid check catches it")

		_, err := builder.VerifyForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.ErrorContains(t, err, "invalid witness utxo for input 0")
	})

	t.Run("forged witness utxo script is refused", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		forfeit.Inputs[0].WitnessUtxo.PkScript = []byte{txscript.OP_TRUE}

		_, err := builder.VerifyForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.ErrorContains(t, err, "invalid witness utxo for input 0")
	})

	t.Run("missing witness utxo is refused", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		forfeit.Inputs[0].WitnessUtxo = nil

		_, err := builder.VerifyForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.ErrorContains(t, err, "invalid witness utxo for input 0")
	})
}

// newForfeitScenario builds the minimum a forfeit tx needs to pass VerifyForfeitTxs: one vtxo
// known to the operator, a one-leaf connector tree, and a forfeit tx spending both. Only the
// prevout metadata is interesting, the signature itself is never checked by this function.
func newForfeitScenario(
	t *testing.T,
) (ports.TxBuilder, []domain.Vtxo, tree.FlatTxTree, *psbt.Packet) {
	t.Helper()

	wallet.On("GetCurrentBlockTime", mock.Anything).
		Return(&ports.BlockTimestamp{Height: 100, Time: 1_700_000_000}, nil).Maybe()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	builder := txbuilder.NewTxBuilder(
		wallet, &staticSigner{pubkey: signerKey.PubKey()}, arklib.Bitcoin,
	)

	// the vtxo the operator knows about
	vtxoKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	vtxoXOnly := schnorr.SerializePubKey(vtxoKey.PubKey())
	vtxoTapKey, err := schnorr.ParsePubKey(vtxoXOnly)
	require.NoError(t, err)
	vtxoScript, err := script.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	var vtxoHash chainhash.Hash
	copy(vtxoHash[:], []byte("vtxo-prevout-hash-32-bytes-xxxxx"))
	vtxo := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: vtxoHash.String(), VOut: 0},
		PubKey:   hex.EncodeToString(vtxoXOnly),
		Amount:   10_000,
	}

	// a one-leaf connector tree
	connectorOut := wire.NewTxOut(450, vtxoScript)
	connectorPtx, err := psbt.New(
		[]*wire.OutPoint{{Hash: chainhash.Hash{}, Index: 0}},
		[]*wire.TxOut{connectorOut},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	connectors := tree.FlatTxTree{{
		Txid: connectorPtx.UnsignedTx.TxID(),
		Tx:   encodeTx(t, connectorPtx),
	}}

	connectorHash, err := chainhash.NewHashFromStr(connectorPtx.UnsignedTx.TxID())
	require.NoError(t, err)

	// the forfeit script the builder will independently derive
	forfeitPubkeyBytes, err := hex.DecodeString(forfeitPubkey)
	require.NoError(t, err)
	forfeitPub, err := btcec.ParsePubKey(forfeitPubkeyBytes)
	require.NoError(t, err)
	forfeitAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(forfeitPub.SerializeCompressed()), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	forfeitScript, err := txscript.PayToAddrScript(forfeitAddr)
	require.NoError(t, err)

	// vtxo input first, connector second
	forfeit, err := tree.BuildForfeitTx(
		[]*wire.OutPoint{
			{Hash: vtxoHash, Index: 0},
			{Hash: *connectorHash, Index: 0},
		},
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
		[]*wire.TxOut{
			{Value: int64(vtxo.Amount), PkScript: vtxoScript},
			connectorOut,
		},
		forfeitScript,
		0,
	)
	require.NoError(t, err)

	// the vtxo input must carry a forfeit closure leaf and a spend sig to be considered
	closureSetup := newSingleKeyVtxoSetup(t, signerKey)
	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: closureSetup.cbBytes,
		Script:       closureSetup.closureScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	sig := makeVtxoSig(t, closureSetup.closureKey, forfeit, closureSetup.leaf)
	forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

	return builder, []domain.Vtxo{vtxo}, connectors, forfeit
}
