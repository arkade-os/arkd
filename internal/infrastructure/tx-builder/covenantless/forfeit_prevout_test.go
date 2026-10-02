package txbuilder_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestVerifyAndRebuildForfeitTxsPrevoutBinding pins that the psbt prevout metadata of a forfeit tx is
// bound to what the operator knows. The txid comparison alone does not cover it: a txid commits
// to the wire tx only, so a client can leave the tx itself correct and forge the WitnessUtxo the
// sighash is computed over, yielding a forfeit tx the operator accepts but bitcoin rejects.
func TestVerifyAndRebuildForfeitTxsPrevoutBinding(t *testing.T) {
	t.Run("valid forfeit tx is accepted", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		valid, err := builder.VerifyAndRebuildForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.NoError(t, err)
		require.Len(t, valid, 1)
	})

	t.Run("forged witness utxo amount is refused", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		txidBefore := forfeit.UnsignedTx.TxID()
		forfeit.Inputs[0].WitnessUtxo.Value += 100_000_000
		require.Equal(t, txidBefore, forfeit.UnsignedTx.TxID(),
			"forging the prevout must not change the txid, otherwise the txid check catches it")

		_, err := builder.VerifyAndRebuildForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.ErrorContains(t, err, "invalid witness utxo for input 0")
	})

	t.Run("forged witness utxo script is refused", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		forfeit.Inputs[0].WitnessUtxo.PkScript = []byte{txscript.OP_TRUE}

		_, err := builder.VerifyAndRebuildForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.ErrorContains(t, err, "invalid witness utxo for input 0")
	})

	t.Run("missing witness utxo is refused", func(t *testing.T) {
		builder, vtxos, connectors, forfeit := newForfeitScenario(t)

		forfeit.Inputs[0].WitnessUtxo = nil

		_, err := builder.VerifyAndRebuildForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
		require.ErrorContains(t, err, "invalid witness utxo for input 0")
	})
}

func TestVerifyAndRebuildForfeitTxsDiscardsClientMetadata(t *testing.T) {
	for _, vtxoFirst := range []bool{true, false} {
		name := "vtxo first"
		if !vtxoFirst {
			name = "connector first"
		}
		t.Run(name, func(t *testing.T) {
			builder, vtxos, connectors, forfeit := newForfeitScenario(t)
			if !vtxoFirst {
				forfeit.UnsignedTx.TxIn[0], forfeit.UnsignedTx.TxIn[1] =
					forfeit.UnsignedTx.TxIn[1], forfeit.UnsignedTx.TxIn[0]
				forfeit.Inputs[0], forfeit.Inputs[1] = forfeit.Inputs[1], forfeit.Inputs[0]
			}
			want := encodeTx(t, forfeit)
			poison := []*psbt.Unknown{{Key: []byte{0xfc, 0x01}, Value: []byte("poison")}}
			root := txscript.NewBaseTapLeaf([]byte{txscript.OP_TRUE}).TapHash()
			forfeit.Unknowns = poison
			for i := range forfeit.Inputs {
				forfeit.Inputs[i].TaprootMerkleRoot = root[:]
				forfeit.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(pubkey)
				forfeit.Inputs[i].SighashType = txscript.SigHashAll
				forfeit.Inputs[i].RedeemScript = []byte{txscript.OP_TRUE}
				forfeit.Inputs[i].WitnessScript = []byte{txscript.OP_TRUE}
				forfeit.Inputs[i].Unknowns = poison
			}
			for i := range forfeit.Outputs {
				forfeit.Outputs[i].TaprootInternalKey = schnorr.SerializePubKey(pubkey)
				forfeit.Outputs[i].Unknowns = poison
			}

			valid, err := builder.VerifyAndRebuildForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
			require.NoError(t, err)
			require.Len(t, valid, 1)
			require.Equal(t, want, valid[vtxos[0].Outpoint].Tx,
				"only the VTXO signatures and spending proof should survive the rebuild")
		})
	}
}

func TestVerifyAndRebuildForfeitTxsPreservesConditionWitness(t *testing.T) {
	builder, vtxos, connectors, forfeit := newForfeitScenario(t)
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	closureScript, err := (&script.ConditionMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{key.PubKey()}},
		Condition:       []byte{txscript.OP_DROP, txscript.OP_TRUE},
	}).Script()
	require.NoError(t, err)
	setup := buildVtxoSetupFromScript(t, key, key, closureScript)
	vtxos[0].PubKey = hex.EncodeToString(setup.p2trScript[2:])
	forfeit.Inputs[0].WitnessUtxo.PkScript = setup.p2trScript
	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: setup.cbBytes,
		Script:       setup.closureScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
		makeVtxoSig(t, key, forfeit, setup.leaf),
	}
	witness := wire.TxWitness{[]byte("condition witness")}
	require.NoError(t, txutils.SetArkPsbtField(forfeit, 0, txutils.ConditionWitnessField, witness))
	forfeit.Inputs[0].Unknowns = append(forfeit.Inputs[0].Unknowns,
		&psbt.Unknown{Key: []byte{0xfc, 0x01}, Value: []byte("poison")})

	valid, err := builder.VerifyAndRebuildForfeitTxs(vtxos, connectors, []string{encodeTx(t, forfeit)})
	require.NoError(t, err)
	rebuilt, err := psbt.NewFromRawBytes(strings.NewReader(valid[vtxos[0].Outpoint].Tx), true)
	require.NoError(t, err)
	gotWitness, err := txutils.GetArkPsbtConditionWitness(rebuilt, 0)
	require.NoError(t, err)
	require.Equal(t, witness, gotWitness)
	require.Len(t, rebuilt.Inputs[0].Unknowns, 1)
	ok, _, err := builder.VerifyVtxoTapscriptSigs(valid[vtxos[0].Outpoint].Tx, false)
	require.NoError(t, err)
	require.True(t, ok)
}

// newForfeitScenario builds the minimum a forfeit tx needs to pass VerifyAndRebuildForfeitTxs: one vtxo
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
	forfeitAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(forfeitPub.SerializeCompressed()), &chaincfg.MainNetParams,
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

func TestVerifyAndRebuildForfeitTxsRejectsMalformedCltvLeaf(t *testing.T) {
	wallet.On("GetCurrentBlockTime", mock.Anything).
		Return(&ports.BlockTimestamp{Height: 100, Time: 1_700_000_000}, nil).Maybe()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	closureKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	builder := txbuilder.NewTxBuilder(
		wallet, &staticSigner{pubkey: signerKey.PubKey()}, arklib.Bitcoin,
	)

	multisig, err := (&script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{closureKey.PubKey()},
		Type:    script.MultisigTypeChecksig,
	}).Script()
	require.NoError(t, err)

	malformed := append(
		[]byte{txscript.OP_NOP, txscript.OP_CHECKLOCKTIMEVERIFY, txscript.OP_DROP},
		multisig...,
	)

	_, err = script.DecodeClosure(malformed)
	require.Error(t, err, "a leaf that re-encodes differently must not decode")

	setup := buildVtxoSetupFromScript(t, closureKey, signerKey, malformed)

	var vtxoHash chainhash.Hash
	copy(vtxoHash[:], []byte("malformed-cltv-vtxo-prevout-hash"))
	taprootKey, err := schnorr.ParsePubKey(setup.p2trScript[2:])
	require.NoError(t, err)
	vtxo := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: vtxoHash.String(), VOut: 0},
		PubKey:   hex.EncodeToString(schnorr.SerializePubKey(taprootKey)),
		Amount:   10_000,
	}

	connectorOut := wire.NewTxOut(450, setup.p2trScript)
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

	forfeitPubkeyBytes, err := hex.DecodeString(forfeitPubkey)
	require.NoError(t, err)
	forfeitPub, err := btcec.ParsePubKey(forfeitPubkeyBytes)
	require.NoError(t, err)
	forfeitAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(forfeitPub.SerializeCompressed()), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	forfeitScript, err := txscript.PayToAddrScript(forfeitAddr)
	require.NoError(t, err)

	forfeit, err := tree.BuildForfeitTx(
		[]*wire.OutPoint{
			{Hash: vtxoHash, Index: 0},
			{Hash: *connectorHash, Index: 0},
		},
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
		[]*wire.TxOut{
			{Value: int64(vtxo.Amount), PkScript: setup.p2trScript},
			connectorOut,
		},
		forfeitScript,
		0,
	)
	require.NoError(t, err)
	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: setup.cbBytes,
		Script:       setup.closureScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
		makeVtxoSig(t, closureKey, forfeit, setup.leaf),
	}

	valid, err := builder.VerifyAndRebuildForfeitTxs(
		[]domain.Vtxo{vtxo}, connectors, []string{encodeTx(t, forfeit)},
	)
	require.Error(t, err)
	require.Empty(t, valid)
}

func TestVerifyAndRebuildForfeitTxsZeroLocktimeCltvNeedsNonFinalSequence(t *testing.T) {
	wallet.On("GetCurrentBlockTime", mock.Anything).
		Return(&ports.BlockTimestamp{Height: 100, Time: 1_700_000_000}, nil).Maybe()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	closureKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	builder := txbuilder.NewTxBuilder(
		wallet, &staticSigner{pubkey: signerKey.PubKey()}, arklib.Bitcoin,
	)

	leafScript, err := (&script.CLTVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{closureKey.PubKey()},
			Type:    script.MultisigTypeChecksig,
		},
		Locktime: 0,
	}).Script()
	require.NoError(t, err)

	// the decoder reports the script faithfully, zero locktime included
	decoded, err := script.DecodeClosure(leafScript)
	require.NoError(t, err)
	cltv, ok := decoded.(*script.CLTVMultisigClosure)
	require.True(t, ok)
	require.Equal(t, arklib.AbsoluteLocktime(0), cltv.Locktime)

	setup := buildVtxoSetupFromScript(t, closureKey, signerKey, leafScript)

	var vtxoHash chainhash.Hash
	copy(vtxoHash[:], []byte("zero-locktime-cltv-vtxo-prevout1"))
	taprootKey, err := schnorr.ParsePubKey(setup.p2trScript[2:])
	require.NoError(t, err)
	vtxo := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: vtxoHash.String(), VOut: 0},
		PubKey:   hex.EncodeToString(schnorr.SerializePubKey(taprootKey)),
		Amount:   10_000,
	}

	connectorOut := wire.NewTxOut(450, setup.p2trScript)
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

	forfeitPubkeyBytes, err := hex.DecodeString(forfeitPubkey)
	require.NoError(t, err)
	forfeitPub, err := btcec.ParsePubKey(forfeitPubkeyBytes)
	require.NoError(t, err)
	forfeitAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(forfeitPub.SerializeCompressed()), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	forfeitScript, err := txscript.PayToAddrScript(forfeitAddr)
	require.NoError(t, err)

	buildWithSequence := func(seq uint32) string {
		forfeit, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{
				{Hash: vtxoHash, Index: 0},
				{Hash: *connectorHash, Index: 0},
			},
			[]uint32{seq, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{
				{Value: int64(vtxo.Amount), PkScript: setup.p2trScript},
				connectorOut,
			},
			forfeitScript,
			0,
		)
		require.NoError(t, err)
		forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: setup.cbBytes,
			Script:       setup.closureScript,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
			makeVtxoSig(t, closureKey, forfeit, setup.leaf),
		}
		return encodeTx(t, forfeit)
	}

	// a final sequence makes OP_CLTV fail, so the operator must not accept it
	_, err = builder.VerifyAndRebuildForfeitTxs(
		[]domain.Vtxo{vtxo}, connectors, []string{buildWithSequence(wire.MaxTxInSequenceNum)},
	)
	require.Error(t, err)

	valid, err := builder.VerifyAndRebuildForfeitTxs(
		[]domain.Vtxo{vtxo}, connectors, []string{buildWithSequence(wire.MaxTxInSequenceNum - 1)},
	)
	require.NoError(t, err)
	require.Len(t, valid, 1)
}
