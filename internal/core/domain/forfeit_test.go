package domain_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestForfeitTxReadyToBroadcast(t *testing.T) {
	operatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	leaf := multisigLeaf(t, userKey.PubKey(), operatorKey.PubKey())

	// build returns a forfeit whose vtxo input commits to leaf and carries a
	// sig for each given signer, and whose connector input is key-spend signed.
	build := func(signers ...*btcec.PublicKey) *psbt.Packet {
		p := forfeitPacket(t)
		p.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: tapControlBlock(t),
			Script:       leaf,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		for _, signer := range signers {
			p.Inputs[0].TaprootScriptSpendSig = append(
				p.Inputs[0].TaprootScriptSpendSig, spendSig(signer, leaf),
			)
		}
		p.Inputs[1].TaprootKeySpendSig = make([]byte, 64)
		return p
	}

	t.Run("ready when every leaf pubkey has signed", func(t *testing.T) {
		require.True(t, domain.ForfeitTxReadyToBroadcast(
			build(userKey.PubKey(), operatorKey.PubKey()),
		))
	})

	t.Run("not ready with only the user signature", func(t *testing.T) {
		require.False(t, domain.ForfeitTxReadyToBroadcast(build(userKey.PubKey())))
	})

	t.Run("not ready when the connector key spend sig is missing", func(t *testing.T) {
		p := build(userKey.PubKey(), operatorKey.PubKey())
		p.Inputs[1].TaprootKeySpendSig = nil
		require.False(t, domain.ForfeitTxReadyToBroadcast(p))
	})

	t.Run("not ready when a leaf pubkey signed a different leaf", func(t *testing.T) {
		// A sig under the right key but committing to another leaf does not
		// satisfy this script, so counting it would report ready and then fail
		// at finalization.
		p := build(userKey.PubKey())
		p.Inputs[0].TaprootScriptSpendSig = append(
			p.Inputs[0].TaprootScriptSpendSig,
			spendSig(operatorKey.PubKey(), multisigLeaf(t, operatorKey.PubKey())),
		)
		require.False(t, domain.ForfeitTxReadyToBroadcast(p))
	})

	t.Run("not ready when a sig comes from a key outside the leaf", func(t *testing.T) {
		// The operator's half signed by some other key does not make the
		// forfeit finalizable: the leaf only accepts its own pubkeys.
		stranger, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		require.False(t, domain.ForfeitTxReadyToBroadcast(
			build(userKey.PubKey(), stranger.PubKey()),
		))
	})
}

func TestForfeitTxCarriesOperatorSignature(t *testing.T) {
	operatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("leaves a forfeit carrying only the user signature alone", func(t *testing.T) {
		p := forfeitPacket(t)
		p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
			spendSig(userKey.PubKey(), []byte{txscriptOpTrue}),
		}

		require.False(t, domain.ForfeitTxCarriesOperatorSignature(
			p, [][]byte{schnorr.SerializePubKey(operatorKey.PubKey())},
		))
	})
}

const txscriptOpTrue = 0x51

// forfeitPacket builds the two-input shape of a real forfeit: the vtxo at input
// 0 and the connector at input 1.
func forfeitPacket(t *testing.T) *psbt.Packet {
	t.Helper()
	var vtxoHash, connectorHash chainhash.Hash
	vtxoHash[0] = 0xaa
	connectorHash[0] = 0xcc
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: vtxoHash, Index: 0}, nil, nil))
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: connectorHash, Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{txscriptOpTrue}))
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	return p
}

// spendSig is a well-formed tapscript spend sig entry under pubkey, committing to
// leaf. The signature bytes are never verified by the code under test.
func spendSig(pubkey *btcec.PublicKey, leaf []byte) *psbt.TaprootScriptSpendSig {
	leafHash := txscript.NewBaseTapLeaf(leaf).TapHash()
	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(pubkey),
		LeafHash:    leafHash[:],
		Signature:   make([]byte, 64),
	}
}

func multisigLeaf(t *testing.T, pubkeys ...*btcec.PublicKey) []byte {
	t.Helper()
	closure := &script.MultisigClosure{
		PubKeys: pubkeys, Type: script.MultisigTypeChecksig,
	}
	leaf, err := closure.Script()
	require.NoError(t, err)
	return leaf
}

// tapControlBlock returns a well-formed single-leaf control block: the leaf
// version byte followed by a real internal key, which psbt decoding requires.
func tapControlBlock(t *testing.T) []byte {
	t.Helper()
	internal, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return append(
		[]byte{byte(txscript.BaseLeafVersion)},
		schnorr.SerializePubKey(internal.PubKey())...,
	)
}
