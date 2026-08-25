package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestForfeitTxs(t *testing.T) {
	ctx := context.Background()

	t.Run("sign at collection time", func(t *testing.T) {
		// The user-signed forfeit tx submitted at collection time.
		userSigned := unsignedPsbt(t, 0xaa)
		// What the operator signer returns: a distinct, fully signed forfeit tx.
		operatorSigned := unsignedPsbt(t, 0xbb)
		wantPtx, err := psbt.NewFromRawBytes(strings.NewReader(operatorSigned), true)
		require.NoError(t, err)
		wantTxid := wantPtx.UnsignedTx.TxID()

		t.Run("signs each forfeit tx via the operator signer", func(t *testing.T) {
			signer := &fakeForfeitSigner{returnTx: operatorSigned}
			s := &service{signer: signer}

			got, err := s.signForfeitTxs(ctx, []string{userSigned})

			require.NoError(t, err)
			require.Equal(t, 1, signer.calls, "signer must be invoked once per forfeit tx")
			require.Equal(t, userSigned, signer.lastTx, "signer must receive the user-signed tx")
			require.Len(t, got, 1)
			require.Equal(t, operatorSigned, got[0].Tx, "stored tx must be the operator-signed tx")
			require.Equal(t, wantTxid, got[0].Txid, "txid must come from the signed psbt")
		})

		t.Run("signs every forfeit tx in the batch", func(t *testing.T) {
			signer := &fakeForfeitSigner{returnTx: operatorSigned}
			s := &service{signer: signer}

			got, err := s.signForfeitTxs(ctx, []string{userSigned, userSigned, userSigned})

			require.NoError(t, err)
			require.Equal(t, 3, signer.calls)
			require.Len(t, got, 3)
		})

		t.Run("returns error when the signer fails", func(t *testing.T) {
			signer := &fakeForfeitSigner{err: errors.New("signer unavailable")}
			s := &service{signer: signer}

			_, err := s.signForfeitTxs(ctx, []string{userSigned})

			require.Error(t, err)
		})
	})

	t.Run("reject submissions carrying operator signatures", func(t *testing.T) {
		operatorKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		operatorPub := operatorKey.PubKey()

		newService := func() *service {
			return &service{cache: testLiveStore{settings: testSettingsStore{
				settings: &ports.Settings{SignerPubkey: operatorPub},
			}}}
		}

		t.Run("rejects a tapscript sig planted under an operator key", func(t *testing.T) {
			// A forfeit carrying the operator's own key would make the
			// collection-time signer append a second entry for the same
			// (key, leaf) pair, producing a duplicate-key psbt that fails the
			// whole round.
			b64 := forfeitPsbt(t, func(p *psbt.Packet) {
				p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
					spendSig(operatorPub),
				}
			})

			err := newService().SubmitForfeitTxs(ctx, []string{b64})

			require.Error(t, err)
			require.Contains(t, err.Error(), "reserved to the operator")
		})

		t.Run("rejects a planted key spend sig on the connector", func(t *testing.T) {
			// The connector is a wallet output: a client cannot legitimately
			// sign it, and a planted sig makes the signer skip it, leaving the
			// forfeit unusable.
			b64 := forfeitPsbt(t, func(p *psbt.Packet) {
				p.Inputs[1].TaprootKeySpendSig = make([]byte, 64)
			})

			err := newService().SubmitForfeitTxs(ctx, []string{b64})

			require.Error(t, err)
			require.Contains(t, err.Error(), "reserved to the operator")
		})

		t.Run("rejects when no operator key is configured", func(t *testing.T) {
			// SignerPubkey is nillable. With no key to compare against, the
			// planted-signature check would match nothing and quietly wave every
			// forfeit through, so submission has to fail instead.
			s := &service{cache: testLiveStore{settings: testSettingsStore{
				settings: &ports.Settings{},
			}}}
			b64 := forfeitPsbt(t, func(p *psbt.Packet) {
				p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
					spendSig(operatorPub),
				}
			})

			require.Error(t, s.SubmitForfeitTxs(ctx, []string{b64}))
		})

		t.Run("leaves a forfeit carrying only the user signature alone", func(t *testing.T) {
			// Asserted on the guard itself: letting SubmitForfeitTxs run past it
			// would just exercise the round machinery, which is not what this
			// covers.
			userKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			p := forfeitPacket(t)
			p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
				spendSig(userKey.PubKey()),
			}

			require.False(t, domain.ForfeitTxCarriesOperatorSignature(
				p, [][]byte{schnorr.SerializePubKey(operatorPub)},
			))
		})
	})

	t.Run("broadcast readiness", func(t *testing.T) {
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
					p.Inputs[0].TaprootScriptSpendSig, spendSig(signer),
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

		t.Run("not ready when a sig comes from a key outside the leaf", func(t *testing.T) {
			// The operator's half signed by some other key does not make the
			// forfeit finalizable: the leaf only accepts its own pubkeys.
			stranger, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			require.False(t, domain.ForfeitTxReadyToBroadcast(
				build(userKey.PubKey(), stranger.PubKey()),
			))
		})
	})
}

const txscriptOpTrue = 0x51

// fakeForfeitSigner is a minimal ports.SignerService double: it records calls to
// SignTransactionTapscript and returns a canned signed tx (or error). Other
// SignerService methods are inherited from the embedded interface and unused.
type fakeForfeitSigner struct {
	ports.SignerService
	returnTx string
	err      error
	calls    int
	lastTx   string
}

func (f *fakeForfeitSigner) SignTransactionTapscript(
	_ context.Context, partialTx string, _ []int,
) (string, error) {
	f.calls++
	f.lastTx = partialTx
	if f.err != nil {
		return "", f.err
	}
	return f.returnTx, nil
}

func unsignedPsbt(t *testing.T, inputIndex byte) string {
	t.Helper()
	var hash chainhash.Hash
	hash[0] = inputIndex
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: hash, Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{txscriptOpTrue}))
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := p.B64Encode()
	require.NoError(t, err)
	return b64
}

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

func forfeitPsbt(t *testing.T, mutate func(*psbt.Packet)) string {
	t.Helper()
	p := forfeitPacket(t)
	mutate(p)
	b64, err := p.B64Encode()
	require.NoError(t, err)
	return b64
}

// spendSig is a well-formed tapscript spend sig entry under pubkey. The
// signature bytes are never verified by the code under test.
func spendSig(pubkey *btcec.PublicKey) *psbt.TaprootScriptSpendSig {
	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(pubkey),
		LeafHash:    make([]byte, 32),
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
