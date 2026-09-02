package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestForfeitTxs(t *testing.T) {
	ctx := t.Context()

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
					spendSig(operatorPub, []byte{txscriptOpTrue}),
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
					spendSig(operatorPub, []byte{txscriptOpTrue}),
				}
			})

			require.Error(t, s.SubmitForfeitTxs(ctx, []string{b64}))
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
