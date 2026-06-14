package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

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

const txscriptOpTrue = 0x51

func TestSignForfeitTxs(t *testing.T) {
	ctx := context.Background()

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
}

func TestForfeitTxOperatorSigned(t *testing.T) {
	operatorXOnly := make([]byte, 32)
	operatorXOnly[0] = 0x07

	build := func(withOperatorSig bool) *psbt.Packet {
		var hash chainhash.Hash
		hash[0] = 0xaa
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: hash, Index: 0}, nil, nil))
		tx.AddTxOut(wire.NewTxOut(1000, []byte{txscriptOpTrue}))
		p, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		if withOperatorSig {
			p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
				XOnlyPubKey: operatorXOnly,
				LeafHash:    make([]byte, 32),
				Signature:   make([]byte, 64),
			}}
		}
		return p
	}

	require.True(t, forfeitTxOperatorSigned(build(true), operatorXOnly),
		"must detect the operator signature")
	require.False(t, forfeitTxOperatorSigned(build(false), operatorXOnly),
		"must report unsigned when the operator sig is absent")

	otherXOnly := make([]byte, 32)
	otherXOnly[0] = 0x09
	require.False(t, forfeitTxOperatorSigned(build(true), otherXOnly),
		"must not match a different pubkey")
}
