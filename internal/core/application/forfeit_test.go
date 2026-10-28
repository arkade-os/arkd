package application

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
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
		userSigned, operatorSigned := signedForfeitPsbt(t, nil)
		wantPtx, err := psbt.NewFromRawBytes(strings.NewReader(operatorSigned), true)
		require.NoError(t, err)
		wantTxid := wantPtx.UnsignedTx.TxID()

		t.Run("signs each forfeit tx via the operator signer", func(t *testing.T) {
			signer := &fakeForfeitSigner{returnTx: operatorSigned}
			s := &service{signer: signer, wallet: &fakeForfeitWallet{}}

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
			s := &service{signer: signer, wallet: &fakeForfeitWallet{}}

			got, err := s.signForfeitTxs(ctx, []string{userSigned, userSigned, userSigned})

			require.NoError(t, err)
			require.Equal(t, 3, signer.calls)
			require.Len(t, got, 3)
		})

		t.Run("returns error when the signer fails", func(t *testing.T) {
			signer := &fakeForfeitSigner{err: errors.New("signer unavailable")}
			s := &service{signer: signer, wallet: &fakeForfeitWallet{}}

			_, err := s.signForfeitTxs(ctx, []string{userSigned})

			require.Error(t, err)
		})

		t.Run("signs the connector via the wallet, scoped to it", func(t *testing.T) {
			internalKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			vtxoSigned := forfeitPsbt(t, func(p *psbt.Packet) {
				p.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
					{
						Script:      []byte{txscriptOpTrue},
						LeafVersion: txscript.BaseLeafVersion,
						ControlBlock: append(
							[]byte{byte(txscript.BaseLeafVersion)},
							schnorr.SerializePubKey(internalKey.PubKey())...,
						),
					},
				}
			})
			signer := &fakeForfeitSigner{returnTx: vtxoSigned}
			wallet := &fakeForfeitWallet{returnTx: operatorSigned}
			s := &service{signer: signer, wallet: wallet}

			got, err := s.signForfeitTxs(ctx, []string{userSigned})

			require.NoError(t, err)
			require.Equal(t, 1, wallet.calls)
			require.Equal(t, vtxoSigned, wallet.lastTx)
			require.Equal(t, []int{1}, wallet.lastIndexes, "wallet must sign the connector only")
			require.Equal(t, operatorSigned, got[0].Tx, "stored tx must carry the connector sig")
		})

		t.Run("returns error when the wallet fails", func(t *testing.T) {
			signer := &fakeForfeitSigner{returnTx: operatorSigned}
			wallet := &fakeForfeitWallet{err: errors.New("wallet locked")}
			s := &service{signer: signer, wallet: wallet}

			_, err := s.signForfeitTxs(ctx, []string{userSigned})

			require.Error(t, err)
		})

		t.Run("rejects a poisoned connector signature", func(t *testing.T) {
			root := txscript.NewBaseTapLeaf([]byte{txscript.OP_TRUE}).TapHash()
			userSigned, operatorSigned := signedForfeitPsbt(t, root[:])
			s := &service{
				signer: &fakeForfeitSigner{returnTx: operatorSigned},
				wallet: &fakeForfeitWallet{},
			}
			got, err := s.signForfeitTxs(ctx, []string{userSigned})
			require.ErrorContains(t, err, "signed forfeit tx is not ready to broadcast")
			require.Nil(t, got)
		})

		t.Run("rejects a missing connector signature", func(t *testing.T) {
			p, err := psbt.NewFromRawBytes(strings.NewReader(operatorSigned), true)
			require.NoError(t, err)
			p.Inputs[1].TaprootKeySpendSig = nil
			missingSig, err := p.B64Encode()
			require.NoError(t, err)
			s := &service{
				signer: &fakeForfeitSigner{returnTx: missingSig},
				wallet: &fakeForfeitWallet{},
			}
			got, err := s.signForfeitTxs(ctx, []string{userSigned})
			require.ErrorContains(t, err, "signed forfeit tx is not ready to broadcast")
			require.Nil(t, got)
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

	t.Run("stops queued verifications after the first failure", func(t *testing.T) {
		for _, verifyErr := range []error{nil, errors.New("verification failed")} {
			name := "invalid signature"
			if verifyErr != nil {
				name = "verification error"
			}
			t.Run(name, func(t *testing.T) {
				operatorKey, err := btcec.NewPrivateKey()
				require.NoError(t, err)
				builder := &failingForfeitBuilder{err: verifyErr}
				s := &service{
					builder: builder,
					cache: testLiveStore{settings: testSettingsStore{
						settings: &ports.Settings{SignerPubkey: operatorKey.PubKey()},
					}},
				}
				b64 := unsignedPsbt(t, 0xaa)
				forfeits := make([]string, runtime.NumCPU()*4)
				for i := range forfeits {
					forfeits[i] = b64
				}

				err = s.SubmitForfeitTxs(t.Context(), forfeits)

				require.Error(t, err)
				if verifyErr != nil {
					require.Contains(t, err.Error(), verifyErr.Error())
				} else {
					require.Contains(t, err.Error(), "invalid signature")
				}
				require.Positive(t, builder.calls.Load())
				require.LessOrEqual(t, builder.calls.Load(), int32(runtime.NumCPU()),
					"only verifications already in flight may finish after a failure")
			})
		}
	})
}

type failingForfeitBuilder struct {
	ports.TxBuilder
	err   error
	calls atomic.Int32
}

func (b *failingForfeitBuilder) VerifyVtxoTapscriptSigs(string, bool) (bool, *psbt.Packet, error) {
	b.calls.Add(1)
	return false, nil, b.err
}

const txscriptOpTrue = 0x51

// fakeForfeitSigner is a minimal ports.SignerService double: it records calls to
// SignTransaction and returns a canned signed tx (or error). Other
// SignerService methods are inherited from the embedded interface and unused.
type fakeForfeitSigner struct {
	ports.SignerService
	returnTx string
	err      error
	calls    int
	lastTx   string
}

func (f *fakeForfeitSigner) SignTransaction(
	_ context.Context, partialTx string, _ []int,
) (string, error) {
	f.calls++
	f.lastTx = partialTx
	if f.err != nil {
		return "", f.err
	}
	return f.returnTx, nil
}

// fakeForfeitWallet echoes the input tx when returnTx is empty.
type fakeForfeitWallet struct {
	ports.WalletService
	returnTx    string
	err         error
	calls       int
	lastTx      string
	lastIndexes []int
}

func (f *fakeForfeitWallet) SignTransactionTapscript(
	_ context.Context, partialTx string, inputIndexes []int,
) (string, error) {
	f.calls++
	f.lastTx = partialTx
	f.lastIndexes = inputIndexes
	if f.err != nil {
		return "", f.err
	}
	if f.returnTx == "" {
		return partialTx, nil
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

// signedForfeitPsbt returns the client and operator versions of a forfeit. The
// connector signature uses merkleRoot, allowing a poisoned wallet tweak to be
// reproduced even when the returned PSBT carries no merkle-root metadata.
// ponytail: input order is covered by the domain and builder tests.
func signedForfeitPsbt(t *testing.T, merkleRoot []byte) (string, string) {
	t.Helper()
	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	operatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	connectorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(txscript.ComputeTaprootKeyNoScript(connectorKey.PubKey()))
	require.NoError(t, err)
	leaf, err := (&script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{userKey.PubKey(), operatorKey.PubKey()},
	}).Script()
	require.NoError(t, err)
	p := forfeitPacket(t)
	p.Inputs[0].WitnessUtxo = wire.NewTxOut(1000, pkScript)
	p.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: append([]byte{byte(txscript.BaseLeafVersion)}, schnorr.SerializePubKey(userKey.PubKey())...),
		Script:       leaf,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
		spendSig(userKey.PubKey(), leaf),
	}
	p.Inputs[1].WitnessUtxo = wire.NewTxOut(330, pkScript)
	userSigned, err := p.B64Encode()
	require.NoError(t, err)
	p.Inputs[0].TaprootScriptSpendSig = append(
		p.Inputs[0].TaprootScriptSpendSig, spendSig(operatorKey.PubKey(), leaf),
	)
	prevouts, err := txutils.GetPrevOutputFetcher(p)
	require.NoError(t, err)
	p.Inputs[1].TaprootKeySpendSig, err = txscript.RawTxInTaprootSignature(
		p.UnsignedTx, txscript.NewTxSigHashes(p.UnsignedTx, prevouts), 1,
		330, pkScript, merkleRoot, txscript.SigHashDefault, connectorKey,
	)
	require.NoError(t, err)
	operatorSigned, err := p.B64Encode()
	require.NoError(t, err)
	return userSigned, operatorSigned
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
