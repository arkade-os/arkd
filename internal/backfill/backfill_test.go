package backfill_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/backfill"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// --- test doubles ---

type fakeVtxos struct {
	vtxos []domain.Vtxo
	err   error
}

func (f *fakeVtxos) GetAllVtxos(_ context.Context) ([]domain.Vtxo, error) {
	return f.vtxos, f.err
}

type fakeRounds struct {
	rounds   map[string]*domain.Round
	patches  []map[string]string
	getErr   error
	patchErr error
}

func (f *fakeRounds) GetRoundWithCommitmentTxid(
	_ context.Context, txid string,
) (*domain.Round, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	r, ok := f.rounds[txid]
	if !ok {
		return nil, fmt.Errorf("round %s not found", txid)
	}
	return r, nil
}

func (f *fakeRounds) PatchForfeitTxs(_ context.Context, txByTxid map[string]string) error {
	if f.patchErr != nil {
		return f.patchErr
	}
	f.patches = append(f.patches, txByTxid)
	// Apply the patch to the stored rounds so re-runs observe signed forfeits.
	for _, r := range f.rounds {
		for i := range r.ForfeitTxs {
			if newTx, ok := txByTxid[r.ForfeitTxs[i].Txid]; ok {
				r.ForfeitTxs[i].Tx = newTx
			}
		}
	}
	return nil
}

type fakeSigner struct {
	pubkey        *btcec.PublicKey
	operatorXOnly []byte
	deprecated    []ports.DeprecatedSignerPubkey
	signErr       error
	calls         int
}

func (f *fakeSigner) GetPubkey(_ context.Context) (*btcec.PublicKey, error) {
	return f.pubkey, nil
}

func (f *fakeSigner) GetDeprecatedPubkeys(
	_ context.Context,
) ([]ports.DeprecatedSignerPubkey, error) {
	return f.deprecated, nil
}

func (f *fakeSigner) SignTransactionTapscript(
	_ context.Context, partialTx string, _ []int,
) (string, error) {
	f.calls++
	if f.signErr != nil {
		return "", f.signErr
	}
	p, err := psbt.NewFromRawBytes(strings.NewReader(partialTx), true)
	if err != nil {
		return "", err
	}
	p.Inputs[0].TaprootScriptSpendSig = append(
		p.Inputs[0].TaprootScriptSpendSig,
		operatorSig(f.operatorXOnly),
	)
	return p.B64Encode()
}

// --- helpers ---

func txid(seed byte) string {
	return strings.Repeat(fmt.Sprintf("%02x", seed), 32)
}

func operatorSig(xOnly []byte) *psbt.TaprootScriptSpendSig {
	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: xOnly,
		LeafHash:    make([]byte, 32),
		Signature:   make([]byte, 64),
		SigHash:     txscript.SigHashDefault,
	}
}

// buildForfeit builds a forfeit psbt spending vtxoOp at input 0 and a connector at
// input 1. When signed is true, it carries the operator's tapscript signature.
func buildForfeit(t *testing.T, vtxoOp domain.Outpoint, operatorXOnly []byte, signed bool) domain.ForfeitTx {
	t.Helper()
	vh, err := chainhash.NewHashFromStr(vtxoOp.Txid)
	require.NoError(t, err)
	ch, err := chainhash.NewHashFromStr(txid(0xcc))
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: *vh, Index: vtxoOp.VOut}, nil, nil))
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: *ch, Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{txscript.OP_TRUE}))

	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	if signed {
		p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{operatorSig(operatorXOnly)}
	}
	b64, err := p.B64Encode()
	require.NoError(t, err)
	return domain.ForfeitTx{Txid: p.UnsignedTx.TxID(), Tx: b64}
}

// forfeitableVtxo builds a settled vtxo that still requires a forfeit.
func forfeitableVtxo(op domain.Outpoint, commitmentTxid string) domain.Vtxo {
	return domain.Vtxo{
		Outpoint:        op,
		CommitmentTxids: []string{commitmentTxid},
		SettledBy:       commitmentTxid,
		ExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}
}

func newOperator(t *testing.T) (*btcec.PublicKey, []byte) {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key.PubKey(), schnorr.SerializePubKey(key.PubKey())
}

// --- tests ---

func TestBackfillSignsUnsignedForfeits(t *testing.T) {
	ctx := context.Background()
	pub, xOnly := newOperator(t)
	commitment := txid(0x11)
	vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

	forfeit := buildForfeit(t, vtxoOp, xOnly, false)
	rounds := &fakeRounds{rounds: map[string]*domain.Round{
		commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
	}}
	vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
	signer := &fakeSigner{pubkey: pub, operatorXOnly: xOnly}

	res, err := backfill.Run(ctx, vtxos, rounds, signer)
	require.NoError(t, err)

	require.Equal(t, 1, res.Scanned)
	require.Equal(t, 1, res.Signed)
	require.Equal(t, 0, res.AlreadySigned)
	require.Equal(t, 0, res.Failed)
	require.Equal(t, 1, signer.calls)
	require.Len(t, rounds.patches, 1)
	// the patched tx keeps the same txid and is now operator-signed
	require.Contains(t, rounds.patches[0], forfeit.Txid)
}

func TestBackfillSkipsAlreadySignedForfeits(t *testing.T) {
	ctx := context.Background()
	pub, xOnly := newOperator(t)
	commitment := txid(0x11)
	vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

	forfeit := buildForfeit(t, vtxoOp, xOnly, true) // already operator-signed
	rounds := &fakeRounds{rounds: map[string]*domain.Round{
		commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
	}}
	vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
	signer := &fakeSigner{pubkey: pub, operatorXOnly: xOnly}

	res, err := backfill.Run(ctx, vtxos, rounds, signer)
	require.NoError(t, err)

	require.Equal(t, 1, res.Scanned)
	require.Equal(t, 0, res.Signed)
	require.Equal(t, 1, res.AlreadySigned)
	require.Equal(t, 0, signer.calls, "must not call signer for already-signed forfeits")
	require.Empty(t, rounds.patches)
}

func TestBackfillSkipsNonForfeitableVtxos(t *testing.T) {
	ctx := context.Background()
	pub, xOnly := newOperator(t)
	commitment := txid(0x11)

	swept := forfeitableVtxo(domain.Outpoint{Txid: txid(0x01)}, commitment)
	swept.Swept = true
	expired := forfeitableVtxo(domain.Outpoint{Txid: txid(0x02)}, commitment)
	expired.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	unrolled := forfeitableVtxo(domain.Outpoint{Txid: txid(0x03)}, commitment)
	unrolled.Unrolled = true
	note := domain.Vtxo{ // no commitment txids -> note
		Outpoint:  domain.Outpoint{Txid: txid(0x04)},
		SettledBy: commitment,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	unsettled := domain.Vtxo{ // never settled
		Outpoint:        domain.Outpoint{Txid: txid(0x05)},
		CommitmentTxids: []string{commitment},
		ExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	rounds := &fakeRounds{rounds: map[string]*domain.Round{}}
	vtxos := &fakeVtxos{vtxos: []domain.Vtxo{swept, expired, unrolled, note, unsettled}}
	signer := &fakeSigner{pubkey: pub, operatorXOnly: xOnly}

	res, err := backfill.Run(ctx, vtxos, rounds, signer)
	require.NoError(t, err)

	require.Equal(t, 0, res.Scanned)
	require.Equal(t, 0, res.Signed)
	require.Equal(t, 0, signer.calls)
}

func TestBackfillIsIdempotent(t *testing.T) {
	ctx := context.Background()
	pub, xOnly := newOperator(t)
	commitment := txid(0x11)
	vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

	forfeit := buildForfeit(t, vtxoOp, xOnly, false)
	rounds := &fakeRounds{rounds: map[string]*domain.Round{
		commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
	}}
	vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
	signer := &fakeSigner{pubkey: pub, operatorXOnly: xOnly}

	first, err := backfill.Run(ctx, vtxos, rounds, signer)
	require.NoError(t, err)
	require.Equal(t, 1, first.Signed)

	second, err := backfill.Run(ctx, vtxos, rounds, signer)
	require.NoError(t, err)
	require.Equal(t, 0, second.Signed, "second run must sign nothing")
	require.Equal(t, 1, second.AlreadySigned)
	require.Equal(t, 1, signer.calls, "signer must not be called again on re-run")
}

func TestBackfillSignerErrorCountsAsFailed(t *testing.T) {
	ctx := context.Background()
	pub, xOnly := newOperator(t)
	commitment := txid(0x11)
	vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

	forfeit := buildForfeit(t, vtxoOp, xOnly, false)
	rounds := &fakeRounds{rounds: map[string]*domain.Round{
		commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
	}}
	vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
	signer := &fakeSigner{pubkey: pub, operatorXOnly: xOnly, signErr: errors.New("signer down")}

	res, err := backfill.Run(ctx, vtxos, rounds, signer)
	require.NoError(t, err, "a per-forfeit signer error must not abort the whole run")

	require.Equal(t, 1, res.Failed)
	require.Equal(t, 0, res.Signed)
	require.Empty(t, rounds.patches, "nothing persisted when signing failed")
}

func TestBackfillSkipsForfeitsSignedWithDeprecatedKey(t *testing.T) {
	ctx := context.Background()
	pub, xOnly := newOperator(t)       // current operator key
	depPub, depXOnly := newOperator(t) // a now-deprecated operator key
	commitment := txid(0x11)
	vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

	// The forfeit was signed with the operator key that was active before a key
	// rotation; it must be recognized as already signed, not re-signed.
	forfeit := buildForfeit(t, vtxoOp, depXOnly, true)
	rounds := &fakeRounds{rounds: map[string]*domain.Round{
		commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
	}}
	vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
	signer := &fakeSigner{
		pubkey:        pub,
		operatorXOnly: xOnly,
		deprecated:    []ports.DeprecatedSignerPubkey{{PubKey: depPub}},
	}

	res, err := backfill.Run(ctx, vtxos, rounds, signer)
	require.NoError(t, err)

	require.Equal(t, 1, res.Scanned)
	require.Equal(t, 0, res.Signed)
	require.Equal(t, 1, res.AlreadySigned)
	require.Equal(t, 0, signer.calls, "must not re-sign a forfeit signed with a deprecated key")
	require.Empty(t, rounds.patches)
}
