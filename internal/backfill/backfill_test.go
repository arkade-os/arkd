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
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestBackfill(t *testing.T) {
	ctx := context.Background()

	t.Run("signs unsigned forfeits", func(t *testing.T) {
		pub, xOnly := newOperator(t)
		commitment := txid(0x11)
		vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

		forfeit := buildForfeit(t, vtxoOp, pub, false)
		rounds := &fakeRounds{rounds: map[string]*domain.Round{
			commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
		}}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
		signer := &fakeSigner{operatorXOnly: xOnly}

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
	})

	t.Run("skips already signed forfeits", func(t *testing.T) {
		pub, xOnly := newOperator(t)
		commitment := txid(0x11)
		vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

		forfeit := buildForfeit(t, vtxoOp, pub, true) // already broadcast-ready
		rounds := &fakeRounds{rounds: map[string]*domain.Round{
			commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
		}}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
		signer := &fakeSigner{operatorXOnly: xOnly}

		res, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err)

		require.Equal(t, 1, res.Scanned)
		require.Equal(t, 0, res.Signed)
		require.Equal(t, 1, res.AlreadySigned)
		require.Equal(t, 0, signer.calls, "must not call signer for already-signed forfeits")
		require.Empty(t, rounds.patches)
	})

	t.Run("skips non forfeitable vtxos", func(t *testing.T) {
		_, xOnly := newOperator(t)
		commitment := txid(0x11)

		swept := forfeitableVtxo(domain.Outpoint{Txid: txid(0x01)}, commitment)
		swept.Swept = true
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
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{swept, unrolled, note, unsettled}}
		signer := &fakeSigner{operatorXOnly: xOnly}

		res, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err)

		require.Equal(t, 0, res.Scanned)
		require.Equal(t, 0, res.Signed)
		// no round lookup was even attempted: the vtxos were filtered out, not dropped
		require.Equal(t, 0, res.Failed)
		require.Equal(t, 0, signer.calls)
	})

	t.Run("is idempotent", func(t *testing.T) {
		pub, xOnly := newOperator(t)
		commitment := txid(0x11)
		vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

		forfeit := buildForfeit(t, vtxoOp, pub, false)
		rounds := &fakeRounds{rounds: map[string]*domain.Round{
			commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
		}}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
		signer := &fakeSigner{operatorXOnly: xOnly}

		first, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err)
		require.Equal(t, 1, first.Signed)

		second, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err)
		require.Equal(t, 0, second.Signed, "second run must sign nothing")
		require.Equal(t, 1, second.AlreadySigned)
		require.Equal(t, 1, signer.calls, "signer must not be called again on re-run")
	})

	t.Run("signer error counts as failed", func(t *testing.T) {
		pub, xOnly := newOperator(t)
		commitment := txid(0x11)
		vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

		forfeit := buildForfeit(t, vtxoOp, pub, false)
		rounds := &fakeRounds{rounds: map[string]*domain.Round{
			commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
		}}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
		signer := &fakeSigner{operatorXOnly: xOnly, signErr: errors.New("signer down")}

		res, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err, "a per-forfeit signer error must not abort the whole run")

		require.Equal(t, 1, res.Failed)
		require.Equal(t, 0, res.Signed)
		require.Empty(t, rounds.patches, "nothing persisted when signing failed")
	})

	t.Run("stops between rounds when the context is cancelled", func(t *testing.T) {
		pub, xOnly := newOperator(t)
		commitment := txid(0x11)
		vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

		forfeit := buildForfeit(t, vtxoOp, pub, false)
		rounds := &fakeRounds{rounds: map[string]*domain.Round{
			commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
		}}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
		signer := &fakeSigner{operatorXOnly: xOnly}

		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		res, err := backfill.Run(cancelled, vtxos, rounds, signer)

		// returns what it had rather than erroring, and signs nothing further
		require.NoError(t, err)
		require.Equal(t, 0, res.Scanned)
		require.Equal(t, 0, res.Signed)
		require.Equal(t, 0, signer.calls)
		require.Empty(t, rounds.patches)
	})

	t.Run("salvages forfeits when the batch patch fails", func(t *testing.T) {
		pub, xOnly := newOperator(t)
		commitment := txid(0x11)
		vtxoA := domain.Outpoint{Txid: txid(0xaa), VOut: 0}
		vtxoB := domain.Outpoint{Txid: txid(0xbb), VOut: 0}

		forfeitA := buildForfeit(t, vtxoA, pub, false)
		forfeitB := buildForfeit(t, vtxoB, pub, false)
		rounds := &fakeRounds{
			rounds: map[string]*domain.Round{commitment: {
				CommitmentTxid: commitment,
				ForfeitTxs:     []domain.ForfeitTx{forfeitA, forfeitB},
			}},
			// the round's batch is rejected, as one bad txid does on the SQL backends
			failBatch: true,
		}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{
			forfeitableVtxo(vtxoA, commitment), forfeitableVtxo(vtxoB, commitment),
		}}
		signer := &fakeSigner{operatorXOnly: xOnly}

		res, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err)

		// both are salvaged one by one rather than written off with the batch
		require.Equal(t, 2, res.Scanned)
		require.Equal(t, 2, res.Signed)
		require.Equal(t, 0, res.Failed)
	})

	t.Run("counts only the forfeit that failed to persist", func(t *testing.T) {
		pub, xOnly := newOperator(t)
		commitment := txid(0x11)
		vtxoA := domain.Outpoint{Txid: txid(0xaa), VOut: 0}
		vtxoB := domain.Outpoint{Txid: txid(0xbb), VOut: 0}

		forfeitA := buildForfeit(t, vtxoA, pub, false)
		forfeitB := buildForfeit(t, vtxoB, pub, false)
		// forfeitA's txid is unknown to storage, so patching it always fails. Before
		// the per-txid retry this rolled forfeitB back too and counted both failed.
		rounds := &fakeRounds{
			rounds: map[string]*domain.Round{commitment: {
				CommitmentTxid: commitment,
				ForfeitTxs:     []domain.ForfeitTx{forfeitA, forfeitB},
			}},
			failTxid: forfeitA.Txid,
		}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{
			forfeitableVtxo(vtxoA, commitment), forfeitableVtxo(vtxoB, commitment),
		}}
		signer := &fakeSigner{operatorXOnly: xOnly}

		res, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err)

		require.Equal(t, 2, res.Scanned)
		require.Equal(t, 1, res.Signed, "the healthy forfeit is still persisted")
		require.Equal(t, 1, res.Failed, "only the bad txid is counted as failed")
	})

	t.Run("skips forfeits signed with rotated away key", func(t *testing.T) {
		_, xOnly := newOperator(t)  // the operator key in use today
		oldPub, _ := newOperator(t) // the key that signed the forfeit, since rotated away
		commitment := txid(0x11)
		vtxoOp := domain.Outpoint{Txid: txid(0xaa), VOut: 0}

		// The forfeit was signed with an operator key that is no longer current and is
		// not even retained as deprecated. Its leaf still commits to that key, so the
		// forfeit is still finalizable and must be left alone rather than re-signed
		// with a key the leaf does not accept.
		forfeit := buildForfeit(t, vtxoOp, oldPub, true)
		rounds := &fakeRounds{rounds: map[string]*domain.Round{
			commitment: {CommitmentTxid: commitment, ForfeitTxs: []domain.ForfeitTx{forfeit}},
		}}
		vtxos := &fakeVtxos{vtxos: []domain.Vtxo{forfeitableVtxo(vtxoOp, commitment)}}
		signer := &fakeSigner{operatorXOnly: xOnly}

		res, err := backfill.Run(ctx, vtxos, rounds, signer)
		require.NoError(t, err)

		require.Equal(t, 1, res.Scanned)
		require.Equal(t, 0, res.Signed)
		require.Equal(t, 1, res.AlreadySigned)
		require.Equal(
			t, 0, signer.calls, "must not re-sign a forfeit signed with a rotated-away key",
		)
		require.Empty(t, rounds.patches)
	})
}

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
	// failBatch rejects any patch of more than one txid, mimicking the SQL
	// backends rolling a whole round back when one txid in the batch is bad.
	failBatch bool
	// failTxid rejects this txid however it is patched, batched or alone.
	failTxid string
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
	if _, bad := txByTxid[f.failTxid]; bad && f.failTxid != "" {
		return fmt.Errorf("forfeit tx %s not found", f.failTxid)
	}
	if f.failBatch && len(txByTxid) > 1 {
		return fmt.Errorf("batch rolled back")
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
	operatorXOnly []byte
	signErr       error
	calls         int
}

// SignTransactionTapscript mirrors the real signer: with no input indexes it adds
// the operator tapscript sig to the vtxo input and a key spend sig to the
// connector, leaving the forfeit ready to finalize.
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
		operatorSig(f.operatorXOnly, p.Inputs[0].TaprootLeafScript[0].Script),
	)
	p.Inputs[1].TaprootKeySpendSig = make([]byte, 64)
	return p.B64Encode()
}

func txid(seed byte) string {
	return strings.Repeat(fmt.Sprintf("%02x", seed), 32)
}

func operatorSig(xOnly, leaf []byte) *psbt.TaprootScriptSpendSig {
	leafHash := txscript.NewBaseTapLeaf(leaf).TapHash()
	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: xOnly,
		LeafHash:    leafHash[:],
		Signature:   make([]byte, 64),
		SigHash:     txscript.SigHashDefault,
	}
}

// buildForfeit builds a forfeit shaped like the real thing: input 0 spends the
// vtxo through a user+operator multisig leaf, input 1 spends the connector
// through the wallet key path. When signed, it carries every signature the
// finalizer needs, so it is already broadcast-ready.
func buildForfeit(
	t *testing.T, vtxoOp domain.Outpoint, operator *btcec.PublicKey, signed bool,
) domain.ForfeitTx {
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

	leaf, user := forfeitLeaf(t, operator)
	p.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBlock(t),
		Script:       leaf,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	// the user always signs its own half before submitting the forfeit
	p.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
		operatorSig(schnorr.SerializePubKey(user), leaf),
	}
	if signed {
		p.Inputs[0].TaprootScriptSpendSig = append(
			p.Inputs[0].TaprootScriptSpendSig,
			operatorSig(schnorr.SerializePubKey(operator), leaf),
		)
		p.Inputs[1].TaprootKeySpendSig = make([]byte, 64)
	}

	b64, err := p.B64Encode()
	require.NoError(t, err)
	return domain.ForfeitTx{Txid: p.UnsignedTx.TxID(), Tx: b64}
}

// controlBlock returns a well-formed single-leaf control block: the leaf version
// byte followed by a real internal key, which psbt decoding requires.
func controlBlock(t *testing.T) []byte {
	t.Helper()
	internal, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return append(
		[]byte{byte(txscript.BaseLeafVersion)}, schnorr.SerializePubKey(internal.PubKey())...,
	)
}

// forfeitLeaf returns a user+operator multisig leaf script and the user pubkey.
func forfeitLeaf(t *testing.T, operator *btcec.PublicKey) ([]byte, *btcec.PublicKey) {
	t.Helper()
	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	closure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{userKey.PubKey(), operator},
		Type:    script.MultisigTypeChecksig,
	}
	leaf, err := closure.Script()
	require.NoError(t, err)
	return leaf, userKey.PubKey()
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
