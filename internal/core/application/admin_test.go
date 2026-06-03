package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func (m *mockedRoundRepo) GetRoundIds(
	ctx context.Context, startedAfter, startedBefore int64, withFailed, withCompleted bool,
) ([]string, error) {
	args := m.Called(ctx, startedAfter, startedBefore, withFailed, withCompleted)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*domain.Round), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) PatchCollectedFees(
	ctx context.Context, feesByRoundId map[string]uint64,
) error {
	return m.Called(ctx, feesByRoundId).Error(0)
}

func feeIntent(in, out uint64) map[string]domain.Intent {
	return map[string]domain.Intent{
		"i": {
			Inputs:    []domain.Vtxo{{Amount: in}},
			Receivers: []domain.Receiver{{Amount: out}},
		},
	}
}

// boardingWitness builds a witness shaped like a taproot script-path spend: its
// last element is a 33-byte control block with leaf version 0xc0.
func boardingWitness() wire.TxWitness {
	return wire.TxWitness{
		make([]byte, 64), // signature
		make([]byte, 34), // leaf script
		append([]byte{0xc0}, make([]byte, 32)...), // control block
	}
}

// makeRawTx serializes a finalized (raw) tx with the given inputs to hex.
func makeRawTx(t *testing.T, ins ...*wire.TxIn) string {
	t.Helper()
	tx := wire.NewMsgTx(2)
	for _, in := range ins {
		tx.AddTxIn(in)
	}
	tx.AddTxOut(wire.NewTxOut(0, []byte{0x6a}))
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

// makePrevoutTx serializes a tx with the given output values and returns its hex
// plus its txid (a dummy input avoids the 0-input segwit decoding ambiguity).
func makePrevoutTx(t *testing.T, values ...int64) (string, chainhash.Hash) {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	for _, v := range values {
		tx.AddTxOut(wire.NewTxOut(v, []byte{0x51}))
	}
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes()), tx.TxHash()
}

func TestIsBoardingWitness(t *testing.T) {
	pubkey := append([]byte{0x02}, make([]byte, 32)...) // 33 bytes, not a control block
	controlBlock := append([]byte{0xc0}, make([]byte, 32)...)
	controlBlockParity := append([]byte{0xc1}, make([]byte, 32)...)
	controlBlockLong := append([]byte{0xc0}, make([]byte, 64)...) // 33 + 32

	tests := []struct {
		name    string
		witness wire.TxWitness
		want    bool
	}{
		{"script-path with sig", wire.TxWitness{[]byte("sig"), []byte("script"), controlBlock}, true},
		{"script-path minimal", wire.TxWitness{[]byte("script"), controlBlock}, true},
		{"script-path parity bit", wire.TxWitness{[]byte("script"), controlBlockParity}, true},
		{"script-path long control block", wire.TxWitness{[]byte("script"), controlBlockLong}, true},
		{"key-path single element", wire.TxWitness{make([]byte, 64)}, false},
		{"p2wpkh", wire.TxWitness{make([]byte, 72), pubkey}, false},
		{"empty witness", wire.TxWitness{}, false},
		{"bad control block length", wire.TxWitness{[]byte("script"), make([]byte, 34)}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isBoardingWitness(tc.witness))
		})
	}
}

func TestAdminGetCollectedFees(t *testing.T) {
	ctx := t.Context()

	// A finalized commitment tx with a single non-boarding input: recomputation
	// yields zero boarding amount and is "complete".
	noBoardingTx := makeRawTx(t, &wire.TxIn{})

	rounds := []*domain.Round{
		// new round, fee persisted -> use stored value.
		{
			Id:            "new-positive",
			CollectedFees: 5000,
		},
		// round with a genuine zero fee -> NOT patched (stays 0)
		{
			Id:            "zero-fee-unpatched",
			CollectedFees: 0,
			CommitmentTx:  noBoardingTx,
			Intents:       feeIntent(10000, 10000),
		},
		// old round, zero (unpersisted) fee -> recomputed from intents: 200.
		{
			Id:            "zero-fee-patched",
			CollectedFees: 0,
			CommitmentTx:  noBoardingTx,
			Intents:       feeIntent(10000, 9800),
		},
	}

	repo := &mockedRoundRepo{}
	ids := make([]string, len(rounds))
	for i, r := range rounds {
		ids[i] = r.Id
		repo.On("GetRoundWithId", mock.Anything, r.Id).Return(r, nil)
	}
	repo.On("GetRoundIds", mock.Anything, int64(0), int64(0), false, true).Return(ids, nil)

	// Only the old, recomputed, non-zero round is lazily patched. The patch
	// happens in a goroutine, so signal the test when it lands.
	patched := make(chan map[string]uint64, 1)
	repo.On("PatchCollectedFees", mock.Anything, mock.Anything).
		Return(nil).
		Run(func(args mock.Arguments) {
			patched <- args.Get(1).(map[string]uint64)
		})

	rm := &mockedRepoManager{}
	rm.On("Rounds").Return(repo)

	svc := &adminService{repoManager: rm, walletSvc: &mockedWallet{}}
	total, err := svc.GetCollectedFees(ctx, 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(5000+0+200), total)

	select {
	case got := <-patched:
		require.Equal(t, map[string]uint64{"zero-fee-patched": 200}, got)
	case <-time.After(2 * time.Second):
		t.Fatal("expected PatchCollectedFees to be called for the recomputed round")
	}

	repo.AssertExpectations(t)
}

func TestAdminGetCollectedFeesNoPatchWhenNotNeeded(t *testing.T) {
	ctx := t.Context()

	noBoardingTx := makeRawTx(t, &wire.TxIn{})

	// One round with a persisted fee and one with a genuine zero fee (inputs ==
	// outputs): nothing to recompute to a non-zero value, so no patch is queued.
	rounds := []*domain.Round{
		{Id: "stored", CollectedFees: 3000},
		{
			Id:            "genuine-zero",
			CollectedFees: 0,
			CommitmentTx:  noBoardingTx,
			Intents:       feeIntent(10000, 10000),
		},
	}

	repo := &mockedRoundRepo{}
	ids := make([]string, len(rounds))
	for i, r := range rounds {
		ids[i] = r.Id
		repo.On("GetRoundWithId", mock.Anything, r.Id).Return(r, nil)
	}
	repo.On("GetRoundIds", mock.Anything, int64(0), int64(0), false, true).Return(ids, nil)

	rm := &mockedRepoManager{}
	rm.On("Rounds").Return(repo)

	svc := &adminService{repoManager: rm, walletSvc: &mockedWallet{}}
	total, err := svc.GetCollectedFees(ctx, 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(3000), total)

	// The patch is gated on a non-empty batch, so no goroutine is ever spawned.
	repo.AssertNotCalled(t, "PatchCollectedFees", mock.Anything, mock.Anything)
}

func TestRecomputeCollectedFeesWithBoarding(t *testing.T) {
	ctx := t.Context()

	// Boarding input prevout worth 100_000 sats at vout 0.
	prevTxHex, prevTxid := makePrevoutTx(t, 100000)

	// Commitment tx: one boarding input (taproot script path) spending that
	// prevout, plus one non-boarding (server liquidity) input.
	commitmentTx := makeRawTx(t,
		&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prevTxid, Index: 0},
			Witness:          boardingWitness(),
		},
		&wire.TxIn{Witness: wire.TxWitness{make([]byte, 64)}}, // key-path, ignored
	)

	// Alice boarded 100_000 and received a 99_000 vtxo (no vtxo inputs of her own).
	// fee = boarding(100_000) + intentIn(0) - intentOut(99_000) = 1_000.
	round := &domain.Round{
		Id:           "old-boarding",
		CommitmentTx: commitmentTx,
		Intents: map[string]domain.Intent{
			"alice": {Receivers: []domain.Receiver{{Amount: 99000}}},
		},
	}

	wallet := &mockedWallet{}
	wallet.On("GetTransaction", mock.Anything, prevTxid.String()).Return(prevTxHex, nil)

	svc := &adminService{walletSvc: wallet}
	fees, complete := svc.recomputeCollectedFees(ctx, round)
	require.True(t, complete)
	require.Equal(t, uint64(1000), fees)
	wallet.AssertExpectations(t)
}
