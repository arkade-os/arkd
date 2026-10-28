package handlers_test

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-signer/interface/grpc/handlers"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

func TestSignerHandlerStatusAndPubkey(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	h := handlers.NewSignerHandler(application.New(priv, nil))

	status, err := h.GetStatus(context.Background(), &signerv1.GetStatusRequest{})
	require.NoError(t, err)
	require.True(t, status.GetReady())

	pub, err := h.GetPubkey(context.Background(), &signerv1.GetPubkeyRequest{})
	require.NoError(t, err)
	require.Equal(t,
		hex.EncodeToString(priv.PubKey().SerializeCompressed()),
		pub.GetPubkey(),
	)
}

func TestHealthHandlerServes(t *testing.T) {
	h := handlers.NewHealthHandler()
	serving := grpchealth.HealthCheckResponse_SERVING

	check, err := h.Check(context.Background(), &grpchealth.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, serving, check.GetStatus())

	list, err := h.List(context.Background(), &grpchealth.HealthListRequest{})
	require.NoError(t, err)
	require.Equal(t, serving, list.GetStatuses()["arkd-signer"].GetStatus())

	ctx, cancel := context.WithCancel(context.Background())
	stream := &fakeWatchServer{ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- h.Watch(&grpchealth.HealthCheckRequest{}, stream) }()

	require.Eventually(t, func() bool {
		return len(stream.sent()) > 0
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, serving, stream.sent()[0].GetStatus())

	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after the stream context was cancelled")
	}
}

func TestSignerHandlerSignTransaction(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	operator, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	h := handlers.NewSignerHandler(application.New(operator, nil))
	operatorXOnly := hex.EncodeToString(schnorr.SerializePubKey(operator.PubKey()))

	t.Run("input indexes select exactly one input", func(t *testing.T) {
		b64 := multiInputPacket(t, owner, operator.PubKey(), 3)

		res, err := h.SignTransaction(
			context.Background(), &signerv1.SignTransactionRequest{
				PartialTx:    b64,
				InputIndexes: []int32{1},
			},
		)
		require.NoError(t, err)

		out, err := psbt.NewFromRawBytes(strings.NewReader(res.GetSignedTx()), true)
		require.NoError(t, err)
		require.Empty(t, out.Inputs[0].TaprootScriptSpendSig, "input 0 was not requested")
		require.Len(t, out.Inputs[1].TaprootScriptSpendSig, 1)
		require.Empty(t, out.Inputs[2].TaprootScriptSpendSig, "input 2 was not requested")
		require.Equal(t,
			operatorXOnly,
			hex.EncodeToString(out.Inputs[1].TaprootScriptSpendSig[0].XOnlyPubKey),
		)
	})

	t.Run("empty index list signs every eligible input", func(t *testing.T) {
		b64 := multiInputPacket(t, owner, operator.PubKey(), 2)

		res, err := h.SignTransaction(
			context.Background(), &signerv1.SignTransactionRequest{PartialTx: b64},
		)
		require.NoError(t, err)

		out, err := psbt.NewFromRawBytes(strings.NewReader(res.GetSignedTx()), true)
		require.NoError(t, err)
		for i := range out.Inputs {
			require.Lenf(t, out.Inputs[i].TaprootScriptSpendSig, 1, "input %d", i)
		}
	})

	t.Run("out of range index is rejected", func(t *testing.T) {
		b64 := multiInputPacket(t, owner, operator.PubKey(), 2)

		for _, idx := range []int32{2, 99, -1} {
			_, err := h.SignTransaction(
				context.Background(), &signerv1.SignTransactionRequest{
					PartialTx:    b64,
					InputIndexes: []int32{idx},
				},
			)
			require.ErrorContainsf(t, err, "out of range", "index %d", idx)
		}
	})

	t.Run("anchor inputs are skipped, not signed", func(t *testing.T) {
		b64 := packetWithAnchor(t, owner, operator.PubKey())

		res, err := h.SignTransaction(
			context.Background(), &signerv1.SignTransactionRequest{PartialTx: b64},
		)
		require.NoError(t, err)

		out, err := psbt.NewFromRawBytes(strings.NewReader(res.GetSignedTx()), true)
		require.NoError(t, err)
		require.Len(t, out.Inputs[0].TaprootScriptSpendSig, 1, "the arkade input signs")
		require.Empty(t, out.Inputs[1].TaprootScriptSpendSig, "the anchor input must not sign")
	})

	t.Run("malformed psbt is rejected", func(t *testing.T) {
		_, err := h.SignTransaction(
			context.Background(),
			&signerv1.SignTransactionRequest{PartialTx: "not-a-psbt"},
		)
		require.Error(t, err)
	})
}

type fakeWatchServer struct {
	grpc.ServerStream
	ctx context.Context

	mu   sync.Mutex
	msgs []*grpchealth.HealthCheckResponse
}

func (f *fakeWatchServer) Context() context.Context { return f.ctx }

func (f *fakeWatchServer) Send(m *grpchealth.HealthCheckResponse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return nil
}

func (f *fakeWatchServer) sent() []*grpchealth.HealthCheckResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*grpchealth.HealthCheckResponse(nil), f.msgs...)
}

func multiInputPacket(
	t *testing.T, owner *btcec.PrivateKey, operator *btcec.PublicKey, n int,
) string {
	t.Helper()
	leaf, pkScript, ctrlBytes := arkadeLeaf(t, owner, operator)

	unsigned := wire.NewMsgTx(2)
	for i := range n {
		unsigned.AddTxIn(wire.NewTxIn(testOutpoint(t, uint32(i)), nil, nil))
	}
	unsigned.AddTxOut(&wire.TxOut{Value: 900, PkScript: pkScript})

	packet, err := psbt.NewFromUnsignedTx(unsigned)
	require.NoError(t, err)
	for i := range n {
		packet.Inputs[i].WitnessUtxo = &wire.TxOut{Value: 1000, PkScript: pkScript}
		packet.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: ctrlBytes,
			Script:       leaf,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
	}

	b64, err := packet.B64Encode()
	require.NoError(t, err)
	return b64
}

func packetWithAnchor(t *testing.T, owner *btcec.PrivateKey, operator *btcec.PublicKey) string {
	t.Helper()
	leaf, pkScript, ctrlBytes := arkadeLeaf(t, owner, operator)

	unsigned := wire.NewMsgTx(2)
	unsigned.AddTxIn(wire.NewTxIn(testOutpoint(t, 0), nil, nil))
	unsigned.AddTxIn(wire.NewTxIn(testOutpoint(t, 1), nil, nil))
	unsigned.AddTxOut(&wire.TxOut{Value: 900, PkScript: pkScript})

	packet, err := psbt.NewFromUnsignedTx(unsigned)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: ctrlBytes,
		Script:       leaf,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	packet.Inputs[1].WitnessUtxo = &wire.TxOut{
		Value: 240, PkScript: txutils.ANCHOR_PKSCRIPT,
	}

	b64, err := packet.B64Encode()
	require.NoError(t, err)
	return b64
}

func arkadeLeaf(
	t *testing.T, owner *btcec.PrivateKey, operator *btcec.PublicKey,
) (leaf, pkScript, ctrlBytes []byte) {
	t.Helper()
	closure := &arkscript.MultisigClosure{
		PubKeys: []*btcec.PublicKey{owner.PubKey(), operator},
		Type:    arkscript.MultisigTypeChecksig,
	}
	leaf, err := closure.Script()
	require.NoError(t, err)

	tapLeaf := txscript.NewBaseTapLeaf(leaf)
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	rootHash := tapTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(owner.PubKey(), rootHash[:])
	pkScript, err = txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(outputKey)).Script()
	require.NoError(t, err)

	ctrlBlock := tapTree.LeafMerkleProofs[0].ToControlBlock(owner.PubKey())
	ctrlBytes, err = ctrlBlock.ToBytes()
	require.NoError(t, err)
	return leaf, pkScript, ctrlBytes
}

func testOutpoint(t *testing.T, index uint32) *wire.OutPoint {
	t.Helper()
	h, err := chainhash.NewHashFromStr(
		"0000000000000000000000000000000000000000000000000000000000000001",
	)
	require.NoError(t, err)
	return &wire.OutPoint{Hash: *h, Index: index}
}
