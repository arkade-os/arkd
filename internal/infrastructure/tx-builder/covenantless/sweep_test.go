package txbuilder

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// recordingWallet captures the arguments signSweepTransaction passes to the wallet.
type recordingWallet struct {
	ports.WalletService
	gotTapscriptIndexes []int
	gotSignInput        string
	tapscriptSigned     string
	finalSigned         string
}

func (w *recordingWallet) SignTransactionTapscript(
	_ context.Context, partialTx string, inputIndexes []int,
) (string, error) {
	w.gotTapscriptIndexes = inputIndexes
	return w.tapscriptSigned, nil
}

func (w *recordingWallet) SignTransaction(
	_ context.Context, partialTx string, _ bool,
) (string, error) {
	w.gotSignInput = partialTx
	return w.finalSigned, nil
}

// TestSignSweepTransaction_DerivesTapscriptIndexes verifies that signing re-derives
// the tapscript input indexes from the psbt (the inputs carrying a TaprootLeafScript)
// rather than relying on indexes threaded through the builder API.
func TestSignSweepTransaction_DerivesTapscriptIndexes(t *testing.T) {
	op0 := &wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0}
	op1 := &wire.OutPoint{Hash: chainhash.Hash{0x02}, Index: 0}
	op2 := &wire.OutPoint{Hash: chainhash.Hash{0x03}, Index: 0}

	ptx, err := psbt.New(
		[]*wire.OutPoint{op0, op1, op2}, nil, 2, 0,
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	// a valid control block is a leaf-version/parity byte + a valid 32-byte x-only
	// internal key (here secp256k1's generator G) + an optional merkle path; psbt
	// deserialization parses and validates the internal key.
	internalKey, err := hex.DecodeString(
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	)
	require.NoError(t, err)
	controlBlock := append([]byte{byte(txscript.BaseLeafVersion)}, internalKey...)

	// only inputs 1 and 2 carry a taproot leaf script
	for _, i := range []int{1, 2} {
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: controlBlock,
			Script:       []byte{0x04, 0x05},
			LeafVersion:  txscript.BaseLeafVersion,
		}}
	}

	unsignedTx, err := ptx.B64Encode()
	require.NoError(t, err)

	w := &recordingWallet{tapscriptSigned: "tapscript-signed-psbt", finalSigned: "final-raw-tx"}

	out, err := signSweepTransaction(context.Background(), w, unsignedTx)
	require.NoError(t, err)

	require.Equal(t, "final-raw-tx", out)
	require.Equal(t, []int{1, 2}, w.gotTapscriptIndexes)
	// the tapscript-signed psbt must be the one forwarded to SignTransaction
	require.Equal(t, "tapscript-signed-psbt", w.gotSignInput)
}

// TestSignSweepTransaction_NoTapscriptInputs verifies that with no tapscript inputs,
// SignTransactionTapscript is skipped and the unsigned psbt goes straight to signing.
func TestSignSweepTransaction_NoTapscriptInputs(t *testing.T) {
	op0 := &wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0}
	ptx, err := psbt.New(
		[]*wire.OutPoint{op0}, nil, 2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	unsignedTx, err := ptx.B64Encode()
	require.NoError(t, err)

	w := &recordingWallet{tapscriptSigned: "should-not-be-used", finalSigned: "final-raw-tx"}

	out, err := signSweepTransaction(context.Background(), w, unsignedTx)
	require.NoError(t, err)

	require.Equal(t, "final-raw-tx", out)
	require.Nil(t, w.gotTapscriptIndexes)
	// with no tapscript inputs, the unsigned psbt is forwarded unchanged
	require.Equal(t, unsignedTx, w.gotSignInput)
}
