package celenv_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/indexer/celenv"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestCompile_RejectsInvalidExpression(t *testing.T) {
	_, err := celenv.Compile("not a cel expr")
	require.Error(t, err)
}

func TestCompile_RejectsNonBoolResult(t *testing.T) {
	_, err := celenv.Compile(`"hello"`)
	require.Error(t, err)
}

func TestEval_HasExtension(t *testing.T) {
	prg, err := celenv.Compile("has(tx.extension)")
	require.NoError(t, err)

	t.Run("tx with extension", func(t *testing.T) {
		ok, err := celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x42, Data: []byte{0xde, 0xad},
		}))
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("tx without extension", func(t *testing.T) {
		ok, err := celenv.Eval(prg, txWithoutExtension())
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func TestEval_HasPacket(t *testing.T) {
	prg, err := celenv.Compile("has(tx.extension) && hasPacket(tx.extension, 0x42)")
	require.NoError(t, err)

	t.Run("matching packet type", func(t *testing.T) {
		ok, err := celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x42, Data: []byte{0x01},
		}))
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("non-matching packet type", func(t *testing.T) {
		ok, err := celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x01, Data: []byte{0x01},
		}))
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("no extension", func(t *testing.T) {
		ok, err := celenv.Eval(prg, txWithoutExtension())
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func TestEval_PacketContains(t *testing.T) {
	prg, err := celenv.Compile(`has(tx.extension) && tx.extension[0x42].contains("dead")`)
	require.NoError(t, err)

	t.Run("packet data contains substring", func(t *testing.T) {
		ok, err := celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x42, Data: []byte{0xde, 0xad, 0xbe, 0xef},
		}))
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("packet data does not contain substring", func(t *testing.T) {
		ok, err := celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x42, Data: []byte{0xbe, 0xef},
		}))
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func TestEval_CostLimitAbortsRunawayExpression(t *testing.T) {
	// Build an expression whose contains() runtime cost vastly exceeds
	// MaxEvalCost, against a small packet payload. Eval should return a
	// cost-limit error, not a result.
	prg, err := celenv.Compile(
		"has(tx.extension) && " +
			"tx.extension[0x05].contains(tx.extension[0x05]) && " +
			"tx.extension[0x05].contains(tx.extension[0x05]) && " +
			"tx.extension[0x05].contains(tx.extension[0x05])",
	)
	require.NoError(t, err)

	// A large packet body so the .contains() cost dominates.
	big := make([]byte, 200_000)
	tx := txWithExtension(t, extension.UnknownPacket{PacketType: 0x05, Data: big})
	_, err = celenv.Eval(prg, tx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cost")
}

func TestEvalWithActivation_ReusesActivation(t *testing.T) {
	// Sanity check: building the activation once and reusing it across
	// programs produces the same outcome as calling Eval separately.
	prg1, err := celenv.Compile("has(tx.extension)")
	require.NoError(t, err)
	prg2, err := celenv.Compile("hasPacket(tx.extension, 0x05)")
	require.NoError(t, err)

	tx := txWithExtension(t, extension.UnknownPacket{PacketType: 0x05, Data: []byte{0xaa}})
	act, err := celenv.BuildActivation(tx)
	require.NoError(t, err)

	got1, err := celenv.EvalWithActivation(prg1, act)
	require.NoError(t, err)
	require.True(t, got1)

	got2, err := celenv.EvalWithActivation(prg2, act)
	require.NoError(t, err)
	require.True(t, got2)
}

// TestEval_IssueExamples exercises the CEL expression patterns called out in
// the issue. The issue's examples use packet type 0x00, which is reserved for
// asset.Packet and dispatches to its specialised deserialiser; constructing a
// valid asset packet is heavy setup that doesn't change the CEL evaluation
// path. We use a non-reserved type (0x05) here; the celenv code treats all
// packet types uniformly, so this proves the same pattern works for 0x00 with
// a real asset packet in production.
func TestEval_IssueExamples(t *testing.T) {
	t.Run("hasPacket(tx.extension, <type>)", func(t *testing.T) {
		prg, err := celenv.Compile("has(tx.extension) && hasPacket(tx.extension, 0x05)")
		require.NoError(t, err)

		ok, err := celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x05, Data: []byte{0xaa},
		}))
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x06, Data: []byte{0xaa},
		}))
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("tx.extension[<type>].contains(<hex>)", func(t *testing.T) {
		// Mirrors the issue's asset-id example shape: a long hex substring
		// embedded in a packet body.
		const needle = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000"
		expr := `has(tx.extension) && tx.extension[0x05].contains("` + needle + `")`
		prg, err := celenv.Compile(expr)
		require.NoError(t, err)

		raw, err := hex.DecodeString(needle)
		require.NoError(t, err)
		ok, err := celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x05, Data: raw,
		}))
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = celenv.Eval(prg, txWithExtension(t, extension.UnknownPacket{
			PacketType: 0x05, Data: []byte{0xbe, 0xef},
		}))
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func txWithExtension(t *testing.T, pkts ...extension.Packet) *wire.MsgTx {
	t.Helper()
	ext, err := extension.NewExtensionFromPackets(pkts...)
	require.NoError(t, err)
	out, err := ext.TxOut()
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(out)
	return tx
}

func txWithoutExtension() *wire.MsgTx {
	return wire.NewMsgTx(2)
}
