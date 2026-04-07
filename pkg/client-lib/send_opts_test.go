package arksdk

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// newTestPsbtWithP2A returns a minimal PSBT with a single P2A-shaped anchor
// output. The anchor's actual script content is irrelevant for these tests;
// addExtension only cares that there is at least one output and that the
// last one is treated as the P2A anchor.
func newTestPsbtWithP2A(t *testing.T) *psbt.Packet {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(wire.NewTxOut(330, []byte{0x51, 0x02, 0x4e, 0x73})) // fake p2a-ish
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	return ptx
}

// TestWithExtraCustomPacket exercises the validation rules of the new
// WithExtraCustomPacket option: rejecting nil packets, rejecting type
// 0x00 (reserved for the asset packet), and successfully appending valid
// UnknownPacket entries to the sendOptions.
func TestWithExtraCustomPacket(t *testing.T) {
	t.Run("rejects type 0x00", func(t *testing.T) {
		opts := newDefaultSendOptions()
		badPkt := extension.UnknownPacket{PacketType: asset.PacketType, Data: []byte{0x01}}
		err := WithExtraCustomPacket(badPkt)(opts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "reserved")
		require.Empty(t, opts.extraExtensionPackets)
	})

	t.Run("rejects nil packet", func(t *testing.T) {
		opts := newDefaultSendOptions()
		err := WithExtraCustomPacket(nil)(opts)
		require.Error(t, err)
		require.Empty(t, opts.extraExtensionPackets)
	})

	t.Run("appends valid packets", func(t *testing.T) {
		opts := newDefaultSendOptions()
		p1 := extension.UnknownPacket{PacketType: 0x03, Data: []byte{0xde, 0xad}}
		p2 := extension.UnknownPacket{PacketType: 0x04, Data: []byte{0xbe, 0xef}}
		err := WithExtraCustomPacket(p1, p2)(opts)
		require.NoError(t, err)
		require.Len(t, opts.extraExtensionPackets, 2)
		require.Equal(t, uint8(0x03), opts.extraExtensionPackets[0].Type())
		require.Equal(t, uint8(0x04), opts.extraExtensionPackets[1].Type())
	})

	t.Run("multiple calls accumulate", func(t *testing.T) {
		opts := newDefaultSendOptions()
		require.NoError(t, WithExtraCustomPacket(
			extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x01}},
		)(opts))
		require.NoError(t, WithExtraCustomPacket(
			extension.UnknownPacket{PacketType: 0x04, Data: []byte{0x02}},
		)(opts))
		require.Len(t, opts.extraExtensionPackets, 2)
	})
}

// TestAddExtension exercises the refactored addExtension helper. It covers
// the no-op, asset-only, asset+extra, extras-only, duplicate detection, and
// nil-packet cases, and asserts that the resulting PSBT's output layout has
// the extension TxOut immediately before the original last (P2A) output.
func TestAddExtension(t *testing.T) {
	t.Run("no-op when empty", func(t *testing.T) {
		ptx := newTestPsbtWithP2A(t)
		before := len(ptx.UnsignedTx.TxOut)
		err := addExtension(ptx, nil, nil)
		require.NoError(t, err)
		require.Equal(t, before, len(ptx.UnsignedTx.TxOut))
	})

	t.Run("asset packet only inserts one output before P2A", func(t *testing.T) {
		ptx := newTestPsbtWithP2A(t)
		p2aBefore := ptx.UnsignedTx.TxOut[len(ptx.UnsignedTx.TxOut)-1]

		// Build a minimal valid asset packet containing a single group.
		out, err := asset.NewAssetOutput(0, 100)
		require.NoError(t, err)
		grp, err := asset.NewAssetGroup(nil, nil, nil, []asset.AssetOutput{*out}, nil)
		require.NoError(t, err)
		pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
		require.NoError(t, err)

		err = addExtension(ptx, pkt, nil)
		require.NoError(t, err)

		require.Len(t, ptx.UnsignedTx.TxOut, 2)
		// Last output must still be the original P2A anchor (same bytes).
		require.Equal(t, p2aBefore.PkScript, ptx.UnsignedTx.TxOut[1].PkScript)
		require.Equal(t, p2aBefore.Value, ptx.UnsignedTx.TxOut[1].Value)
		// New output at position [len-2] should be an OP_RETURN extension.
		require.True(t, len(ptx.UnsignedTx.TxOut[0].PkScript) > 0)
		require.Equal(t, byte(0x6a), ptx.UnsignedTx.TxOut[0].PkScript[0])
	})

	t.Run("asset + extra packets produce parseable extension", func(t *testing.T) {
		ptx := newTestPsbtWithP2A(t)

		out, err := asset.NewAssetOutput(0, 100)
		require.NoError(t, err)
		grp, err := asset.NewAssetGroup(nil, nil, nil, []asset.AssetOutput{*out}, nil)
		require.NoError(t, err)
		pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
		require.NoError(t, err)

		extras := []extension.Packet{
			extension.UnknownPacket{PacketType: 0x03, Data: []byte{0xde, 0xad, 0xbe, 0xef}},
		}

		err = addExtension(ptx, pkt, extras)
		require.NoError(t, err)
		require.Len(t, ptx.UnsignedTx.TxOut, 2)

		// Round-trip the OP_RETURN output through the extension parser to
		// confirm both packets landed in the envelope.
		extTx := wire.NewMsgTx(2)
		extTx.AddTxOut(ptx.UnsignedTx.TxOut[0])
		extTx.AddTxOut(ptx.UnsignedTx.TxOut[1])
		parsed, err := extension.NewExtensionFromTx(extTx)
		require.NoError(t, err)
		require.NotNil(t, parsed.GetAssetPacket())
		got := parsed.GetPacketByType(0x03)
		require.NotNil(t, got)
		gotBytes, err := got.Serialize()
		require.NoError(t, err)
		require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, gotBytes)
	})

	t.Run("extras-only (no asset packet) works", func(t *testing.T) {
		ptx := newTestPsbtWithP2A(t)
		extras := []extension.Packet{
			extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x01, 0x02}},
		}
		err := addExtension(ptx, nil, extras)
		require.NoError(t, err)
		require.Len(t, ptx.UnsignedTx.TxOut, 2)
	})

	t.Run("duplicate types rejected", func(t *testing.T) {
		ptx := newTestPsbtWithP2A(t)
		extras := []extension.Packet{
			extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x01}},
			extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x02}},
		}
		err := addExtension(ptx, nil, extras)
		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate")
	})

	t.Run("nil extra packet rejected", func(t *testing.T) {
		ptx := newTestPsbtWithP2A(t)
		extras := []extension.Packet{nil}
		err := addExtension(ptx, nil, extras)
		require.Error(t, err)
	})

	t.Run("asset packet type 0x00 + extra type 0x00 rejected", func(t *testing.T) {
		ptx := newTestPsbtWithP2A(t)

		out, err := asset.NewAssetOutput(0, 100)
		require.NoError(t, err)
		grp, err := asset.NewAssetGroup(nil, nil, nil, []asset.AssetOutput{*out}, nil)
		require.NoError(t, err)
		pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
		require.NoError(t, err)

		// Caller should not be able to bypass the option-level check.
		extras := []extension.Packet{
			extension.UnknownPacket{PacketType: asset.PacketType, Data: []byte{0xff}},
		}
		err = addExtension(ptx, pkt, extras)
		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate")
	})
}
