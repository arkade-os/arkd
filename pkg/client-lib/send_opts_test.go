package arksdk

import (
	"bytes"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// anchorMarkerKey / anchorMarkerValue stamp a distinctive Unknowns entry on
// the P2A anchor's POutput so tests can verify ptx.Outputs[i] stays aligned
// with ptx.UnsignedTx.TxOut[i] across addExtension.
var (
	anchorMarkerKey   = []byte{0xaa, 0xbb}
	anchorMarkerValue = []byte{0xde, 0xad, 0xbe, 0xef}
)

func TestWithExtraPacket(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name                string
			packets             []extension.Packet
			expectErrorContains string
		}{
			{
				name: "rejects type 0x00",
				packets: []extension.Packet{
					extension.UnknownPacket{PacketType: asset.PacketType, Data: []byte{0x01}},
				},
				expectErrorContains: "reserved",
			},
			{
				name:    "rejects nil packet",
				packets: []extension.Packet{nil},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opts := newDefaultSendOptions()
				err := WithExtraPacket(tc.packets...).applySend(opts)
				require.Error(t, err)
				if tc.expectErrorContains != "" {
					require.Contains(t, err.Error(), tc.expectErrorContains)
				}
				require.Empty(t, opts.extraPackets)
			})
		}
	})

	t.Run("valid", func(t *testing.T) {
		p1 := extension.UnknownPacket{PacketType: 0x03, Data: []byte{0xde, 0xad}}
		p2 := extension.UnknownPacket{PacketType: 0x04, Data: []byte{0xbe, 0xef}}
		p1A := extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x01}}
		p2A := extension.UnknownPacket{PacketType: 0x04, Data: []byte{0x02}}

		testCases := []struct {
			name         string
			applyPackets [][]extension.Packet
			expectTypes  []uint8
		}{
			{
				name:         "appends valid packets",
				applyPackets: [][]extension.Packet{[]extension.Packet{p1, p2}},
				expectTypes:  []uint8{0x03, 0x04},
			},
			{
				name: "multiple calls accumulate",
				applyPackets: [][]extension.Packet{
					[]extension.Packet{p1A},
					[]extension.Packet{p2A},
				},
				expectTypes: []uint8{0x03, 0x04},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opts := newDefaultSendOptions()
				for _, callPackets := range tc.applyPackets {
					require.NoError(t, WithExtraPacket(callPackets...).applySend(opts))
				}
				require.Len(t, opts.extraPackets, len(tc.expectTypes))
				for i, wantType := range tc.expectTypes {
					require.Equal(t, wantType, opts.extraPackets[i].Type())
				}
			})
		}
	})
}

// TestAddExtension exercises the refactored addExtension helper. It covers
// the no-op, asset-only, asset+extra, extras-only, duplicate detection, and
// nil-packet cases, and asserts that the resulting PSBT's output layout has
// the extension TxOut immediately before the original last (P2A) output.
func TestAddExtension(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			name                  string
			includeAssetPacket    bool
			extraPkts             []extension.Packet
			expectNoOpOutputCount bool
			expectedTxOutLen      int
			checkP2AAnchor        bool
			checkParseExtension   bool
			expectedPacketType    uint8
			expectedPacketBytes   []byte
		}{
			{
				name:                  "no-op when empty",
				includeAssetPacket:    false,
				extraPkts:             nil,
				expectNoOpOutputCount: true,
			},
			{
				name:               "asset packet only inserts one output before P2A",
				includeAssetPacket: true,
				extraPkts:          nil,
				expectedTxOutLen:   2,
				checkP2AAnchor:     true,
			},
			{
				name:               "asset + extra packets produce parseable extension",
				includeAssetPacket: true,
				extraPkts: []extension.Packet{
					extension.UnknownPacket{PacketType: 0x03, Data: []byte{0xde, 0xad, 0xbe, 0xef}},
				},
				expectedTxOutLen:    2,
				checkParseExtension: true,
				expectedPacketType:  0x03,
				expectedPacketBytes: []byte{0xde, 0xad, 0xbe, 0xef},
			},
			{
				name:               "extras-only (no asset packet) works",
				includeAssetPacket: false,
				extraPkts: []extension.Packet{
					extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x01, 0x02}},
				},
				expectedTxOutLen: 2,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ptx := newTestPsbtWithP2A(t)
				beforeLen := len(ptx.UnsignedTx.TxOut)
				anchorIdxBefore := len(ptx.Outputs) - 1

				var pkt asset.Packet
				if tc.includeAssetPacket {
					pkt = newTestAssetPacket(t)
				}

				var p2aBefore *wire.TxOut
				if tc.checkP2AAnchor {
					p2aBefore = ptx.UnsignedTx.TxOut[len(ptx.UnsignedTx.TxOut)-1]
				}

				err := addExtension(ptx, pkt, tc.extraPkts)
				require.NoError(t, err)

				if tc.expectNoOpOutputCount {
					require.Equal(t, beforeLen, len(ptx.UnsignedTx.TxOut))
					require.Len(t, ptx.Outputs, beforeLen)
					require.True(t, hasAnchorMarker(ptx.Outputs[anchorIdxBefore]))
					return
				}

				require.Len(t, ptx.UnsignedTx.TxOut, tc.expectedTxOutLen)
				require.Len(t, ptx.Outputs, tc.expectedTxOutLen)
				// The anchor POutput must follow its TxOut to the new last
				// index, and the slot it vacated must be empty (for the EXT).
				require.True(t, hasAnchorMarker(ptx.Outputs[len(ptx.Outputs)-1]))
				require.False(t, hasAnchorMarker(ptx.Outputs[anchorIdxBefore]))

				if tc.checkP2AAnchor {
					// Last output must still be the original P2A anchor (same bytes).
					require.Equal(t, p2aBefore.PkScript, ptx.UnsignedTx.TxOut[1].PkScript)
					require.Equal(t, p2aBefore.Value, ptx.UnsignedTx.TxOut[1].Value)
					// New output at position [len-2] should be an OP_RETURN extension.
					require.True(t, len(ptx.UnsignedTx.TxOut[0].PkScript) > 0)
					require.Equal(t, byte(0x6a), ptx.UnsignedTx.TxOut[0].PkScript[0])
				}

				if tc.checkParseExtension {
					// Round-trip the OP_RETURN output through the extension parser to
					// confirm both packets landed in the envelope.
					extTx := wire.NewMsgTx(2)
					extTx.AddTxOut(ptx.UnsignedTx.TxOut[0])
					extTx.AddTxOut(ptx.UnsignedTx.TxOut[1])
					parsed, err := extension.NewExtensionFromTx(extTx)
					require.NoError(t, err)
					require.NotNil(t, parsed.GetAssetPacket())

					got := parsed.GetPacketByType(tc.expectedPacketType)
					require.NotNil(t, got)
					gotBytes, err := got.Serialize()
					require.NoError(t, err)
					require.Equal(t, tc.expectedPacketBytes, gotBytes)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name                string
			includeAssetPacket  bool
			extraPkts           []extension.Packet
			expectErrorContains string
		}{
			{
				name: "duplicate types rejected",
				extraPkts: []extension.Packet{
					extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x01}},
					extension.UnknownPacket{PacketType: 0x03, Data: []byte{0x02}},
				},
				expectErrorContains: "duplicate",
			},
			{
				name:                "nil extra packet rejected",
				extraPkts:           []extension.Packet{nil},
				expectErrorContains: "",
			},
			{
				name:               "asset packet type 0x00 + extra type 0x00 rejected",
				includeAssetPacket: true,
				extraPkts: []extension.Packet{
					extension.UnknownPacket{PacketType: asset.PacketType, Data: []byte{0xff}},
				},
				expectErrorContains: "duplicate",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ptx := newTestPsbtWithP2A(t)
				before := snapshotPsbt(ptx)

				var pkt asset.Packet
				if tc.includeAssetPacket {
					pkt = newTestAssetPacket(t)
				}

				err := addExtension(ptx, pkt, tc.extraPkts)
				require.Error(t, err)
				if tc.expectErrorContains != "" {
					require.Contains(t, err.Error(), tc.expectErrorContains)
				}
				assertPsbtUnchanged(t, before, ptx)
			})
		}
	})
}

func newTestPsbtWithP2A(t *testing.T) *psbt.Packet {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(wire.NewTxOut(330, []byte{0x51, 0x02, 0x4e, 0x73})) // fake p2a-ish
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Outputs[len(ptx.Outputs)-1].Unknowns = []*psbt.Unknown{
		{Key: anchorMarkerKey, Value: anchorMarkerValue},
	}
	return ptx
}

func hasAnchorMarker(po psbt.POutput) bool {
	for _, u := range po.Unknowns {
		if u != nil && bytes.Equal(u.Key, anchorMarkerKey) && bytes.Equal(u.Value, anchorMarkerValue) {
			return true
		}
	}
	return false
}

func newTestAssetPacket(t *testing.T) asset.Packet {
	t.Helper()
	out, err := asset.NewAssetOutput(0, 100)
	require.NoError(t, err)
	grp, err := asset.NewAssetGroup(nil, nil, nil, []asset.AssetOutput{*out}, nil)
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

type psbtSnapshot struct {
	txOuts          []wire.TxOut
	anchorMarkerIdx int
}

func snapshotPsbt(ptx *psbt.Packet) psbtSnapshot {
	s := psbtSnapshot{
		txOuts:          make([]wire.TxOut, 0, len(ptx.UnsignedTx.TxOut)),
		anchorMarkerIdx: -1,
	}
	for _, out := range ptx.UnsignedTx.TxOut {
		s.txOuts = append(s.txOuts, wire.TxOut{
			Value:    out.Value,
			PkScript: append([]byte(nil), out.PkScript...),
		})
	}
	for i, po := range ptx.Outputs {
		if hasAnchorMarker(po) {
			s.anchorMarkerIdx = i
			break
		}
	}
	return s
}

func assertPsbtUnchanged(t *testing.T, before psbtSnapshot, after *psbt.Packet) {
	t.Helper()
	require.Equal(t, len(before.txOuts), len(after.UnsignedTx.TxOut))
	require.Equal(t, len(before.txOuts), len(after.Outputs))
	for i := range before.txOuts {
		require.Equal(t, before.txOuts[i].Value, after.UnsignedTx.TxOut[i].Value)
		require.Equal(t, before.txOuts[i].PkScript, after.UnsignedTx.TxOut[i].PkScript)
	}
	require.GreaterOrEqual(t, before.anchorMarkerIdx, 0)
	require.True(t, hasAnchorMarker(after.Outputs[before.anchorMarkerIdx]))
}
