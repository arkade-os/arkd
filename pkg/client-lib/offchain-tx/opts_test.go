package offchaintx

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/stretchr/testify/require"
)

// sampleTapTreeBytes is a BIP-371-encoded tap tree taken from the BIP-371
// test vector; used as a known-good blob across tap-tree tests.
const sampleTapTreeHex = "01c02220736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02ac"

func TestWithExtraPacket(t *testing.T) {
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
				opts := newOptions()
				for _, callPackets := range tc.applyPackets {
					require.NoError(t, WithExtraPacket(callPackets...).apply(opts))
				}
				require.Len(t, opts.extraPackets, len(tc.expectTypes))
				for i, wantType := range tc.expectTypes {
					require.Equal(t, wantType, opts.extraPackets[i].Type())
				}
			})
		}
	})

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
				opts := newOptions()
				err := WithExtraPacket(tc.packets...).apply(opts)
				require.Error(t, err)
				if tc.expectErrorContains != "" {
					require.Contains(t, err.Error(), tc.expectErrorContains)
				}
				require.Empty(t, opts.extraPackets)
			})
		}
	})
}

func TestWithTxOutsTaprootTree(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("populates state and defensively copies values", func(t *testing.T) {
			tree := sampleTapTreeBytes(t)
			caller := map[string][]byte{"abcd": tree}

			opts := newOptions()
			require.NoError(t, WithTxOutsTaprootTree(caller).apply(opts))

			stored, ok := opts.outputsTapTree["abcd"]
			require.True(t, ok)
			require.Equal(t, tree, stored)

			// mutating the caller's slice must not leak into the stored copy
			tree[0] ^= 0xff
			require.NotEqual(t, tree[0], stored[0])
		})

		t.Run("multiple calls merge keys", func(t *testing.T) {
			opts := newOptions()
			require.NoError(t, WithTxOutsTaprootTree(map[string][]byte{
				"aa": sampleTapTreeBytes(t),
			}).apply(opts))
			require.NoError(t, WithTxOutsTaprootTree(map[string][]byte{
				"bb": sampleTapTreeBytes(t),
			}).apply(opts))

			require.Len(t, opts.outputsTapTree, 2)
			require.Contains(t, opts.outputsTapTree, "aa")
			require.Contains(t, opts.outputsTapTree, "bb")
		})

		t.Run("later call overwrites same key", func(t *testing.T) {
			first := encodedTapTree(t,
				"20736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02ac",
			)
			second := encodedTapTree(t,
				"20631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969ac",
			)

			opts := newOptions()
			require.NoError(t, WithTxOutsTaprootTree(
				map[string][]byte{"aa": first},
			).apply(opts))
			require.NoError(t, WithTxOutsTaprootTree(
				map[string][]byte{"aa": second},
			).apply(opts))

			require.Equal(t, second, opts.outputsTapTree["aa"])
		})
	})

	t.Run("invalid", func(t *testing.T) {
		validTree := sampleTapTreeBytes(t)
		testCases := []struct {
			name                string
			input               map[string][]byte
			expectErrorContains string
		}{
			{
				name:                "missing trees",
				input:               map[string][]byte{},
				expectErrorContains: "missing taproot trees",
			},
			{
				name:                "empty tree",
				input:               map[string][]byte{"deadbeef": {}},
				expectErrorContains: "must not be empty",
			},
			{
				name: "malformed bip-371 tree",
				// Header advertises a 0xff-byte script but no payload follows.
				input:               map[string][]byte{"deadbeef": {0x01, 0xc0, 0xff}},
				expectErrorContains: "invalid bip-371 tap tree",
			},
			{
				name: "many trees with one invalid",
				input: map[string][]byte{
					"aa": validTree,
					"bb": {},
				},
				expectErrorContains: "must not be empty",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opts := newOptions()
				err := WithTxOutsTaprootTree(tc.input).apply(opts)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectErrorContains)
			})
		}
	})
}
