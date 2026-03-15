package asset_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
)

func FuzzNewPacketFromBytes(f *testing.F) {
	// Valid packet serializations (from existing packet fixtures) so mutator
	// can start from structured inputs.
	addHexSeed(f, "01020200000001010000c0de810a")
	addHexSeed(f, "040602030001067469636b657204544553540001010100640602030001067469636b65720554455354320001010100ac020602030001067469636b65720554455354330001010000b4100402067469636b657205544553543304646573630d636f6e74726f6c5f6173736574000101020001")

	// Hostile / edge seeds around varint and truncation behavior.
	f.Add([]byte{})                       // empty input
	f.Add([]byte{0x00})                   // packet count = 0
	f.Add([]byte{0x01})                   // count=1, missing payload
	f.Add([]byte{0x80})                   // truncated varint
	f.Add([]byte{0xff})                   // truncated varint
	f.Add([]byte{0x01, 0x00})             // one group, presence=0, then missing ins/outs
	f.Add([]byte{0x01, 0x07})             // one group, all optional bits set, no body
	f.Add([]byte{0x01, 0x04, 0x00})       // metadata present, zero md count, then missing ins/outs
	f.Add([]byte{0x01, 0x02, 0x01, 0x00}) // controlAsset present, short payload

	// Max uint64 varint (can stress downstream make(..., count) calls).
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})

	// Overlong varint (>10 bytes) / malformed continuation.
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})
	f.Add([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := asset.NewPacketFromBytes(data)
		if err != nil {
			return
		}

		// If parsing succeeded, serialization should succeed.
		serialized, err := pkt.Serialize()
		if err != nil {
			t.Fatalf("serialize failed after successful parse: %v", err)
		}

		// Re-parsing serialized bytes should also succeed.
		pkt2, err := asset.NewPacketFromBytes(serialized)
		if err != nil {
			t.Fatalf("re-parse failed after serialize: %v", err)
		}

		// Canonical string form should be stable across parse/serialize cycles.
		if pkt.String() != pkt2.String() {
			t.Fatalf("non-stable roundtrip: pkt=%s pkt2=%s", pkt.String(), pkt2.String())
		}
	})
}

func addHexSeed(f *testing.F, s string) {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	f.Add(b)
}
