package extension_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/stretchr/testify/require"
)

func FuzzNewExtensionFromBytes(f *testing.F) {
	for _, s := range []string{
		"6a0d41524b00080100000101000001",   // canonical
		"6a0e41524b0088000100000101000001", // overlong packet-length prefix
		"6a4c0d41524b00080100000101000001", // non-minimal push (PUSHDATA1)
		"6a0d41524b0008010000010100000151", // trailing OP_1 after payload
	} {
		f.Add(hexSeed(s))
	}
	f.Add([]byte{})
	f.Add([]byte{0x6a})                         // OP_RETURN only
	f.Add([]byte{0x6a, 0x03, 0x41, 0x52, 0x4b}) // OP_RETURN + magic only (no packets)

	f.Fuzz(func(t *testing.T, data []byte) {
		ext, err := extension.NewExtensionFromBytes(data)
		if err != nil {
			return
		}

		// Round-trip oracle: any accepted script must re-serialize to exactly the
		// input bytes. A failure means NewExtensionFromBytes accepted a non-canonical
		// encoding that the narrow framing/packet checks failed to reject.
		reser, err := ext.Serialize()
		require.NoError(t, err)
		require.Equalf(t, data, reser,
			"non-canonical extension accepted: data=%x reser=%x", data, reser)
	})
}

func hexSeed(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
