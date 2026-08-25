package txutils_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/stretchr/testify/require"
)

type testcase struct {
	scripts         []string
	expectedTapTree string
}

// fixture extracted from BIP371. https://bips.dev/371/
var testcases = []testcase{
	{
		scripts: []string{
			"20736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02ac",
			"20631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969ac",
			"2044faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c4273ac",
		},
		expectedTapTree: "01c02220736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02ac02c02220631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969ac02c0222044faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c4273ac",
	},
}

func TestTapTree(t *testing.T) {
	for _, tc := range testcases {
		// encode
		taptree := txutils.TapTree(tc.scripts)
		raw, err := taptree.Encode()
		require.NoError(t, err)
		require.Equal(t, tc.expectedTapTree, hex.EncodeToString(raw))

		// decode
		rawBytes, err := hex.DecodeString(tc.expectedTapTree)
		require.NoError(t, err)
		decodedTapTree, err := txutils.DecodeTapTree(rawBytes)
		require.NoError(t, err)
		require.Equal(t, tc.scripts, []string(decodedTapTree))
	}
}

func TestDecodeTapTree(t *testing.T) {
	t.Run("exceeds remaining data", func(t *testing.T) {
		// depth, leaf version, len=5, only 2 bytes follow
		data := []byte{0x00, 0xc0, 0x05, 0xaa, 0xbb}
		_, err := txutils.DecodeTapTree(data)
		require.ErrorContains(t, err, "exceeds remaining data")
	})

	t.Run("exceeds max script size", func(t *testing.T) {
		var b bytes.Buffer
		b.WriteByte(0x00) // depth
		b.WriteByte(0xc0) // leaf version
		b.WriteByte(0xfd) // compact-size prefix for uint16
		_ = binary.Write(&b, binary.LittleEndian, uint16(10001))
		b.Write(bytes.Repeat([]byte{0x00}, 10001))
		_, err := txutils.DecodeTapTree(b.Bytes())
		require.ErrorContains(t, err, "exceeds max")
	})

	t.Run("exceeds max leaves", func(t *testing.T) {
		var b bytes.Buffer
		for i := 0; i <= txutils.MaxLeaves; i++ {
			b.WriteByte(0x00) // depth
			b.WriteByte(0xc0) // leaf version
			b.WriteByte(0x01) // 1-byte script
			b.WriteByte(0x00) // script
		}
		_, err := txutils.DecodeTapTree(b.Bytes())
		require.ErrorContains(t, err, fmt.Sprintf("leaves length %d exceeds max", txutils.MaxLeaves+1))
	})
}
