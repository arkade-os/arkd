package txutils_test

import (
	"encoding/hex"
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
		expectedTapTree: "01c02220736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02ac01c02220631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969ac01c0222044faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c4273ac",
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
