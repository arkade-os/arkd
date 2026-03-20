package txutils_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/stretchr/testify/require"
)

func TestReadTxWitness(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			name       string
			raw        string
			wantLen    int
			wantFirst  []byte
			checkFirst bool
		}{
			{
				name:    "empty witness",
				raw:     "00",
				wantLen: 0,
			},
			{
				name:       "one empty item",
				raw:        "0100",
				wantLen:    1,
				wantFirst:  []byte{},
				checkFirst: true,
			},
			{
				name:       "one item with bytes",
				raw:        "01020405",
				wantLen:    1,
				wantFirst:  []byte{0x04, 0x05},
				checkFirst: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				raw, err := hex.DecodeString(tc.raw)
				require.NoError(t, err)

				witness, err := txutils.ReadTxWitness(raw)
				require.NoError(t, err)
				require.Len(t, witness, tc.wantLen)
				if tc.checkFirst {
					require.Equal(t, tc.wantFirst, witness[0])
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name string
			raw  string
		}{
			{
				name: "huge count tiny payload",
				raw:  "ff0000000000000080",
			},
			{
				name: "truncated item",
				raw:  "0102",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				raw, err := hex.DecodeString(tc.raw)
				require.NoError(t, err)

				_, err = txutils.ReadTxWitness(raw)
				require.Error(t, err)
			})
		}
	})
}
