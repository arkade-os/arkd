package txutils_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/stretchr/testify/require"
)

func TestReadTxWitness(t *testing.T) {
	testCases := []struct {
		name       string
		raw        string
		wantErr    bool
		wantLen    int
		wantFirst  []byte
		checkFirst bool
	}{
		{
			name:    "valid empty witness",
			raw:     "00",
			wantLen: 0,
		},
		{
			name:       "valid one empty item",
			raw:        "0100",
			wantLen:    1,
			wantFirst:  []byte{},
			checkFirst: true,
		},
		{
			name:       "valid one item with bytes",
			raw:        "01020405",
			wantLen:    1,
			wantFirst:  []byte{0x04, 0x05},
			checkFirst: true,
		},
		{
			name:    "invalid huge count tiny payload",
			raw:     "ff0000000000000080",
			wantErr: true,
		},
		{
			name:    "invalid truncated item",
			raw:     "0102",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.raw)
			require.NoError(t, err)

			witness, err := txutils.ReadTxWitness(raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, witness, tc.wantLen)
			if tc.checkFirst {
				require.Equal(t, tc.wantFirst, witness[0])
			}
		})
	}
}
