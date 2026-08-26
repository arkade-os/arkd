package txutils_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
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

func TestExtractWithAnchors(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name    string
			witness string
		}{
			{
				// A witness count of 2^32 sizes a [][]byte at ~103GB, which is a fatal
				// OOM rather than a panic the recovery interceptor could trap.
				name:    "witness count exceeds remaining bytes",
				witness: "ff0000000001000000",
			},
			{
				name:    "truncated witness item",
				witness: "0102",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				witness, err := hex.DecodeString(tc.witness)
				require.NoError(t, err)

				packet := packetWithFinalWitness(t, witness)
				_, err = txutils.ExtractWithAnchors(packet)
				require.Error(t, err)
			})
		}
	})
}

// packetWithFinalWitness builds a single-input psbt carrying witness verbatim as
// the input's FinalScriptWitness.
func packetWithFinalWitness(t *testing.T, witness []byte) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].FinalScriptWitness = witness
	return packet
}
