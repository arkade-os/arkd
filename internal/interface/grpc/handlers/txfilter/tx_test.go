package txfilter_test

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/arkade-os/arkd/internal/interface/grpc/handlers/txfilter"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/raw_txs.json
var rawTxsJSON []byte

func TestNewTx(t *testing.T) {
	fixtures := loadRawTxFixtures(t)

	t.Run("nil tx", func(t *testing.T) {
		got, err := txfilter.NewTx(nil)
		require.NoError(t, err)
		require.Empty(t, got.Extension)
	})

	t.Run("valid", func(t *testing.T) {
		for _, v := range fixtures.Valid {
			t.Run(v.Name, func(t *testing.T) {
				rawTx := parseTx(t, v.Hex)
				got, err := txfilter.NewTx(rawTx)
				require.NoError(t, err)
				require.Equal(t, v.ExpectedPackets, got.Extension)
			})
		}
	})

	t.Run("no extension swallows error", func(t *testing.T) {
		for _, v := range fixtures.NoExtension {
			t.Run(v.Name, func(t *testing.T) {
				rawTx := parseTx(t, v.Hex)
				got, err := txfilter.NewTx(rawTx)
				require.NoError(t, err)
				require.Empty(t, got.Extension)
			})
		}
	})

	t.Run("malformed extension propagates error", func(t *testing.T) {
		for _, v := range fixtures.Malformed {
			t.Run(v.Name, func(t *testing.T) {
				rawTx := parseTx(t, v.Hex)
				_, err := txfilter.NewTx(rawTx)
				require.Error(t, err)
				require.ErrorContains(t, err, v.Err)
				require.False(t, errors.Is(err, extension.ErrExtensionNotFound))
			})
		}
	})
}

func parseTx(t *testing.T, hexStr string) *wire.MsgTx {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	tx := wire.NewMsgTx(wire.TxVersion)
	require.NoError(t, tx.DeserializeNoWitness(bytes.NewReader(b)))
	return tx
}

type rawTxFixtures struct {
	Valid       []validRawTx       `json:"valid"`
	NoExtension []noExtensionRawTx `json:"noExtension"`
	Malformed   []malformedRawTx   `json:"malformed"`
}

type validRawTx struct {
	Name            string           `json:"name"`
	Hex             string           `json:"hex"`
	ExpectedPackets map[int64]string `json:"expectedPackets"`
}

type noExtensionRawTx struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
}

type malformedRawTx struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
	Err  string `json:"err"`
}

func loadRawTxFixtures(t *testing.T) *rawTxFixtures {
	t.Helper()
	var data rawTxFixtures
	require.NoError(t, json.Unmarshal(rawTxsJSON, &data))
	return &data
}
