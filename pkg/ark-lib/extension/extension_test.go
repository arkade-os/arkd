package extension_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestExtension(t *testing.T) {
	var fixtures extensionFixtures
	f, err := os.ReadFile("testdata/extension_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("NewExtensionFromBytes", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewExtensionFromBytes {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)

					ext, err := extension.NewExtensionFromBytes(data)
					require.NoError(t, err)
					require.NotNil(t, ext)
					require.Len(t, ext, v.ExpectedPacketCount)

					for i, expectedType := range v.ExpectedPacketTypes {
						require.Equal(t, expectedType, ext[i].Type())
					}
				})
			}
		})

		t.Run("roundtrip", func(t *testing.T) {
			for _, v := range fixtures.Valid.Roundtrip {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)

					ext, err := extension.NewExtensionFromBytes(data)
					require.NoError(t, err)
					require.NotNil(t, ext)

					got, err := ext.Serialize()
					require.NoError(t, err)
					require.Equal(t, v.Hex, hex.EncodeToString(got))
				})
			}
		})
	})

	t.Run("IsExtension", func(t *testing.T) {
		t.Run("true", func(t *testing.T) {
			for _, v := range fixtures.IsExtension.True {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)
					require.True(t, extension.IsExtension(data))
				})
			}
		})

		t.Run("false", func(t *testing.T) {
			for _, v := range fixtures.IsExtension.False {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)
					require.False(t, extension.IsExtension(data))
				})
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("NewExtensionFromBytes", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewExtensionFromBytes {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)

					got, err := extension.NewExtensionFromBytes(data)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
	})
}

func TestNewExtensionFromTx(t *testing.T) {
	var fixtures extensionFixtures
	f, err := os.ReadFile("testdata/extension_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	parseTx := func(t *testing.T, hexStr string) *wire.MsgTx {
		t.Helper()
		b, err := hex.DecodeString(hexStr)
		require.NoError(t, err)
		tx := wire.NewMsgTx(wire.TxVersion)
		require.NoError(t, tx.DeserializeNoWitness(bytes.NewReader(b)))
		return tx
	}

	t.Run("valid", func(t *testing.T) {
		for _, v := range fixtures.NewExtensionFromTx.Valid {
			t.Run(v.Name, func(t *testing.T) {
				tx := parseTx(t, v.Hex)
				ext, err := extension.NewExtensionFromTx(tx)
				require.NoError(t, err)
				require.Len(t, ext, v.ExpectedPacketCount)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, v := range fixtures.NewExtensionFromTx.Invalid {
			t.Run(v.Name, func(t *testing.T) {
				tx := parseTx(t, v.Hex)
				_, err := extension.NewExtensionFromTx(tx)
				require.Error(t, err)
				if v.ExpectedError == "ErrExtensionNotFound" {
					require.ErrorIs(t, err, extension.ErrExtensionNotFound)
				} else {
					require.ErrorContains(t, err, v.ExpectedError)
				}
			})
		}
	})
}

type extensionFixtures struct {
	Valid struct {
		NewExtensionFromBytes []struct {
			Name                string  `json:"name"`
			Hex                 string  `json:"hex"`
			ExpectedPacketCount int     `json:"expectedPacketCount"`
			ExpectedPacketTypes []uint8 `json:"expectedPacketTypes"`
		} `json:"newExtensionFromBytes"`
		Roundtrip []struct {
			Name string `json:"name"`
			Hex  string `json:"hex"`
		} `json:"roundtrip"`
	} `json:"valid"`
	NewExtensionFromTx struct {
		Valid []struct {
			Name                string `json:"name"`
			Hex                 string `json:"hex"`
			ExpectedPacketCount int    `json:"expectedPacketCount"`
		} `json:"valid"`
		Invalid []struct {
			Name          string `json:"name"`
			Hex           string `json:"hex"`
			ExpectedError string `json:"expectedError"`
		} `json:"invalid"`
	} `json:"newExtensionFromTx"`
	IsExtension struct {
		True []struct {
			Name string `json:"name"`
			Hex  string `json:"hex"`
		} `json:"true"`
		False []struct {
			Name string `json:"name"`
			Hex  string `json:"hex"`
		} `json:"false"`
	} `json:"isExtension"`
	Invalid struct {
		NewExtensionFromBytes []struct {
			Name          string `json:"name"`
			Hex           string `json:"hex"`
			ExpectedError string `json:"expectedError"`
		} `json:"newExtensionFromBytes"`
	} `json:"invalid"`
}
