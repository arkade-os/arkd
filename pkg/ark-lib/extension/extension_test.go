package extension_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
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
					require.True(t, extension.IsExtension(got))

					txout, err := ext.TxOut()
					require.NoError(t, err)
					require.NotNil(t, txout)
					require.Equal(t, got, txout.PkScript)
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

		t.Run("Serialize", func(t *testing.T) {
			for _, v := range fixtures.Invalid.Serialize {
				t.Run(v.Name, func(t *testing.T) {
					ext := make(extension.Extension, v.PacketCount)

					got, err := ext.Serialize()
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)

					txout, err := ext.TxOut()
					require.Error(t, err)
					require.Nil(t, txout)
				})
			}
		})
	})

	t.Run("GetAssetPacket", func(t *testing.T) {
		t.Run("found", func(t *testing.T) {
			for _, v := range fixtures.GetAssetPacket.Found {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)

					ext, err := extension.NewExtensionFromBytes(data)
					require.NoError(t, err)

					ap := ext.GetAssetPacket()
					require.NotNil(t, ap)
					require.Equal(t, asset.PacketType, ap.Type())

					got, err := ap.Serialize()
					require.NoError(t, err)
					require.Equal(t, v.ExpectedAssetPacketHex, hex.EncodeToString(got))
				})
			}
		})

		t.Run("not found", func(t *testing.T) {
			for _, v := range fixtures.GetAssetPacket.NotFound {
				t.Run(v.Name, func(t *testing.T) {
					if v.Hex == "" {
						var ext extension.Extension
						require.Nil(t, ext.GetAssetPacket())
						return
					}

					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)

					ext, err := extension.NewExtensionFromBytes(data)
					require.NoError(t, err)

					require.Nil(t, ext.GetAssetPacket())
				})
			}
		})
	})

	t.Run("GetPacketByType", func(t *testing.T) {
		t.Run("found", func(t *testing.T) {
			for _, v := range fixtures.GetPacketByType.Found {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)

					ext, err := extension.NewExtensionFromBytes(data)
					require.NoError(t, err)

					p := ext.GetPacketByType(v.QueryType)
					require.NotNil(t, p)
					require.Equal(t, v.QueryType, p.Type())

					got, err := p.Serialize()
					require.NoError(t, err)
					require.Equal(t, v.ExpectedPacketHex, hex.EncodeToString(got))
				})
			}
		})

		t.Run("not found", func(t *testing.T) {
			for _, v := range fixtures.GetPacketByType.NotFound {
				t.Run(v.Name, func(t *testing.T) {
					data, err := hex.DecodeString(v.Hex)
					require.NoError(t, err)

					ext, err := extension.NewExtensionFromBytes(data)
					require.NoError(t, err)

					require.Nil(t, ext.GetPacketByType(v.QueryType))
				})
			}
		})

		t.Run("nil extension does not panic", func(t *testing.T) {
			require.Nil(t, extension.Extension(nil).GetPacketByType(0x00))
			require.Nil(t, extension.Extension(nil).GetPacketByType(0x03))
			require.Nil(t, extension.Extension(nil).GetPacketByType(0xff))
		})

		t.Run("empty extension does not panic", func(t *testing.T) {
			ext := extension.Extension{}
			require.Nil(t, ext.GetPacketByType(0x00))
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
		Serialize []struct {
			Name          string `json:"name"`
			PacketCount   int    `json:"packetCount"`
			ExpectedError string `json:"expectedError"`
		} `json:"serialize"`
	} `json:"invalid"`
	GetAssetPacket struct {
		Found []struct {
			Name                  string `json:"name"`
			Hex                   string `json:"hex"`
			ExpectedAssetPacketHex string `json:"expectedAssetPacketHex"`
		} `json:"found"`
		NotFound []struct {
			Name string `json:"name"`
			Hex  string `json:"hex"`
		} `json:"notFound"`
	} `json:"getAssetPacket"`
	GetPacketByType struct {
		Found []struct {
			Name              string `json:"name"`
			Hex               string `json:"hex"`
			QueryType         uint8  `json:"queryType"`
			ExpectedPacketHex string `json:"expectedPacketHex"`
		} `json:"found"`
		NotFound []struct {
			Name      string `json:"name"`
			Hex       string `json:"hex"`
			QueryType uint8  `json:"queryType"`
		} `json:"notFound"`
	} `json:"getPacketByType"`
}
