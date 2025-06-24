package common_test

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"testing"

	common "github.com/ark-network/ark/common"
	"github.com/stretchr/testify/require"
)

var f []byte

func init() {
	var err error
	f, err = os.ReadFile("fixtures/encoding.json")
	if err != nil {
		log.Fatal(err)
	}
}

func TestAddressEncoding(t *testing.T) {
	fixtures := struct {
		Address struct {
			Valid []struct {
				Addr              string `json:"addr"`
				ExpectedVersion   uint8  `json:"expectedVersion"`
				ExpectedPrefix    string `json:"expectedPrefix"`
				ExpectedUserKey   string `json:"expectedUserKey"`
				ExpectedServerKey string `json:"expectedServerKey"`
			} `json:"valid"`
			Invalid []struct {
				Addr          string `json:"addr"`
				ExpectedError string `json:"expectedError"`
			} `json:"invalid"`
		} `json:"address"`
	}{}
	err := json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fixtures.Address.Valid {
			addr, err := common.DecodeAddressV0(f.Addr)
			require.NoError(t, err)
			require.NotNil(t, addr)
			require.Equal(t, f.ExpectedVersion, addr.Version)
			require.Equal(t, f.ExpectedPrefix, addr.HRP)
			require.Equal(t, f.ExpectedUserKey, hex.EncodeToString(addr.VtxoTapKey.SerializeCompressed()))
			require.Equal(t, f.ExpectedServerKey, hex.EncodeToString(addr.Server.SerializeCompressed()))

			encoded, err := addr.EncodeV0()
			require.NoError(t, err)
			require.Equal(t, f.Addr, encoded)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fixtures.Address.Invalid {
			t.Run(f.ExpectedError, func(t *testing.T) {
				addr, err := common.DecodeAddressV0(f.Addr)
				require.Contains(t, err.Error(), f.ExpectedError)
				require.Nil(t, addr)
			})
		}
	})
}
