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
			addr, err := common.DecodeAddress(f.Addr)
			require.NoError(t, err)
			require.NotEmpty(t, addr.HRP)
			require.NotNil(t, addr.Server)
			require.NotNil(t, addr.VtxoTapKey)

			require.NoError(t, err)
			require.Equal(t, f.ExpectedUserKey, hex.EncodeToString(addr.VtxoTapKey.SerializeCompressed()))

			require.NoError(t, err)
			require.Equal(t, f.ExpectedServerKey, hex.EncodeToString(addr.Server.SerializeCompressed()))

			encoded, err := addr.Encode()
			require.NoError(t, err)
			require.Equal(t, f.Addr, encoded)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fixtures.Address.Invalid {
			addr, err := common.DecodeAddress(f.Addr)
			require.EqualError(t, err, f.ExpectedError)
			require.Nil(t, addr)
		}
	})
}
