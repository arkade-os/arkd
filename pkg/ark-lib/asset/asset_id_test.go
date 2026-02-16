package asset_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

func TestAssetId(t *testing.T) {
	var fixtures assetIdFixtures
	buf, err := os.ReadFile("testdata/asset_id_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(buf, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, v := range fixtures.Valid {
			t.Run(v.Name, func(t *testing.T) {
				assetId, err := asset.NewAssetId(v.Txid, uint16(v.Index))
				require.NoError(t, err)
				require.NotNil(t, assetId)

				got, err := assetId.Serialize()
				require.NoError(t, err)
				require.NotEmpty(t, got)
				require.Equal(t, v.SerializedHex, assetId.String())

				testAsset, err := asset.NewAssetIdFromString(v.SerializedHex)
				require.NoError(t, err)
				require.Equal(t, v.Txid, testAsset.Txid.String())
				require.Equal(t, uint16(v.Index), testAsset.Index)
				require.Equal(t, v.SerializedHex, assetId.String())
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("NewAssetId", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewAssetId {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetId(v.Txid, uint16(v.Index))
					require.Error(t, err)
					require.Contains(t, err.Error(), v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("NewAssetIdFromString", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewAssetIdFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetIdFromString(v.SerializedHex)
					require.Error(t, err)
					require.Contains(t, err.Error(), v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
	})
}

type assetIdFixtures struct {
	Valid []struct {
		Name          string `json:"name"`
		Txid          string `json:"txid"`
		Index         int    `json:"index"`
		SerializedHex string `json:"serializedHex"`
	} `json:"valid"`
	Invalid struct {
		NewAssetId []struct {
			Name          string `json:"name"`
			Txid          string `json:"txid"`
			Index         int    `json:"index"`
			ExpectedError string `json:"expectedError"`
		} `json:"newAssetId"`
		NewAssetIdFromString []struct {
			Name          string `json:"name"`
			SerializedHex string `json:"serializedHex"`
			ExpectedError string `json:"expectedError"`
		} `json:"newAssetIdFromString"`
	} `json:"invalid"`
}
