package asset_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

func TestAssetRef(t *testing.T) {
	var fixtures assetRefFixtures
	f, err := os.ReadFile("testdata/asset_ref_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("NewAssetRefFromId", func(t *testing.T) {
			for _, v := range fixtures.Valid.AssetRefFromId {
				t.Run(v.Name, func(t *testing.T) {
					assetId, err := asset.NewAssetId(v.Txid, v.Index)
					require.NoError(t, err)

					assetRef, err := asset.NewAssetRefFromId(*assetId)
					require.NoError(t, err)
					require.NotNil(t, assetRef)
					require.Equal(t, int(assetRef.Type), int(asset.AssetRefByID))

					got, err := assetRef.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.SerializedHex, assetRef.String())
				})
			}
		})
		t.Run("NewAssetRefFromGroupIndex", func(t *testing.T) {
			for _, v := range fixtures.Valid.AssetRefFromGroupIndex {
				t.Run(v.Name, func(t *testing.T) {
					assetRef, err := asset.NewAssetRefFromGroupIndex(uint16(v.Index))
					require.NoError(t, err)
					require.NotNil(t, assetRef)
					require.Equal(t, int(asset.AssetRefByGroup), int(assetRef.Type))

					got, err := assetRef.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.SerializedHex, assetRef.String())
				})
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("NewAssetRefFromString", func(t *testing.T) {
			for _, v := range fixtures.Invalid.AssetRefFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetRefFromString(v.SerializedHex)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
	})
}

type assetRefFixtures struct {
	Valid struct {
		AssetRefFromId []struct {
			Name          string `json:"name"`
			Txid          string `json:"txid"`
			Index         uint16 `json:"index"`
			SerializedHex string `json:"serializedHex"`
		} `json:"newAssetRefFromId"`
		AssetRefFromGroupIndex []struct {
			Name          string `json:"name"`
			Index         int    `json:"index"`
			SerializedHex string `json:"serializedHex"`
		} `json:"newAssetRefFromGroupIndex"`
	} `json:"valid"`
	Invalid struct {
		AssetRefFromString []struct {
			Name          string `json:"name"`
			SerializedHex string `json:"serializedHex"`
			ExpectedError string `json:"expectedError"`
		} `json:"newAssetRefFromString"`
	} `json:"invalid"`
}
