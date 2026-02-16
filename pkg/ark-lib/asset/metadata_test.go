package asset_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

func TestMetadata(t *testing.T) {
	var fixtures metadataFixtures
	buf, err := os.ReadFile("testdata/metadata_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(buf, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("new metadata", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewMetadata {
				t.Run(v.Name, func(t *testing.T) {
					metadata, err := asset.NewMetadata(v.Key, v.Value)
					require.NoError(t, err)
					require.NotNil(t, metadata)

					got, err := metadata.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.SerializedHex, metadata.String())

					mdHash := metadata.Hash()
					require.Equal(t, v.Hash, hex.EncodeToString(mdHash[:]))

					testMetadata, err := asset.NewMetadataFromString(v.SerializedHex)
					require.NoError(t, err)
					require.Equal(t, v.Key, string(testMetadata.Key))
					require.Equal(t, v.Value, string(testMetadata.Value))
				})
			}
		})
		t.Run("hash", func(t *testing.T) {
			for _, v := range fixtures.Valid.Hash {
				t.Run(v.Name, func(t *testing.T) {
					var metadata []asset.Metadata
					for _, vv := range v.Metadata {
						md, err := asset.NewMetadata(vv.Key, vv.Value)
						require.NoError(t, err)
						require.NotNil(t, md)
						metadata = append(metadata, *md)
					}
					got, err := asset.GenerateMetadataListHash(metadata)
					require.NoError(t, err)
					require.Equal(t, v.ExpectedHash, hex.EncodeToString(got[:]))
				})
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("from key value", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewMetadataFromKeyValue {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewMetadata(v.Key, v.Value)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("from string", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewMetadataFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewMetadataFromString(v.SerializedHex)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
	})
}

type metadataFixtures struct {
	Valid struct {
		NewMetadata []struct {
			metadataValidationFixture
			Name          string `json:"name"`
			Hash          string `json:"hash"`
			SerializedHex string `json:"serializedHex"`
		} `json:"newMetadata"`
		Hash []struct {
			Name         string                      `json:"name"`
			Metadata     []metadataValidationFixture `json:"metadata"`
			ExpectedHash string                      `json:"expectedHash"`
		} `json:"hash"`
	} `json:"valid"`
	Invalid struct {
		NewMetadataFromKeyValue []struct {
			metadataValidationFixture
			Name          string `json:"name"`
			ExpectedError string `json:"expectedError"`
		} `json:"newMetadata"`
		NewMetadataFromString []struct {
			Name          string `json:"name"`
			SerializedHex string `json:"serializedHex"`
			ExpectedError string `json:"expectedError"`
		} `json:"newMetadataFromString"`
	} `json:"invalid"`
}

type metadataValidationFixture struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
