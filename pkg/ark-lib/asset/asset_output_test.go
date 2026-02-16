package asset_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

func TestAssetOutput(t *testing.T) {
	var fixtures assetOutputFixtures
	buf, err := os.ReadFile("testdata/asset_output_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(buf, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("newOutput", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewOutput {
				t.Run(v.Name, func(t *testing.T) {
					out, err := asset.NewAssetOutput(v.Vout, v.Amount)
					require.NoError(t, err)
					require.NotNil(t, out)

					got, err := out.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.SerializedHex, out.String())

					testAsset, err := asset.NewAssetOutputFromString(v.SerializedHex)
					require.NoError(t, err)
					require.Equal(t, v.Vout, testAsset.Vout)
					require.Equal(t, v.Amount, testAsset.Amount)
					require.Equal(t, v.SerializedHex, out.String())
				})
			}
		})
		t.Run("newOutputs", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewOutputs {
				t.Run(v.Name, func(t *testing.T) {
					outs := make([]asset.AssetOutput, 0, len(v.Outputs))
					for _, vv := range v.Outputs {
						out, err := asset.NewAssetOutput(vv.Vout, vv.Amount)
						require.NoError(t, err)
						require.NotNil(t, out)
						outs = append(outs, *out)
					}
					assetOutputs, err := asset.NewAssetOutputs(outs)
					require.NoError(t, err)
					require.NotNil(t, assetOutputs)

					got, err := assetOutputs.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.SerializedHex, assetOutputs.String())

					testAssetOutputs, err := asset.NewAssetOutputsFromString(v.SerializedHex)
					require.NoError(t, err)
					require.Equal(t, assetOutputs, testAssetOutputs)
				})
			}
		})
	})
	t.Run("invalid", func(t *testing.T) {
		t.Run("from string", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewOutputFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetOutputFromString(v.SerializedHex)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("from outputs", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewOutputs {
				t.Run(v.Name, func(t *testing.T) {
					outs := make([]asset.AssetOutput, 0, len(v.Outputs))
					for _, vv := range v.Outputs {
						out, err := asset.NewAssetOutput(vv.Vout, vv.Amount)
						require.NoError(t, err)
						require.NotNil(t, out)
						outs = append(outs, *out)
					}
					got, err := asset.NewAssetOutputs(outs)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
	})
}

type assetOutputFixtures struct {
	Valid struct {
		NewOutput []struct {
			Name          string `json:"name"`
			Vout          uint16 `json:"vout"`
			Amount        uint64 `json:"amount"`
			SerializedHex string `json:"serializedHex"`
		} `json:"newOutput"`
		NewOutputs []struct {
			Name    string `json:"name"`
			Outputs []struct {
				Vout   uint16 `json:"vout"`
				Amount uint64 `json:"amount"`
			} `json:"outputs"`
			SerializedHex string `json:"serializedHex"`
		} `json:"newOutputs"`
	} `json:"valid"`
	Invalid struct {
		NewOutputFromString []struct {
			Name          string `json:"name"`
			SerializedHex string `json:"serializedHex"`
			ExpectedError string `json:"expectedError"`
		} `json:"newOutputFromString"`
		NewOutputs []struct {
			Name    string `json:"name"`
			Outputs []struct {
				Vout   uint16 `json:"vout"`
				Amount uint64 `json:"amount"`
			} `json:"outputs"`
			ExpectedError string `json:"expectedError"`
		} `json:"newOutputs"`
	} `json:"invalid"`
}
