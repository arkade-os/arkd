package asset_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

func TestAssetInput(t *testing.T) {
	var fixtures assetInputFixtures
	buf, err := os.ReadFile("testdata/asset_input_fixtures.json")
	require.NoError(t, err)
	err = json.Unmarshal(buf, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("NewInput", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewInput {
				t.Run(v.Name, func(t *testing.T) {
					in, err := asset.NewAssetInput(v.Vin, v.Amount)
					if v.Type == asset.AssetInputTypeIntent.String() {
						in, err = asset.NewIntentAssetInput(v.Txid, v.Vin, v.Amount)
					}
					require.NoError(t, err)
					require.NotNil(t, in)

					got, err := in.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.SerializedHex, in.String())

					testAsset, err := asset.NewAssetInputFromString(v.SerializedHex)
					require.NoError(t, err)
					require.Equal(t, v.Vin, testAsset.Vin)
					require.Equal(t, v.Amount, testAsset.Amount)
					require.Equal(t, v.SerializedHex, in.String())
				})
			}
		})
		t.Run("NewInputs", func(t *testing.T) {
			for _, v := range fixtures.Valid.NewInputs {
				t.Run(v.Name, func(t *testing.T) {
					ins := make([]asset.AssetInput, 0, len(v.Inputs))
					for _, vv := range v.Inputs {
						in, err := asset.NewAssetInput(vv.Vin, vv.Amount)
						if vv.Type == asset.AssetInputTypeIntent.String() {
							in, err = asset.NewIntentAssetInput(vv.Txid, vv.Vin, vv.Amount)
						}
						require.NoError(t, err)
						require.NotNil(t, in)
						ins = append(ins, *in)
					}
					assetInputs, err := asset.NewAssetInputs(ins)
					require.NoError(t, err)
					require.NotNil(t, assetInputs)

					got, err := assetInputs.Serialize()
					require.NoError(t, err)
					require.NotEmpty(t, got)
					require.Equal(t, v.SerializedHex, assetInputs.String())

					testAssetInputs, err := asset.NewAssetInputsFromString(v.SerializedHex)
					require.NoError(t, err)
					require.Equal(t, assetInputs, testAssetInputs)
				})
			}
		})
	})
	t.Run("invalid", func(t *testing.T) {
		t.Run("NewInput", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewInput {
				t.Run(v.Name, func(t *testing.T) {
					_, err := asset.NewIntentAssetInput(v.Txid, uint16(v.Vin), 0)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
				})
			}
		})
		t.Run("NewInputFromString", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewInputFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetInputFromString(v.SerializedHex)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("NewInputs", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewInputs {
				t.Run(v.Name, func(t *testing.T) {
					ins := make([]asset.AssetInput, 0, len(v.Inputs))
					for _, vv := range v.Inputs {
						ins = append(ins, vv.parse())
					}
					got, err := asset.NewAssetInputs(ins)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("NewInputsFromString", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewInputsFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetInputsFromString(v.SerializedHex)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
	})
}

type assetInputFixtures struct {
	Valid struct {
		NewInput []struct {
			assetInputValidationFixture
			Name          string `json:"name"`
			SerializedHex string `json:"serializedHex"`
		} `json:"newInput"`
		NewInputs []struct {
			Name          string                        `json:"name"`
			Inputs        []assetInputValidationFixture `json:"inputs"`
			SerializedHex string                        `json:"serializedHex"`
		} `json:"newInputs"`
	} `json:"valid"`
	Invalid struct {
		NewInput []struct {
			assetInputValidationFixture
			Name          string `json:"name"`
			ExpectedError string `json:"expectedError"`
		} `json:"newInput"`
		NewInputFromString []struct {
			Name          string `json:"name"`
			SerializedHex string `json:"serializedHex"`
			ExpectedError string `json:"expectedError"`
		} `json:"newInputFromString"`
		NewInputs []struct {
			Name          string                        `json:"name"`
			Inputs        []assetInputValidationFixture `json:"inputs"`
			ExpectedError string                        `json:"expectedError"`
		} `json:"newInputs"`
		NewInputsFromString []struct {
			Name          string `json:"name"`
			SerializedHex string `json:"serializedHex"`
			ExpectedError string `json:"expectedError"`
		} `json:"newInputsFromString"`
	} `json:"invalid"`
}

type assetInputValidationFixture struct {
	Type   string `json:"type"`
	Vin    uint16 `json:"vin"`
	Amount uint64 `json:"amount"`
	Txid   string `json:"txid"`
}

func (v assetInputValidationFixture) parse() asset.AssetInput {
	if v.Type == asset.AssetInputTypeLocal.String() {
		in, _ := asset.NewAssetInput(v.Vin, v.Amount)
		return *in
	}
	in, _ := asset.NewIntentAssetInput(v.Txid, v.Vin, v.Amount)
	return *in
}
