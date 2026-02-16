package asset_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

func TestAssetGroup(t *testing.T) {
	var fixtures assetGroupFixturesJSON
	buf, err := os.ReadFile("testdata/asset_group_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf, &fixtures); err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		for _, v := range fixtures.Valid {
			t.Run(v.Name, func(t *testing.T) {
				assetId, controlAsset, ins, outs, md := v.parse()
				assetGroup, err := asset.NewAssetGroup(assetId, controlAsset, ins, outs, md)
				require.NoError(t, err)
				require.NotNil(t, assetGroup)

				got, err := assetGroup.Serialize()
				require.NoError(t, err)
				require.NotEmpty(t, got)
				require.Equal(t, v.SerializedHex, assetGroup.String())

				assetGroup, err = asset.NewAssetGroupFromString(v.SerializedHex)
				require.NoError(t, err)
				if assetId != nil {
					require.Equal(t, assetId.String(), assetGroup.AssetId.String())
				} else {
					require.Nil(t, assetGroup.AssetId)
				}
				if controlAsset != nil {
					require.Equal(t, controlAsset.String(), assetGroup.ControlAsset.String())
				} else {
					require.Nil(t, assetGroup.ControlAsset)
				}
				require.Equal(t, ins, assetGroup.Inputs)
				require.Equal(t, outs, assetGroup.Outputs)
				require.Equal(t, md, assetGroup.Metadata)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("NewAssetGroup", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewAssetGroup {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetGroup(v.parse())
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
		t.Run("NewAssetGroupFromString", func(t *testing.T) {
			for _, v := range fixtures.Invalid.NewAssetGroupFromString {
				t.Run(v.Name, func(t *testing.T) {
					got, err := asset.NewAssetGroupFromString(v.SerializedHex)
					require.Error(t, err)
					require.ErrorContains(t, err, v.ExpectedError)
					require.Nil(t, got)
				})
			}
		})
	})
}

type assetGroupFixturesJSON struct {
	Valid []struct {
		assetGroupValidationFixture
		Name          string `json:"name"`
		SerializedHex string `json:"serializedHex"`
	} `json:"valid"`
	Invalid struct {
		NewAssetGroup []struct {
			assetGroupValidationFixture
			Name          string `json:"name"`
			ExpectedError string `json:"expectedError"`
		} `json:"newAssetGroup"`
		NewAssetGroupFromString []struct {
			Name          string `json:"name"`
			ExpectedError string `json:"expectedError"`
			SerializedHex string `json:"serializedHex"`
		} `json:"newAssetGroupFromString"`
	} `json:"invalid"`
}

type assetGroupValidationFixture struct {
	AssetId      assetIdFixture       `json:"assetId,omitempty"`
	ControlAsset *assetRefFixture     `json:"controlAsset,omitempty"`
	Metadata     []metadataFixture    `json:"metadata,omitempty"`
	Inputs       []assetInputFixture  `json:"inputs"`
	Outputs      []assetOutputFixture `json:"outputs"`
}

func (f assetGroupValidationFixture) parse() (
	*asset.AssetId, *asset.AssetRef, []asset.AssetInput, []asset.AssetOutput, []asset.Metadata,
) {
	ins := make([]asset.AssetInput, 0, len(f.Inputs))
	for _, in := range f.Inputs {
		ins = append(ins, *in.parse())
	}
	outs := make([]asset.AssetOutput, 0, len(f.Outputs))
	for _, out := range f.Outputs {
		outs = append(outs, *out.parse())
	}
	md := make([]asset.Metadata, 0, len(f.Metadata))
	for _, m := range f.Metadata {
		md = append(md, *m.parse())
	}
	if len(ins) == 0 {
		ins = nil
	}
	if len(outs) == 0 {
		outs = nil
	}
	if len(md) == 0 {
		md = nil
	}
	var ctrlAsset *asset.AssetRef
	if f.ControlAsset != nil {
		ctrlAsset = f.ControlAsset.parse()
	}
	return f.AssetId.parse(), ctrlAsset, ins, outs, md
}

type assetIdFixture struct {
	Txid  string `json:"txid"`
	Index uint16 `json:"index"`
}

func (f assetIdFixture) parse() *asset.AssetId {
	if f.Txid == "" && f.Index == 0 {
		return nil
	}
	id, _ := asset.NewAssetId(f.Txid, f.Index)
	return id
}

type assetRefFixture struct {
	AssetId    assetIdFixture `json:"assetId,omitempty"`
	GroupIndex uint16         `json:"groupIndex,omitempty"`
}

func (f assetRefFixture) parse() *asset.AssetRef {
	if f.AssetId.Txid == "" {
		ref, _ := asset.NewAssetRefFromGroupIndex(f.GroupIndex)
		return ref
	}
	ref, _ := asset.NewAssetRefFromId(*f.AssetId.parse())
	return ref
}

type assetInputFixture struct {
	Type   string `json:"type"`
	Vin    uint16 `json:"vin"`
	Txid   string `json:"txid"`
	Amount uint64 `json:"amount"`
}

func (f assetInputFixture) parse() *asset.AssetInput {
	if f.Type == asset.AssetInputTypeLocal.String() {
		in, _ := asset.NewAssetInput(f.Vin, f.Amount)
		return in
	}
	in, _ := asset.NewIntentAssetInput(f.Txid, f.Vin, f.Amount)
	return in
}

type assetOutputFixture struct {
	Type   string `json:"type"`
	Vout   uint16 `json:"vout"`
	Amount uint64 `json:"amount"`
}

func (f assetOutputFixture) parse() *asset.AssetOutput {
	out, _ := asset.NewAssetOutput(f.Vout, f.Amount)
	return out
}

type metadataFixture struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (f metadataFixture) parse() *asset.Metadata {
	md, _ := asset.NewMetadata(f.Key, f.Value)
	return md
}
