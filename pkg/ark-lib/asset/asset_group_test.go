package asset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type assetGroupFixture struct {
	Name          string         `json:"name"`
	AssetGroup    jsonAssetGroup `json:"asset_group"`
	ExpectedError string         `json:"expected_error,omitempty"`
}

type assetGroupFixturesJSON struct {
	Valid   []assetGroupFixture `json:"valid"`
	Invalid []assetGroupFixture `json:"invalid"`
}

var (
	localInputOutputFixture AssetGroup
	fullRoundtripFixture    AssetGroup
)

func init() {
	valid, _, err := parseAssetGroupFixtures()
	if err != nil {
		panic(err)
	}
	localInputOutputFixture, err = GetAssetGroupFixture("local_input_output", valid)
	if err != nil {
		panic(err)
	}
	fullRoundtripFixture, err = GetAssetGroupFixture("full_roundtrip", valid)
	if err != nil {
		panic(err)
	}
}

func parseAssetGroupFixtures() ([]assetGroupFixture, []assetGroupFixture, error) {
	file, err := os.ReadFile("testdata/asset_group_fixtures.json")
	if err != nil {
		return nil, nil, err
	}
	var jsonData assetGroupFixturesJSON
	if err := json.Unmarshal(file, &jsonData); err != nil {
		return nil, nil, err
	}
	return jsonData.Valid, jsonData.Invalid, nil
}

func fixtureToAssetGroupSingle(ja jsonAssetGroup) (AssetGroup, error) {
	var ag AssetGroup

	if ja.AssetId != nil && ja.AssetId.Txid != "" {
		b, err := hex.DecodeString(ja.AssetId.Txid)
		if err != nil {
			return ag, err
		}
		var arr [32]byte
		copy(arr[:], b)
		ag.AssetId = &AssetId{Txid: arr, Index: ja.AssetId.Index}
	}

	ag.Immutable = ja.Immutable

	for _, o := range ja.Outputs {
		out := AssetOutput{Amount: o.Amount}
		switch o.Type {
		case "local":
			out.Type = AssetTypeLocal
			out.Vout = o.Vout
		case "teleport":
			out.Type = AssetTypeTeleport
			if o.Script != "" {
				script, err := hex.DecodeString(o.Script)
				if err != nil {
					return ag, err
				}
				out.Script = script
			}
		}
		ag.Outputs = append(ag.Outputs, out)
	}

	if ja.Control != nil {
		if ja.Control.Type == "AssetRefByGroup" {
			ag.ControlAsset = AssetRefFromGroupIndex(ja.Control.GroupIndex)
		} else if ja.Control.AssetId != nil && ja.Control.AssetId.Txid != "" {
			b, err := hex.DecodeString(ja.Control.AssetId.Txid)
			if err != nil {
				return ag, err
			}
			var arr [32]byte
			copy(arr[:], b)
			ag.ControlAsset = AssetRefFromId(AssetId{Txid: arr, Index: ja.Control.AssetId.Index})
		}
	}

	for _, in := range ja.Inputs {
		ai := AssetInput{Amount: in.Amount}

		if in.TypeRaw != nil {
			ai.Type = AssetType(*in.TypeRaw)
		} else {
			switch in.Type {
			case "local":
				ai.Type = AssetTypeLocal
				ai.Vin = in.Vin
			case "teleport":
				ai.Type = AssetTypeTeleport
			}
		}

		if in.Witness != nil {
			if in.Witness.Script != "" {
				s, err := hex.DecodeString(in.Witness.Script)
				if err != nil {
					return ag, err
				}
				ai.Witness.Script = s
			}
			if in.Witness.Txid != "" {
				b, err := hex.DecodeString(in.Witness.Txid)
				if err != nil {
					return ag, err
				}
				var arr [32]byte
				copy(arr[:], b)
				ai.Witness.Txid = arr
			}
			ai.Witness.Index = in.Witness.Index
		}
		ag.Inputs = append(ag.Inputs, ai)
	}

	if len(ja.Metadata) > 0 {
		ag.Metadata = ja.Metadata
	}

	return ag, nil
}

func GetAssetGroupFixture(name string, fixtures []assetGroupFixture) (AssetGroup, error) {
	for _, f := range fixtures {
		if f.Name == name {
			return fixtureToAssetGroupSingle(f.AssetGroup)
		}
	}
	return AssetGroup{}, fmt.Errorf("fixture not found: %s", name)
}

func GetInvalidAssetGroupFixture(name string, fixtures []assetGroupFixture) (AssetGroup, string, error) {
	for _, f := range fixtures {
		if f.Name == name {
			ag, err := fixtureToAssetGroupSingle(f.AssetGroup)
			return ag, f.ExpectedError, err
		}
	}
	return AssetGroup{}, "", fmt.Errorf("fixture not found: %s", name)
}

func TestAssetGroup_Encode_ErrorUnknownInputType(t *testing.T) {
	t.Parallel()
	_, invalid, err := parseAssetGroupFixtures()
	require.NoError(t, err)

	ag, expectedErr, err := GetInvalidAssetGroupFixture("unknown_input_type", invalid)
	require.NoError(t, err)

	_, encErr := ag.Encode()
	require.Error(t, encErr)
	require.Contains(t, encErr.Error(), expectedErr)
}

func TestAssetGroup_Decode_Truncated(t *testing.T) {
	t.Parallel()
	ag := localInputOutputFixture
	data, err := ag.Encode()
	require.NoError(t, err)
	if len(data) < 5 {
		t.Skip("encoded data too small to truncate")
	}
	// Truncate last 3 bytes to simulate incomplete data
	tr := data[:len(data)-3]
	var out AssetGroup
	err = out.Decode(bytes.NewReader(tr))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected EOF")
}

func TestAssetEncodeDecodeRoundTrip(t *testing.T) {
	ag := fullRoundtripFixture

	encoded, err := ag.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	var decoded AssetGroup

	require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))
	require.Equal(t, ag, decoded)

	decoded.normalizeAssetSlices()
	ag.normalizeAssetSlices()
	require.Equal(t, ag.AssetId.Index, decoded.AssetId.Index)
	require.Equal(t, ag.Immutable, decoded.Immutable)
	require.Equal(t, ag.ControlAsset.Type, decoded.ControlAsset.Type)
	require.Equal(t, ag.Metadata, decoded.Metadata)
	require.Equal(t, ag.Inputs[0].Vin, decoded.Inputs[0].Vin)
	require.Equal(t, ag.Outputs[0].Vout, decoded.Outputs[0].Vout)

	var nilAssetGroup *AssetGroup
	_, err = nilAssetGroup.Encode()
	require.Error(t, err)
	require.Equal(t, "cannot encode nil AssetGroup", fmt.Sprint(err))
}
