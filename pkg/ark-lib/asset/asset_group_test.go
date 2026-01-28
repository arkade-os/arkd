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
		case "intent":
			out.Type = AssetTypeIntent
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
			case "intent":
				ai.Type = AssetTypeIntent
				ai.Vin = in.Vin
				if in.Txid != "" {
					b, err := hex.DecodeString(in.Txid)
					if err != nil {
						return ag, err
					}
					copy(ai.Txid[:], b)
				}
			}
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

	var nilAssetGroup *AssetGroup
	_, err = nilAssetGroup.Encode()
	require.Error(t, err)
	require.Equal(t, "cannot encode nil AssetGroup", fmt.Sprint(err))
}

func TestAssetGroup_Decode_TruncatedAtVariousPoints(t *testing.T) {
	t.Parallel()

	// Test empty buffer (no presence byte)
	t.Run("empty_buffer", func(t *testing.T) {
		var ag AssetGroup
		err := ag.Decode(bytes.NewReader([]byte{}))
		require.Error(t, err)
		require.Equal(t, "EOF", err.Error())
	})

	// Test with AssetId present but truncated
	t.Run("truncated_asset_id_txid", func(t *testing.T) {
		// presence byte with AssetId flag, but only partial Txid
		data := []byte{0x01} // maskAssetId
		data = append(data, bytes.Repeat([]byte{0xaa}, 16)...) // only 16 bytes of Txid (need 32)
		var ag AssetGroup
		err := ag.Decode(bytes.NewReader(data))
		require.Error(t, err)
		require.Equal(t, "unexpected EOF", err.Error())
	})

	t.Run("truncated_asset_id_index", func(t *testing.T) {
		// presence byte with AssetId flag, full Txid but no Index
		data := []byte{0x01} // maskAssetId
		data = append(data, bytes.Repeat([]byte{0xaa}, 32)...) // 32 bytes Txid
		// missing 2 bytes for Index
		var ag AssetGroup
		err := ag.Decode(bytes.NewReader(data))
		require.Error(t, err)
		require.Equal(t, "EOF", err.Error())
	})

	// Test with ControlAsset present but truncated
	t.Run("truncated_control_asset", func(t *testing.T) {
		// presence byte with ControlAsset flag, but no control asset data
		data := []byte{0x02} // maskControlAsset
		var ag AssetGroup
		err := ag.Decode(bytes.NewReader(data))
		require.Error(t, err)
		require.Equal(t, "EOF", err.Error())
	})

	// Test with Metadata present but truncated
	t.Run("truncated_metadata", func(t *testing.T) {
		// presence byte with Metadata flag, but no metadata data
		data := []byte{0x04} // maskMetadata
		var ag AssetGroup
		err := ag.Decode(bytes.NewReader(data))
		require.Error(t, err)
		require.Equal(t, "EOF", err.Error())
	})

	// Test with valid presence but truncated inputs
	t.Run("truncated_inputs", func(t *testing.T) {
		// presence byte with no flags, then truncated input list
		data := []byte{0x00}        // no flags
		data = append(data, 0x01)   // input count = 1
		// but no actual input data
		var ag AssetGroup
		err := ag.Decode(bytes.NewReader(data))
		require.Error(t, err)
		require.Equal(t, "EOF", err.Error())
	})

	// Test with valid inputs but truncated outputs
	t.Run("truncated_outputs", func(t *testing.T) {
		// Use fixture for minimal valid asset group
		ag := localInputOutputFixture
		encoded, err := ag.Encode()
		require.NoError(t, err)

		// Find where outputs start and truncate there
		// Structure: presence(1) + inputs(count + data) + outputs(count + data)
		// We need to truncate after inputs but before outputs complete
		// Truncate to just presence + inputs + output count but no output data
		truncateAt := len(encoded) - 10 // remove last 10 bytes
		if truncateAt < 5 {
			truncateAt = 5
		}
		truncated := encoded[:truncateAt]

		var decoded AssetGroup
		err = decoded.Decode(bytes.NewReader(truncated))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected EOF")
	})
}
