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

type jsonAssetIdFixture struct {
	Name     string `json:"name"`
	TxidSeed byte   `json:"txid_seed"`
	Index    uint16 `json:"index"`
}

type jsonInvalidStringFixture struct {
	Name                  string `json:"name"`
	Value                 string `json:"value,omitempty"`
	ByteLength            int    `json:"byte_length,omitempty"`
	ExpectedErrorFormat   string `json:"expected_error_format,omitempty"`
	ExpectedErrorContains string `json:"expected_error_contains,omitempty"`
}

type assetFixturesJSON struct {
	AssetIds       []jsonAssetIdFixture       `json:"asset_ids"`
	InvalidStrings []jsonInvalidStringFixture `json:"invalid_strings"`
}

var assetFixtures assetFixturesJSON

func init() {
	file, err := os.ReadFile("testdata/asset_fixtures.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(file, &assetFixtures); err != nil {
		panic(err)
	}
}

func getAssetIdFixture(name string) *jsonAssetIdFixture {
	for _, f := range assetFixtures.AssetIds {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getInvalidStringFixture(name string) *jsonInvalidStringFixture {
	for _, f := range assetFixtures.InvalidStrings {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToAssetId(f *jsonAssetIdFixture) AssetId {
	return AssetId{
		Txid:  deterministicBytesArray(f.TxidSeed),
		Index: f.Index,
	}
}

func TestAssetIdFromString_InvalidLength(t *testing.T) {
	fixture := getInvalidStringFixture("short")
	require.NotNil(t, fixture)

	// hex encoding means string length is double the byte length
	shortLen := len(fixture.Value) / 2
	assetId, err := NewAssetIdFromString(fixture.Value)
	require.Error(t, err)
	require.Equal(t, fmt.Sprintf(fixture.ExpectedErrorFormat, shortLen), err.Error())
	require.Nil(t, assetId)
}

func TestAssetIdStringConversion(t *testing.T) {
	fixture := getAssetIdFixture("deterministic")
	require.NotNil(t, fixture)
	assetId := fixtureToAssetId(fixture)

	s := assetId.String()
	decoded, err := NewAssetIdFromString(s)
	require.NoError(t, err)
	require.Equal(t, &assetId, decoded)

	// Test invalid hex
	invalidHexFixture := getInvalidStringFixture("invalid_hex")
	require.NotNil(t, invalidHexFixture)
	_, err = NewAssetIdFromString(invalidHexFixture.Value)
	require.Error(t, err)

	// Test invalid length
	wrongLengthFixture := getInvalidStringFixture("wrong_length")
	require.NotNil(t, wrongLengthFixture)
	_, err = NewAssetIdFromString(hex.EncodeToString(make([]byte, wrongLengthFixture.ByteLength)))
	require.Error(t, err)
}

func TestNewAssetIdFromBytes(t *testing.T) {
	t.Parallel()

	t.Run("valid_bytes", func(t *testing.T) {
		fixture := getAssetIdFixture("deterministic")
		require.NotNil(t, fixture)
		expected := fixtureToAssetId(fixture)

		// Build the expected bytes manually
		buf := make([]byte, ASSET_ID_SIZE)
		copy(buf[:TX_HASH_SIZE], expected.Txid[:])
		buf[ASSET_ID_SIZE-2] = byte(expected.Index >> 8)
		buf[ASSET_ID_SIZE-1] = byte(expected.Index)

		assetId, err := NewAssetIdFromBytes(buf)
		require.NoError(t, err)
		require.Equal(t, &expected, assetId)
	})

	t.Run("too_short", func(t *testing.T) {
		fixture := getInvalidStringFixture("too_short_bytes")
		require.NotNil(t, fixture)

		buf := make([]byte, fixture.ByteLength)
		assetId, err := NewAssetIdFromBytes(buf)
		require.Error(t, err)
		require.Nil(t, assetId)
		require.Equal(t, fmt.Sprintf(fixture.ExpectedErrorFormat, fixture.ByteLength), err.Error())
	})

	t.Run("too_long", func(t *testing.T) {
		fixture := getInvalidStringFixture("wrong_length")
		require.NotNil(t, fixture)

		buf := make([]byte, fixture.ByteLength)
		assetId, err := NewAssetIdFromBytes(buf)
		require.Error(t, err)
		require.Nil(t, assetId)
		require.Equal(t, fmt.Sprintf(fixture.ExpectedErrorFormat, fixture.ByteLength), err.Error())
	})

	t.Run("empty", func(t *testing.T) {
		fixture := getInvalidStringFixture("empty")
		require.NotNil(t, fixture)

		assetId, err := NewAssetIdFromBytes([]byte{})
		require.Error(t, err)
		require.Nil(t, assetId)
		require.Equal(t, fmt.Sprintf(fixture.ExpectedErrorFormat, 0), err.Error())
	})
}

func TestAssetId_Serialize_BigEndianIndex(t *testing.T) {
	t.Parallel()

	t.Run("high_byte_index", func(t *testing.T) {
		// Index 256 = 0x0100 in big endian should be [0x01, 0x00]
		fixture := getAssetIdFixture("high_byte_index")
		require.NotNil(t, fixture)
		assetId := fixtureToAssetId(fixture)

		serialized := assetId.Serialize()
		require.Len(t, serialized, ASSET_ID_SIZE)

		// Check big-endian encoding: high byte first
		require.Equal(t, byte(0x01), serialized[ASSET_ID_SIZE-2])
		require.Equal(t, byte(0x00), serialized[ASSET_ID_SIZE-1])
	})

	t.Run("low_byte_only", func(t *testing.T) {
		// Index 255 = 0x00FF in big endian should be [0x00, 0xFF]
		fixture := getAssetIdFixture("low_byte_only")
		require.NotNil(t, fixture)
		assetId := fixtureToAssetId(fixture)

		serialized := assetId.Serialize()
		require.Len(t, serialized, ASSET_ID_SIZE)

		require.Equal(t, byte(0x00), serialized[ASSET_ID_SIZE-2])
		require.Equal(t, byte(0xFF), serialized[ASSET_ID_SIZE-1])
	})

	t.Run("max_index", func(t *testing.T) {
		// Index 65535 = 0xFFFF in big endian should be [0xFF, 0xFF]
		fixture := getAssetIdFixture("max_index")
		require.NotNil(t, fixture)
		assetId := fixtureToAssetId(fixture)

		serialized := assetId.Serialize()
		require.Len(t, serialized, ASSET_ID_SIZE)

		require.Equal(t, byte(0xFF), serialized[ASSET_ID_SIZE-2])
		require.Equal(t, byte(0xFF), serialized[ASSET_ID_SIZE-1])
	})

	t.Run("zero_index", func(t *testing.T) {
		// Index 0 = 0x0000 in big endian should be [0x00, 0x00]
		fixture := getAssetIdFixture("zero_index")
		require.NotNil(t, fixture)
		assetId := fixtureToAssetId(fixture)

		serialized := assetId.Serialize()
		require.Len(t, serialized, ASSET_ID_SIZE)

		require.Equal(t, byte(0x00), serialized[ASSET_ID_SIZE-2])
		require.Equal(t, byte(0x00), serialized[ASSET_ID_SIZE-1])
	})
}

func TestAssetId_SerializeRoundtrip(t *testing.T) {
	t.Parallel()

	for _, fixtureName := range []string{"deterministic", "zero_index", "max_index", "high_byte_index", "low_byte_only", "zero_txid"} {
		fixtureName := fixtureName
		t.Run(fixtureName, func(t *testing.T) {
			t.Parallel()
			fixture := getAssetIdFixture(fixtureName)
			require.NotNil(t, fixture)
			original := fixtureToAssetId(fixture)

			serialized := original.Serialize()
			decoded, err := NewAssetIdFromBytes(serialized)
			require.NoError(t, err)
			require.Equal(t, &original, decoded)

			// Verify Txid bytes match
			for i := 0; i < TX_HASH_SIZE; i++ {
				require.Equal(t, original.Txid[i], decoded.Txid[i])
			}
			require.Equal(t, original.Index, decoded.Index)
		})
	}
}

func TestAssetId_String(t *testing.T) {
	t.Parallel()

	t.Run("deterministic", func(t *testing.T) {
		fixture := getAssetIdFixture("deterministic")
		require.NotNil(t, fixture)
		assetId := fixtureToAssetId(fixture)

		s := assetId.String()
		// String should be hex encoded, so 34 bytes * 2 = 68 characters
		require.Len(t, s, ASSET_ID_SIZE*2)

		// Verify it's valid hex
		decoded, err := hex.DecodeString(s)
		require.NoError(t, err)
		require.Len(t, decoded, ASSET_ID_SIZE)
	})

	t.Run("zero_txid", func(t *testing.T) {
		fixture := getAssetIdFixture("zero_txid")
		require.NotNil(t, fixture)
		assetId := fixtureToAssetId(fixture)

		s := assetId.String()
		// First 64 chars should be all zeros (32 bytes of 0x00)
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", s[:64])
	})
}

// helper function to deep equal compare []AssetGroup slices
func assetGroupsEqual(a, b []AssetGroup) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i].AssetId == nil) != (b[i].AssetId == nil) {
			return false
		}
		// check each field in the AssetId matches
		if a[i].AssetId != nil && b[i].AssetId != nil {
			if a[i].AssetId.Index != b[i].AssetId.Index {
				return false
			}
			if a[i].AssetId.Txid != b[i].AssetId.Txid {
				return false
			}
		}
		if a[i].Immutable != b[i].Immutable {
			return false
		}
		// check each field in the Outputs slice match
		if len(a[i].Outputs) != len(b[i].Outputs) {
			return false
		}
		for idx, o := range a[i].Outputs {
			if o.Type != b[i].Outputs[idx].Type ||
				o.Vout != b[i].Outputs[idx].Vout ||
				len(o.Script) != len(b[i].Outputs[idx].Script) ||
				!bytes.Equal(o.Script, b[i].Outputs[idx].Script) ||
				o.Amount != b[i].Outputs[idx].Amount {
				return false
			}
		}
		// check each ControlAsset field matches
		if (a[i].ControlAsset == nil) != (b[i].ControlAsset == nil) {
			return false
		}
		if a[i].ControlAsset != nil && b[i].ControlAsset != nil {
			if a[i].ControlAsset.Type != b[i].ControlAsset.Type ||
				a[i].ControlAsset.GroupIndex != b[i].ControlAsset.GroupIndex ||
				a[i].ControlAsset.AssetId != b[i].ControlAsset.AssetId {
				return false
			}
		}
		// check each field in the Inputs slice match
		if len(a[i].Inputs) != len(b[i].Inputs) {
			return false
		}
		for idx, in := range a[i].Inputs {
			if in.Type != b[i].Inputs[idx].Type ||
				in.Vin != b[i].Inputs[idx].Vin ||
				// check Witness fields
				len(in.Witness.Script) != len(b[i].Inputs[idx].Witness.Script) ||
				!bytes.Equal(in.Witness.Script, b[i].Inputs[idx].Witness.Script) ||
				len(in.Witness.Txid) != len(b[i].Inputs[idx].Witness.Txid) ||
				!bytes.Equal(in.Witness.Txid[:], b[i].Inputs[idx].Witness.Txid[:]) ||
				in.Amount != b[i].Inputs[idx].Amount {
				return false
			}
		}
		// check each field in the Metadata slice match
		if len(a[i].Metadata) != len(b[i].Metadata) {
			return false
		}
		for idx, md := range a[i].Metadata {
			if md.Key != b[i].Metadata[idx].Key ||
				md.Value != b[i].Metadata[idx].Value {
				return false
			}
		}
	}
	return true
}
