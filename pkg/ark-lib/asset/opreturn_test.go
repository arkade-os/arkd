package asset

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type jsonContainsAssetPacketCase struct {
	Name        string `json:"name"`
	PkScriptHex string `json:"pk_script_hex,omitempty"`
	BuildType   string `json:"build_type,omitempty"`
	ZeroCount   int    `json:"zero_count,omitempty"`
	ByteCount   int    `json:"byte_count,omitempty"`
	Expected    bool   `json:"expected"`
	Description string `json:"description,omitempty"`
}

type jsonParsePacketOpReturnCase struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	PkScriptHex   string `json:"pk_script_hex,omitempty"`
	BuildType     string `json:"build_type,omitempty"`
	ExpectedError string `json:"expected_error,omitempty"`
}

type jsonParsePacketOpReturnFixtures struct {
	Valid   []jsonParsePacketOpReturnCase `json:"valid"`
	Invalid []jsonParsePacketOpReturnCase `json:"invalid"`
}

type jsonContainsAssetPacketFixtures struct {
	Valid   []jsonContainsAssetPacketCase `json:"valid"`
	Invalid []jsonContainsAssetPacketCase `json:"invalid"`
}

type opreturnFixturesJSON struct {
	ParsePacketOpReturn  jsonParsePacketOpReturnFixtures `json:"parse_packet_opreturn"`
	ContainsAssetPacket  jsonContainsAssetPacketFixtures `json:"contains_asset_packet"`
}

var opreturnFixtures opreturnFixturesJSON

func init() {
	file, err := os.ReadFile("testdata/opreturn_fixtures.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(file, &opreturnFixtures); err != nil {
		panic(err)
	}
}

func buildPkScript(f *jsonContainsAssetPacketCase) ([]byte, error) {
	return buildPkScriptFromParams(f.BuildType, f.PkScriptHex, f.ZeroCount, f.ByteCount)
}

func buildPkScriptFromParams(buildType, pkScriptHex string, zeroCount, byteCount int) ([]byte, error) {
	switch buildType {
	case "arkade_magic_with_zeros":
		script := append([]byte{0x6a}, ArkadeMagic...)
		for i := 0; i < zeroCount; i++ {
			script = append(script, 0x00)
		}
		return script, nil
	case "arkade_magic_with_sequential":
		script := append([]byte{0x6a}, ArkadeMagic...)
		for i := 0; i < byteCount; i++ {
			script = append(script, byte(i))
		}
		return script, nil
	case "arkade_magic_invalid_tlv_length":
		// OP_RETURN + push opcode + ArkadeMagic + type(0x00) + length(100) + only 2 bytes of data
		// Length 100 is a single-byte varint (values < 253 are encoded as-is)
		payload := append([]byte{}, ArkadeMagic...)
		payload = append(payload, MarkerAssetPayload) // type
		payload = append(payload, 0x64)               // length = 100 (single-byte varint)
		payload = append(payload, 0x01, 0x02)         // only 2 bytes (need 100)
		// Build proper OP_RETURN with data push
		script := []byte{0x6a}                      // OP_RETURN
		script = append(script, byte(len(payload))) // push length
		script = append(script, payload...)
		return script, nil
	case "arkade_magic_unknown_marker":
		// OP_RETURN + push opcode + ArkadeMagic + unknown type(0x99) + length(1) + value(0x00)
		payload := append([]byte{}, ArkadeMagic...)
		payload = append(payload, 0x99)       // unknown type
		payload = append(payload, 0x01)       // length = 1
		payload = append(payload, 0x00)       // value
		script := []byte{0x6a}
		script = append(script, byte(len(payload)))
		script = append(script, payload...)
		return script, nil
	case "arkade_magic_only":
		// OP_RETURN + push opcode + ArkadeMagic only (no TLV)
		payload := append([]byte{}, ArkadeMagic...)
		script := []byte{0x6a}
		script = append(script, byte(len(payload)))
		script = append(script, payload...)
		return script, nil
	case "arkade_magic_type_only":
		// OP_RETURN + push opcode + ArkadeMagic + type byte only (no length)
		payload := append([]byte{}, ArkadeMagic...)
		payload = append(payload, MarkerAssetPayload)
		script := []byte{0x6a}
		script = append(script, byte(len(payload)))
		script = append(script, payload...)
		return script, nil
	case "arkade_magic_incomplete_value":
		// OP_RETURN + push opcode + ArkadeMagic + type + length(10) + only 3 bytes
		payload := append([]byte{}, ArkadeMagic...)
		payload = append(payload, MarkerAssetPayload) // type
		payload = append(payload, 0x0a)               // length = 10
		payload = append(payload, 0x01, 0x02, 0x03)   // only 3 bytes (need 10)
		script := []byte{0x6a}
		script = append(script, byte(len(payload)))
		script = append(script, payload...)
		return script, nil
	default:
		if pkScriptHex == "" {
			return []byte{}, nil
		}
		return hex.DecodeString(pkScriptHex)
	}
}

func TestContainsAssetPacket(t *testing.T) {
	// Test all invalid cases from fixtures
	for _, fixture := range opreturnFixtures.ContainsAssetPacket.Invalid {
		t.Run(fixture.Name, func(t *testing.T) {
			pkScript, err := buildPkScript(&fixture)
			require.NoError(t, err)

			if fixture.Expected {
				require.True(t, ContainsAssetPacket(pkScript))
			} else {
				require.False(t, ContainsAssetPacket(pkScript))
			}
		})
	}

	// check valid asset packet (dynamically created)
	t.Run("valid_asset_packet", func(t *testing.T) {
		packet := &AssetPacket{
			Assets: []AssetGroup{controlAsset, normalAsset},
		}
		txOut, err := packet.Encode()
		require.NoError(t, err)
		require.NotEmpty(t, txOut)
		require.True(t, ContainsAssetPacket(txOut.PkScript))
	})
}

func TestParsePacketOpReturn_Errors(t *testing.T) {
	t.Parallel()

	for _, tc := range opreturnFixtures.ParsePacketOpReturn.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			pkScript, err := buildPkScriptFromParams(tc.BuildType, tc.PkScriptHex, 0, 0)
			require.NoError(t, err)

			assetPayload, subDustKey, err := parsePacketOpReturn(pkScript)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.ExpectedError)
			require.Nil(t, assetPayload)
			require.Nil(t, subDustKey)
		})
	}
}

func TestParsePacketOpReturn_MultipleTLVMarkers(t *testing.T) {
	t.Parallel()

	t.Run("duplicate_asset_payload_uses_first", func(t *testing.T) {
		// Build script with two MarkerAssetPayload entries
		// The parser should use the first one only
		payload := append([]byte{}, ArkadeMagic...)

		// First asset payload: [0x01, 0x02]
		payload = append(payload, MarkerAssetPayload) // type
		payload = append(payload, 0x02)               // length = 2
		payload = append(payload, 0x01, 0x02)         // value

		// Second asset payload: [0x03, 0x04, 0x05]
		payload = append(payload, MarkerAssetPayload) // type
		payload = append(payload, 0x03)               // length = 3
		payload = append(payload, 0x03, 0x04, 0x05)   // value

		script := []byte{0x6a}                      // OP_RETURN
		script = append(script, byte(len(payload))) // push length
		script = append(script, payload...)

		assetPayload, subDustKey, err := parsePacketOpReturn(script)
		require.NoError(t, err)
		require.Nil(t, subDustKey)

		// Should get the first asset payload
		require.Equal(t, []byte{0x01, 0x02}, assetPayload)
	})

	t.Run("duplicate_subdust_key_uses_first", func(t *testing.T) {
		// Build script with two MarkerSubDustKey entries
		payload := append([]byte{}, ArkadeMagic...)

		// First subdust key: 32 bytes of 0xAA
		firstKey := make([]byte, 32)
		for i := range firstKey {
			firstKey[i] = 0xAA
		}
		payload = append(payload, MarkerSubDustKey)
		payload = append(payload, byte(len(firstKey)))
		payload = append(payload, firstKey...)

		// Second subdust key: 32 bytes of 0xBB
		secondKey := make([]byte, 32)
		for i := range secondKey {
			secondKey[i] = 0xBB
		}
		payload = append(payload, MarkerSubDustKey)
		payload = append(payload, byte(len(secondKey)))
		payload = append(payload, secondKey...)

		script := []byte{0x6a}                      // OP_RETURN
		script = append(script, byte(len(payload))) // push length
		script = append(script, payload...)

		assetPayload, subDustKey, err := parsePacketOpReturn(script)
		require.NoError(t, err)
		require.Nil(t, assetPayload)

		// Should get the first subdust key
		require.Equal(t, firstKey, subDustKey)
	})

	t.Run("asset_and_subdust_both_present", func(t *testing.T) {
		payload := append([]byte{}, ArkadeMagic...)

		// SubDust key first
		subDust := make([]byte, 32)
		for i := range subDust {
			subDust[i] = 0x55
		}
		payload = append(payload, MarkerSubDustKey)
		payload = append(payload, byte(len(subDust)))
		payload = append(payload, subDust...)

		// Asset payload second
		assetData := []byte{0x01, 0x00} // version + count
		payload = append(payload, MarkerAssetPayload)
		payload = append(payload, byte(len(assetData)))
		payload = append(payload, assetData...)

		script := []byte{0x6a}                      // OP_RETURN
		script = append(script, byte(len(payload))) // push length
		script = append(script, payload...)

		assetPayload, subDustKey, err := parsePacketOpReturn(script)
		require.NoError(t, err)
		require.Equal(t, subDust, subDustKey)
		require.Equal(t, assetData, assetPayload)
	})

	t.Run("unknown_marker_types_skipped", func(t *testing.T) {
		payload := append([]byte{}, ArkadeMagic...)

		// Unknown marker type 0x10
		payload = append(payload, 0x10)       // unknown type
		payload = append(payload, 0x02)       // length = 2
		payload = append(payload, 0xAA, 0xBB) // value (ignored)

		// Valid asset payload
		assetData := []byte{0x01, 0x00}
		payload = append(payload, MarkerAssetPayload)
		payload = append(payload, byte(len(assetData)))
		payload = append(payload, assetData...)

		// Another unknown marker type 0x99
		payload = append(payload, 0x99)       // unknown type
		payload = append(payload, 0x01)       // length = 1
		payload = append(payload, 0xFF)       // value (ignored)

		script := []byte{0x6a}                      // OP_RETURN
		script = append(script, byte(len(payload))) // push length
		script = append(script, payload...)

		assetPayload, subDustKey, err := parsePacketOpReturn(script)
		require.NoError(t, err)
		require.Nil(t, subDustKey)
		require.Equal(t, assetData, assetPayload)
	})
}

func TestContainsAssetPacket_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("valid_minimal_asset_packet", func(t *testing.T) {
		// Create a valid minimal asset packet
		packet := &AssetPacket{
			Assets: []AssetGroup{{
				Inputs:  []AssetInput{{Type: AssetTypeLocal, Vin: 0, Amount: 100}},
				Outputs: []AssetOutput{{Type: AssetTypeLocal, Vout: 0, Amount: 100}},
			}},
		}
		txOut, err := packet.Encode()
		require.NoError(t, err)
		require.True(t, ContainsAssetPacket(txOut.PkScript))
	})

	t.Run("op_pushdata1", func(t *testing.T) {
		// Test with OP_PUSHDATA1 (for payloads 76-255 bytes)
		// Build a payload > 75 bytes to trigger OP_PUSHDATA1
		payload := append([]byte{}, ArkadeMagic...)

		// Add enough data to exceed 75 bytes
		largeAssetData := make([]byte, 80)
		for i := range largeAssetData {
			largeAssetData[i] = byte(i)
		}
		payload = append(payload, MarkerAssetPayload)
		payload = append(payload, byte(len(largeAssetData)))
		payload = append(payload, largeAssetData...)

		// Script with OP_PUSHDATA1: 0x6a 0x4c <len> <data>
		script := []byte{0x6a, 0x4c, byte(len(payload))}
		script = append(script, payload...)

		assetPayload, _, err := parsePacketOpReturn(script)
		require.NoError(t, err)
		require.Equal(t, largeAssetData, assetPayload)
	})

	t.Run("multiple_data_pushes", func(t *testing.T) {
		// Test with multiple OP_PUSHDATA in the script
		// The parser should concatenate all data pushes
		part1 := append([]byte{}, ArkadeMagic...)
		part2 := []byte{MarkerAssetPayload, 0x02, 0xAA, 0xBB}

		// Script: OP_RETURN <push part1> <push part2>
		script := []byte{0x6a}
		script = append(script, byte(len(part1)))
		script = append(script, part1...)
		script = append(script, byte(len(part2)))
		script = append(script, part2...)

		assetPayload, _, err := parsePacketOpReturn(script)
		require.NoError(t, err)
		require.Equal(t, []byte{0xAA, 0xBB}, assetPayload)
	})
}
