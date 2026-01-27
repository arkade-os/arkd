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

type opreturnFixturesJSON struct {
	ContainsAssetPacketCases []jsonContainsAssetPacketCase `json:"contains_asset_packet_cases"`
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

func getContainsAssetPacketCase(name string) *jsonContainsAssetPacketCase {
	for _, f := range opreturnFixtures.ContainsAssetPacketCases {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func buildPkScript(f *jsonContainsAssetPacketCase) ([]byte, error) {
	switch f.BuildType {
	case "arkade_magic_with_zeros":
		script := append([]byte{0x6a}, ArkadeMagic...)
		for i := 0; i < f.ZeroCount; i++ {
			script = append(script, 0x00)
		}
		return script, nil
	case "arkade_magic_with_sequential":
		script := append([]byte{0x6a}, ArkadeMagic...)
		for i := 0; i < f.ByteCount; i++ {
			script = append(script, byte(i))
		}
		return script, nil
	default:
		if f.PkScriptHex == "" {
			return []byte{}, nil
		}
		return hex.DecodeString(f.PkScriptHex)
	}
}

func TestContainsAssetPacket(t *testing.T) {
	// Test all false cases from fixtures
	falseCases := []string{
		"empty",
		"no_opreturn_prefix",
		"only_opreturn_prefix",
		"tokenizer_error",
		"missing_arkade_magic",
		"with_arkade_magic_bad_data",
		"with_arkade_magic_bad_length",
	}

	for _, caseName := range falseCases {
		t.Run(caseName, func(t *testing.T) {
			fixture := getContainsAssetPacketCase(caseName)
			require.NotNil(t, fixture)

			pkScript, err := buildPkScript(fixture)
			require.NoError(t, err)

			require.Equal(t, fixture.Expected, ContainsAssetPacket(pkScript))
		})
	}

	// check valid asset packet
	t.Run("valid_asset_packet", func(t *testing.T) {
		packet := &AssetPacket{
			Assets: []AssetGroup{controlAsset, normalAsset},
		}
		txOut, err := packet.Encode()
		require.NoError(t, err)
		require.NotEmpty(t, txOut)
		require.Equal(t, true, ContainsAssetPacket(txOut.PkScript))
	})
}
