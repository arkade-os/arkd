package asset

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	Name        string `json:"name"`
	PkScriptHex string `json:"pk_script_hex"`
}

func TestFixtures_DecodeExtensionPacket(t *testing.T) {
	data, err := os.ReadFile("testdata/extension_fixtures.json")
	require.NoError(t, err)

	var fixtures []fixture
	require.NoError(t, json.Unmarshal(data, &fixtures))

	updated := false
	for i, f := range fixtures {
		if f.PkScriptHex == "" {
			// generate real pk_script_hex from deterministic setup
			switch f.Name {
			case "normal":
				packet := AssetPacket{Assets: []AssetGroup{normalAsset}}
				extPacket := &ExtensionPacket{Asset: &packet}
				txOut, err := extPacket.Encode()
				require.NoError(t, err)
				fixtures[i].PkScriptHex = hex.EncodeToString(txOut.PkScript)
				updated = true
			case "control":
				packet := AssetPacket{Assets: []AssetGroup{controlAsset}}
				extPacket := &ExtensionPacket{Asset: &packet}
				txOut, err := extPacket.Encode()
				require.NoError(t, err)
				fixtures[i].PkScriptHex = hex.EncodeToString(txOut.PkScript)
				updated = true
			case "subdust":
				// deterministic key bytes
				var b [32]byte
				for k := range b {
					b[k] = 0x55
				}
				_, pub := btcec.PrivKeyFromBytes(b[:])
				sd := &SubDustPacket{Key: pub, Amount: 123}
				extPacket := &ExtensionPacket{SubDust: sd}
				txOut, err := extPacket.Encode()
				require.NoError(t, err)
				fixtures[i].PkScriptHex = hex.EncodeToString(txOut.PkScript)
				updated = true
			case "control+normal":
				packet := AssetPacket{Assets: []AssetGroup{controlAsset, normalAsset}}
				extPacket := &ExtensionPacket{Asset: &packet}
				txOut, err := extPacket.Encode()
				require.NoError(t, err)
				fixtures[i].PkScriptHex = hex.EncodeToString(txOut.PkScript)
				updated = true
			case "subdust+control":
				// deterministic key bytes
				var b [32]byte
				for k := range b {
					b[k] = 0x55
				}
				_, pub := btcec.PrivKeyFromBytes(b[:])
				sd := &SubDustPacket{Key: pub, Amount: 123}
				packet := AssetPacket{Assets: []AssetGroup{controlAsset}}
				extPacket := &ExtensionPacket{Asset: &packet, SubDust: sd}
				txOut, err := extPacket.Encode()
				require.NoError(t, err)
				fixtures[i].PkScriptHex = hex.EncodeToString(txOut.PkScript)
				updated = true
			default:
				t.Skipf("unknown fixture name: %s", f.Name)
			}
		}
	}

	if updated && os.Getenv("UPDATE_FIXTURES") == "1" {
		out, err := json.MarshalIndent(fixtures, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile("testdata/extension_fixtures.json", out, 0644))
	}

	// Now validate decoding for each fixture
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			scriptBytes, err := hex.DecodeString(f.PkScriptHex)
			require.NoError(t, err)
			txOut := wire.TxOut{Value: 0, PkScript: scriptBytes}
			_, err = DecodeToExtensionPacket(txOut)
			require.NoError(t, err)
		})
	}
}
