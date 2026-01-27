package asset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// json shapes for fixtures
type jsonAssetId struct {
	Txid  string `json:"txid"`
	Index uint16 `json:"index"`
}

type jsonOutput struct {
	Type    string `json:"type"`
	TypeRaw *uint8 `json:"type_raw,omitempty"`
	Vout    uint32 `json:"vout,omitempty"`
	Script  string `json:"script,omitempty"`
	Amount  uint64 `json:"amount,omitempty"`
}

type jsonInputWitness struct {
	Script string `json:"script,omitempty"`
	Txid   string `json:"txid,omitempty"`
	Index  uint32 `json:"index,omitempty"`
}

type jsonInput struct {
	Type    string            `json:"type"`
	TypeRaw *uint8            `json:"type_raw,omitempty"`
	Vin     uint32            `json:"vin,omitempty"`
	Amount  uint64            `json:"amount,omitempty"`
	Witness *jsonInputWitness `json:"witness,omitempty"`
}

type jsonControlAsset struct {
	Type       string       `json:"type,omitempty"`
	TypeRaw    *uint8       `json:"type_raw,omitempty"`
	AssetId    *jsonAssetId `json:"asset_id,omitempty"`
	GroupIndex uint16       `json:"group_index,omitempty"`
}

type jsonAssetGroup struct {
	AssetId   *jsonAssetId      `json:"asset_id,omitempty"`
	Immutable bool              `json:"immutable,omitempty"`
	Outputs   []jsonOutput      `json:"outputs,omitempty"`
	Control   *jsonControlAsset `json:"control_asset,omitempty"`
	Inputs    []jsonInput       `json:"inputs,omitempty"`
	Metadata  []Metadata        `json:"metadata,omitempty"`
}

type fixture struct {
	Name          string           `json:"name"`
	Description   string           `json:"description,omitempty"`
	Assets        []jsonAssetGroup `json:"assets"`
	PkScriptHex   string           `json:"pk_script_hex,omitempty"`
	ExpectedError string           `json:"expected_error,omitempty"`
}

type verifyFixturesJSON struct {
	Valid   []fixture `json:"valid"`
	Invalid []fixture `json:"invalid"`
}

// make a Control Asset from fixture
var controlAsset AssetGroup
var normalAsset AssetGroup
var emptyAssetId AssetId

func init() {
	{
		valid, _, err := parseFixtures()
		if err != nil {
			panic(err)
		}
		controlAsset = ControlAsset(valid)
		normalAsset = NormalAsset(valid)
		emptyAssetId = EmptyAssetId(valid)
	}
}

func TestVerifyAssetGroupFixtures(t *testing.T) {
	valid, _, err := parseFixtures()
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, validFixture := range valid {
			// create AssetGroups from fixture
			ags := make([]AssetGroup, 0, len(validFixture.Assets))
			for _, ja := range validFixture.Assets {
				ag := AssetGroup{}
				if ja.AssetId != nil && ja.AssetId.Txid != "" {
					b, err := hex.DecodeString(ja.AssetId.Txid)
					require.NoError(t, err)
					var arr [32]byte
					copy(arr[:], b)
					ag.AssetId = &AssetId{Txid: arr, Index: ja.AssetId.Index}
				}
				ag.Immutable = ja.Immutable
				for _, o := range ja.Outputs {
					out := AssetOutput{}
					switch o.Type {
					case "local":
						out.Type = AssetTypeLocal
						out.Vout = o.Vout
						out.Amount = o.Amount
					case "teleport":
						out.Type = AssetTypeTeleport
						if o.Script != "" {
							script, err := hex.DecodeString(o.Script)
							require.NoError(t, err)
							out.Script = script
						}
						out.Amount = o.Amount
					}
					ag.Outputs = append(ag.Outputs, out)
				}
				if ja.Control != nil {
					if ja.Control.Type == "AssetRefByGroup" {
						ag.ControlAsset = AssetRefFromGroupIndex(ja.Control.GroupIndex)
					} else if ja.Control.AssetId != nil && ja.Control.AssetId.Txid != "" {
						b, err := hex.DecodeString(ja.Control.AssetId.Txid)
						require.NoError(t, err)
						var arr [32]byte
						copy(arr[:], b)
						ag.ControlAsset = AssetRefFromId(AssetId{Txid: arr, Index: ja.Control.AssetId.Index})
					}
				}
				// inputs
				for _, in := range ja.Inputs {
					ai := AssetInput{}
					switch in.Type {
					case "local":
						ai.Type = AssetTypeLocal
						ai.Vin = in.Vin
						ai.Amount = in.Amount
					case "teleport":
						ai.Type = AssetTypeTeleport
						ai.Amount = in.Amount
					}
					if in.Witness != nil {
						if in.Witness.Script != "" {
							s, err := hex.DecodeString(in.Witness.Script)
							require.NoError(t, err)
							ai.Witness.Script = s
						}
						if in.Witness.Txid != "" {
							b, err := hex.DecodeString(in.Witness.Txid)
							require.NoError(t, err)
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
				ags = append(ags, ag)
				// encode the AssetGroup for comparison
				agBytes, err := ag.Encode()
				require.NoError(t, err)
				// compare to fixture expected encoding
				expectedAgBytes, err := hex.DecodeString(validFixture.PkScriptHex)
				require.NoError(t, err)
				require.True(t, bytes.Equal(expectedAgBytes, agBytes))
			}
			// put AssetGroups into AssetPacket and ExtensionPacket
			packet := AssetPacket{Assets: ags}
			extPacket := &ExtensionPacket{Asset: &packet}
			// validate the asset groups can be encoded
			txOut, err := extPacket.Encode()
			require.NoError(t, err)

			// now decode back and compare to original fixture AssetGroup
			decodedExtPacket, err := DecodeToExtensionPacket(wire.TxOut{Value: 0, PkScript: txOut.PkScript})
			require.NoError(t, err)
			require.NotNil(t, decodedExtPacket.Asset)
			require.Equal(t, len(packet.Assets), len(decodedExtPacket.Asset.Assets))
			for i, originalAG := range packet.Assets {
				decodedAG := decodedExtPacket.Asset.Assets[i]
				require.Equal(t, originalAG.Immutable, decodedAG.Immutable)
				// AssetId
				if originalAG.AssetId == nil {
					require.Nil(t, decodedAG.AssetId)
				} else {
					require.NotNil(t, decodedAG.AssetId)
					require.Equal(t, originalAG.AssetId.Txid, decodedAG.AssetId.Txid)
					require.Equal(t, originalAG.AssetId.Index, decodedAG.AssetId.Index)
				}
				// ControlAsset
				if originalAG.ControlAsset == nil {
					require.Nil(t, decodedAG.ControlAsset)
				} else {
					require.NotNil(t, decodedAG.ControlAsset)
					require.Equal(t, originalAG.ControlAsset.Type, decodedAG.ControlAsset.Type)
					require.Equal(t, originalAG.ControlAsset.AssetId.String(), decodedAG.ControlAsset.AssetId.String())
					require.Equal(t, originalAG.ControlAsset.GroupIndex, decodedAG.ControlAsset.GroupIndex)
				}
				// Outputs
				require.Equal(t, len(originalAG.Outputs), len(decodedAG.Outputs))
				for j, originalOut := range originalAG.Outputs {
					decodedOut := decodedAG.Outputs[j]
					require.Equal(t, originalOut.Type, decodedOut.Type)
					require.Equal(t, originalOut.Vout, decodedOut.Vout)
					require.Equal(t, originalOut.Amount, decodedOut.Amount)
					require.Equal(t, originalOut.Script, decodedOut.Script)
				}
				// Inputs
				require.Equal(t, len(originalAG.Inputs), len(decodedAG.Inputs))
				for j, originalIn := range originalAG.Inputs {
					decodedIn := decodedAG.Inputs[j]
					require.Equal(t, originalIn.Type, decodedIn.Type)
					require.Equal(t, originalIn.Vin, decodedIn.Vin)
					require.Equal(t, originalIn.Amount, decodedIn.Amount)
					require.Equal(t, originalIn.Witness.Script, decodedIn.Witness.Script)
					require.Equal(t, originalIn.Witness.Txid, decodedIn.Witness.Txid)
					require.Equal(t, originalIn.Witness.Index, decodedIn.Witness.Index)
				}
				// Metadata
				require.Equal(t, len(originalAG.Metadata), len(decodedAG.Metadata))
				for j, originalMeta := range originalAG.Metadata {
					decodedMeta := decodedAG.Metadata[j]
					require.Equal(t, originalMeta.Key, decodedMeta.Key)
					require.Equal(t, originalMeta.Value, decodedMeta.Value)
				}
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		_, invalid, err := parseFixtures()
		require.NoError(t, err)

		for _, invalidFixture := range invalid {
			t.Run(invalidFixture.Name, func(t *testing.T) {
				// If pk_script_hex is provided, test decoding failure
				if invalidFixture.PkScriptHex != "" {
					pkScript, err := hex.DecodeString(invalidFixture.PkScriptHex)
					require.NoError(t, err)

					var ag AssetGroup
					err = ag.Decode(bytes.NewReader(pkScript))
					require.Error(t, err)
					require.Contains(t, err.Error(), invalidFixture.ExpectedError)
					return
				}

				// Otherwise test encoding failure
				for _, ja := range invalidFixture.Assets {
					ag, err := fixtureToAssetGroup(fixture{Assets: []jsonAssetGroup{ja}})
					require.NoError(t, err)

					_, err = ag.Encode()
					require.Error(t, err)
					require.Contains(t, err.Error(), invalidFixture.ExpectedError)
				}
			})
		}
	})

}

func TestExtensionPacketEncodeDecode(t *testing.T) {
	packet := AssetPacket{
		Assets: []AssetGroup{controlAsset, normalAsset},
	}

	extPacket := &ExtensionPacket{Asset: &packet}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)

	decodedExt, err := DecodeToExtensionPacket(txOut)
	require.NoError(t, err)
	require.NotNil(t, decodedExt.Asset)
	require.Equal(t, packet, *decodedExt.Asset)
}

func TestDecodeToExtensionPacket_InvalidOpReturn(t *testing.T) {
	t.Parallel()
	// missing OP_RETURN
	txOut := wire.TxOut{Value: 0, PkScript: []byte{0x01, 0x02}}
	ep, err := DecodeToExtensionPacket(txOut)
	require.Error(t, err)
	require.Contains(t, err.Error(), "OP_RETURN not present")
	require.Nil(t, ep)
}

func TestDecodeToExtensionPacket_CorruptedPayload(t *testing.T) {
	t.Parallel()
	// build a valid packet then corrupt PkScript
	pub := deterministicPubKey(t, 0x42)
	sd := &SubDustPacket{Key: &pub, Amount: 5}
	packet := AssetPacket{Assets: []AssetGroup{controlAsset}}
	extPacket := &ExtensionPacket{Asset: &packet, SubDust: sd}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)
	require.Greater(t, len(txOut.PkScript), 2)
	// truncate pkScript to corrupt and trigger tokenizer error
	tr := wire.TxOut{Value: txOut.Value, PkScript: txOut.PkScript[:len(txOut.PkScript)-2]}
	ep, err := DecodeToExtensionPacket(tr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "opcode OP_PUSHDATA1 pushes 168 bytes, but script only has 166 remaining")
	require.Nil(t, ep)
}

func parseFixtures() ([]fixture, []fixture, error) {
	file, err := os.ReadFile("testdata/extension_fixtures.json")
	if err != nil {
		return nil, nil, err
	}
	var jsonData verifyFixturesJSON
	err = json.Unmarshal(file, &jsonData)
	if err != nil {
		return nil, nil, err
	}
	return jsonData.Valid, jsonData.Invalid, nil
}

// convert jsonAssetGroup from fixture to AssetGroup
func fixtureToAssetGroup(f fixture) (AssetGroup, error) {
	var ag AssetGroup
	if len(f.Assets) == 0 {
		return ag, nil
	}
	ja := f.Assets[0]
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
		out := AssetOutput{}
		if o.TypeRaw != nil {
			out.Type = AssetType(*o.TypeRaw)
			out.Vout = o.Vout
			out.Amount = o.Amount
		} else {
			switch o.Type {
			case "local":
				out.Type = AssetTypeLocal
				out.Vout = o.Vout
				out.Amount = o.Amount
			case "teleport":
				out.Type = AssetTypeTeleport
				if o.Script != "" {
					script, err := hex.DecodeString(o.Script)
					if err != nil {
						return ag, err
					}
					out.Script = script
				}
				out.Amount = o.Amount
			}
		}
		ag.Outputs = append(ag.Outputs, out)
	}
	if ja.Control != nil {
		if ja.Control.TypeRaw != nil {
			ag.ControlAsset = &AssetRef{Type: AssetRefType(*ja.Control.TypeRaw)}
		} else if ja.Control.Type == "AssetRefByGroup" {
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
	// inputs
	for _, in := range ja.Inputs {
		ai := AssetInput{}
		if in.TypeRaw != nil {
			ai.Type = AssetType(*in.TypeRaw)
			ai.Amount = in.Amount
		} else {
			switch in.Type {
			case "local":
				ai.Type = AssetTypeLocal
				ai.Vin = in.Vin
				ai.Amount = in.Amount
			case "teleport":
				ai.Type = AssetTypeTeleport
				ai.Amount = in.Amount
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

func GetFixture(name string, fixtures []fixture) AssetGroup {
	for _, f := range fixtures {
		if f.Name == name {
			ag, _ := fixtureToAssetGroup(f)
			return ag
		}
	}
	return AssetGroup{}
}

func ControlAsset(fixtures []fixture) AssetGroup {
	return GetFixture("control", fixtures)
}

func NormalAsset(fixtures []fixture) AssetGroup {
	return GetFixture("normal", fixtures)
}

func EmptyAssetId(fixtures []fixture) AssetId {
	emptyFixture := GetFixture("empty", fixtures)
	if emptyFixture.AssetId != nil {
		return *emptyFixture.AssetId
	}
	return AssetId{}
}
