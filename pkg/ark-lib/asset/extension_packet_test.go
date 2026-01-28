package asset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
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

type jsonInput struct {
	Type    string `json:"type"`
	TypeRaw *uint8 `json:"type_raw,omitempty"`
	Vin     uint32 `json:"vin,omitempty"`
	Amount  uint64 `json:"amount,omitempty"`
	Txid    string `json:"txid,omitempty"`
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

type jsonExtPubKeyFixture struct {
	Name         string `json:"name"`
	PrivKeyBytes string `json:"priv_key_bytes"`
}

type verifyFixturesJSON struct {
	Valid   []fixture              `json:"valid"`
	Invalid []fixture              `json:"invalid"`
	PubKeys []jsonExtPubKeyFixture `json:"pub_keys"`
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
			t.Run(validFixture.Name, func(t *testing.T) {
				// create AssetGroups from fixture using helper
				ags, err := fixtureToAssetGroups(validFixture)
				require.NoError(t, err)

				// verify each asset group encodes to expected bytes (if provided)
				if validFixture.PkScriptHex != "" {
					for _, ag := range ags {
						agBytes, err := ag.Encode()
						require.NoError(t, err)
						expectedAgBytes, err := hex.DecodeString(validFixture.PkScriptHex)
						require.NoError(t, err)
						require.Equal(t, hex.EncodeToString(expectedAgBytes), hex.EncodeToString(agBytes),
							"pk_script_hex mismatch - actual: %s", hex.EncodeToString(agBytes))
					}
				}

				// put AssetGroups into AssetPacket and ExtensionPacket
				packet := AssetPacket{Assets: ags}
				extPacket := &ExtensionPacket{Asset: &packet}

				// validate the asset groups can be encoded
				txOut, err := extPacket.Encode()
				require.NoError(t, err)

				// decode back and compare to original
				decodedExtPacket, err := DecodeToExtensionPacket(wire.TxOut{Value: 0, PkScript: txOut.PkScript})
				require.NoError(t, err)
				require.NotNil(t, decodedExtPacket.Asset)
				require.Equal(t, len(packet.Assets), len(decodedExtPacket.Asset.Assets))

				for i, originalAG := range packet.Assets {
					decodedAG := decodedExtPacket.Asset.Assets[i]
					require.Equal(t, originalAG.Immutable, decodedAG.Immutable)
					require.Equal(t, originalAG.AssetId, decodedAG.AssetId)
					require.Equal(t, originalAG.ControlAsset, decodedAG.ControlAsset)
					require.Equal(t, originalAG.Outputs, decodedAG.Outputs)
					require.Equal(t, originalAG.Inputs, decodedAG.Inputs)
					require.Equal(t, originalAG.Metadata, decodedAG.Metadata)
				}
			})
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
	pubFixture := getExtPubKeyFixture("corrupted_payload_0x42")
	require.NotNil(t, pubFixture)
	pubPtr, err := fixtureToExtPubKey(pubFixture)
	require.NoError(t, err)
	pub := *pubPtr
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
	require.Contains(t, err.Error(), "opcode OP_PUSHDATA1 pushes")
	require.Contains(t, err.Error(), "but script only has")
	require.Nil(t, ep)
}

var extPubKeyFixtures []jsonExtPubKeyFixture

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
	extPubKeyFixtures = jsonData.PubKeys
	return jsonData.Valid, jsonData.Invalid, nil
}

func getExtPubKeyFixture(name string) *jsonExtPubKeyFixture {
	for _, f := range extPubKeyFixtures {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToExtPubKey(f *jsonExtPubKeyFixture) (*btcec.PublicKey, error) {
	if f == nil {
		return nil, nil
	}
	privKeyBytes, err := hex.DecodeString(f.PrivKeyBytes)
	if err != nil {
		return nil, err
	}
	_, pub := btcec.PrivKeyFromBytes(privKeyBytes)
	return pub, nil
}

// convert all jsonAssetGroups from fixture to []AssetGroup
func fixtureToAssetGroups(f fixture) ([]AssetGroup, error) {
	ags := make([]AssetGroup, 0, len(f.Assets))
	for _, ja := range f.Assets {
		ag, err := jsonAssetGroupToAssetGroup(ja)
		if err != nil {
			return nil, err
		}
		ags = append(ags, ag)
	}
	return ags, nil
}

// convert single jsonAssetGroup to AssetGroup
func jsonAssetGroupToAssetGroup(ja jsonAssetGroup) (AssetGroup, error) {
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
			case "intent":
				out.Type = AssetTypeIntent
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

// convert jsonAssetGroup from fixture to AssetGroup (legacy - uses first asset only)
func fixtureToAssetGroup(f fixture) (AssetGroup, error) {
	if len(f.Assets) == 0 {
		return AssetGroup{}, nil
	}
	return jsonAssetGroupToAssetGroup(f.Assets[0])
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

func TestExtensionPacketEncode_SubDustKeyMissing(t *testing.T) {
	t.Parallel()
	// SubDust is set but Key is nil (with Asset present to pass first validation)
	extPacket := &ExtensionPacket{
		Asset:   &AssetPacket{Assets: []AssetGroup{controlAsset}},
		SubDust: &SubDustPacket{Key: nil, Amount: 100},
	}
	txOut, err := extPacket.Encode()
	require.Error(t, err)
	require.Equal(t, "subdust key missing", err.Error())
	require.Equal(t, int64(0), txOut.Value)
}

func TestDecodeToExtensionPacket_InvalidSubDustKey(t *testing.T) {
	t.Parallel()
	// Craft a TxOut with invalid schnorr pubkey bytes
	// OP_RETURN + ArkadeMagic + MarkerSubDustKey(0x01) + length + invalid key bytes
	invalidKey := bytes.Repeat([]byte{0xff}, 32) // invalid schnorr pubkey
	var payload bytes.Buffer
	payload.Write(ArkadeMagic)
	payload.WriteByte(MarkerSubDustKey)
	var scratch [8]byte
	_ = tlv.WriteVarInt(&payload, uint64(len(invalidKey)), &scratch)
	payload.Write(invalidKey)

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	builder.AddFullData(payload.Bytes())
	pkScript, err := builder.Script()
	require.NoError(t, err)

	txOut := wire.TxOut{Value: 100, PkScript: pkScript}
	ep, err := DecodeToExtensionPacket(txOut)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid public key")
	require.Nil(t, ep)
}

func TestExtensionPacketEncode_EmptyPacket(t *testing.T) {
	t.Parallel()
	// nil packet
	var nilPacket *ExtensionPacket
	txOut, err := nilPacket.Encode()
	require.Error(t, err)
	require.Equal(t, "empty op_return packet", err.Error())
	require.Equal(t, int64(0), txOut.Value)

	// empty packet (no Asset, no SubDust)
	emptyPacket := &ExtensionPacket{}
	txOut, err = emptyPacket.Encode()
	require.Error(t, err)
	require.Equal(t, "empty op_return packet", err.Error())
	require.Equal(t, int64(0), txOut.Value)

	// SubDust with nil key and no Asset
	subDustNoKey := &ExtensionPacket{
		SubDust: &SubDustPacket{Key: nil, Amount: 100},
	}
	txOut, err = subDustNoKey.Encode()
	require.Error(t, err)
	require.Equal(t, "empty op_return packet", err.Error())
	require.Equal(t, int64(0), txOut.Value)
}

func TestIntentOnlyAssetGroupRoundtrip(t *testing.T) {
	t.Parallel()

	// Load fixtures from asset_group_encodings_fixtures.json
	file, err := os.ReadFile("testdata/asset_group_encodings_fixtures.json")
	require.NoError(t, err)

	var fixtures struct {
		IntentRoundtripCases []struct {
			Name        string       `json:"name"`
			Description string       `json:"description,omitempty"`
			Inputs      []jsonInput  `json:"inputs"`
			Outputs     []jsonOutput `json:"outputs"`
		} `json:"intent_roundtrip_cases"`
	}
	require.NoError(t, json.Unmarshal(file, &fixtures))

	for _, tc := range fixtures.IntentRoundtripCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Build AssetGroup from fixture using shared helper
			ja := jsonAssetGroup{Inputs: tc.Inputs, Outputs: tc.Outputs}
			ag, err := jsonAssetGroupToAssetGroup(ja)
			require.NoError(t, err)

			// Encode and decode
			encoded, err := ag.Encode()
			require.NoError(t, err)

			var decoded AssetGroup
			require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))

			// Verify inputs match
			require.Len(t, decoded.Inputs, len(ag.Inputs))
			for i, original := range ag.Inputs {
				require.Equal(t, original.Type, decoded.Inputs[i].Type)
				require.Equal(t, original.Amount, decoded.Inputs[i].Amount)
				require.Equal(t, original.Vin, decoded.Inputs[i].Vin)
				if original.Type == AssetTypeIntent {
					require.Equal(t, original.Txid, decoded.Inputs[i].Txid)
				}
			}

			// Verify outputs match
			require.Len(t, decoded.Outputs, len(ag.Outputs))
			for i, original := range ag.Outputs {
				require.Equal(t, original.Type, decoded.Outputs[i].Type)
				require.Equal(t, original.Amount, decoded.Outputs[i].Amount)
				if original.Type == AssetTypeLocal {
					require.Equal(t, original.Vout, decoded.Outputs[i].Vout)
				}
			}
		})
	}

	// Test extension packet roundtrip separately
	t.Run("extension_packet_roundtrip", func(t *testing.T) {
		// Find the intent_extension_packet fixture
		var tc *struct {
			Name        string       `json:"name"`
			Description string       `json:"description,omitempty"`
			Inputs      []jsonInput  `json:"inputs"`
			Outputs     []jsonOutput `json:"outputs"`
		}
		for i := range fixtures.IntentRoundtripCases {
			if fixtures.IntentRoundtripCases[i].Name == "intent_extension_packet" {
				tc = &fixtures.IntentRoundtripCases[i]
				break
			}
		}
		require.NotNil(t, tc, "intent_extension_packet fixture not found")

		ja := jsonAssetGroup{Inputs: tc.Inputs, Outputs: tc.Outputs}
		ag, err := jsonAssetGroupToAssetGroup(ja)
		require.NoError(t, err)

		packet := AssetPacket{Assets: []AssetGroup{ag}}
		extPacket := &ExtensionPacket{Asset: &packet}

		txOut, err := extPacket.Encode()
		require.NoError(t, err)

		decoded, err := DecodeToExtensionPacket(txOut)
		require.NoError(t, err)
		require.NotNil(t, decoded.Asset)
		require.Len(t, decoded.Asset.Assets, 1)

		decodedAG := decoded.Asset.Assets[0]
		require.Equal(t, ag.Inputs, decodedAG.Inputs)
		require.Equal(t, ag.Outputs, decodedAG.Outputs)
	})
}

func TestIsExtensionPacket(t *testing.T) {
	t.Parallel()

	t.Run("valid_asset_packet", func(t *testing.T) {
		packet := &AssetPacket{
			Assets: []AssetGroup{{
				Inputs:  []AssetInput{{Type: AssetTypeLocal, Vin: 0, Amount: 100}},
				Outputs: []AssetOutput{{Type: AssetTypeLocal, Vout: 0, Amount: 100}},
			}},
		}
		extPacket := &ExtensionPacket{Asset: packet}
		txOut, err := extPacket.Encode()
		require.NoError(t, err)

		require.True(t, IsExtensionPacket(txOut.PkScript))
	})

	t.Run("valid_subdust_only", func(t *testing.T) {
		pubFixture := getExtPubKeyFixture("subdust_only_0x33")
		require.NotNil(t, pubFixture)
		pubPtr, err := fixtureToExtPubKey(pubFixture)
		require.NoError(t, err)
		pub := *pubPtr
		extPacket := &ExtensionPacket{
			SubDust: &SubDustPacket{Key: &pub, Amount: 100},
		}
		txOut, err := extPacket.Encode()
		require.NoError(t, err)

		require.True(t, IsExtensionPacket(txOut.PkScript))
	})

	t.Run("valid_asset_and_subdust", func(t *testing.T) {
		pubFixture := getExtPubKeyFixture("asset_and_subdust_0x44")
		require.NotNil(t, pubFixture)
		pubPtr, err := fixtureToExtPubKey(pubFixture)
		require.NoError(t, err)
		pub := *pubPtr
		packet := &AssetPacket{
			Assets: []AssetGroup{{
				Inputs:  []AssetInput{{Type: AssetTypeLocal, Vin: 0, Amount: 100}},
				Outputs: []AssetOutput{{Type: AssetTypeLocal, Vout: 0, Amount: 100}},
			}},
		}
		extPacket := &ExtensionPacket{
			Asset:   packet,
			SubDust: &SubDustPacket{Key: &pub, Amount: 50},
		}
		txOut, err := extPacket.Encode()
		require.NoError(t, err)

		require.True(t, IsExtensionPacket(txOut.PkScript))
	})

	t.Run("empty_data", func(t *testing.T) {
		require.False(t, IsExtensionPacket([]byte{}))
	})

	t.Run("nil_data", func(t *testing.T) {
		require.False(t, IsExtensionPacket(nil))
	})

	t.Run("non_opreturn", func(t *testing.T) {
		// Random bytes that don't start with OP_RETURN
		require.False(t, IsExtensionPacket([]byte{0x01, 0x02, 0x03}))
	})

	t.Run("opreturn_without_arkade_magic", func(t *testing.T) {
		// OP_RETURN followed by random data (no ArkadeMagic)
		script := []byte{0x6a, 0x04, 0x01, 0x02, 0x03, 0x04}
		require.False(t, IsExtensionPacket(script))
	})

	t.Run("opreturn_with_arkade_magic_but_no_payload", func(t *testing.T) {
		// OP_RETURN + ArkadeMagic but no TLV payload
		payload := append([]byte{}, ArkadeMagic...)
		script := []byte{0x6a, byte(len(payload))}
		script = append(script, payload...)
		require.False(t, IsExtensionPacket(script))
	})

	t.Run("opreturn_with_unknown_marker_only", func(t *testing.T) {
		// OP_RETURN + ArkadeMagic + unknown marker (0x99)
		payload := append([]byte{}, ArkadeMagic...)
		payload = append(payload, 0x99, 0x01, 0x00) // unknown type, len=1, value=0
		script := []byte{0x6a, byte(len(payload))}
		script = append(script, payload...)
		require.False(t, IsExtensionPacket(script))
	})

	t.Run("truncated_script", func(t *testing.T) {
		// Valid start but truncated
		payload := append([]byte{}, ArkadeMagic...)
		payload = append(payload, MarkerAssetPayload, 0x10) // type + length but no data
		script := []byte{0x6a, byte(len(payload))}
		script = append(script, payload...)
		require.False(t, IsExtensionPacket(script))
	})
}
