package asset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

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
						require.True(t, bytes.Equal(expectedAgBytes, agBytes))
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
	require.Contains(t, err.Error(), "opcode OP_PUSHDATA1 pushes")
	require.Contains(t, err.Error(), "but script only has")
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
