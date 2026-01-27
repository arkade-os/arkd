package asset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// Fixture types for asset_group_encodings tests
type jsonAssetRefFixture struct {
	Name        string       `json:"name"`
	Type        string       `json:"type"`
	TypeRaw     *uint8       `json:"type_raw,omitempty"`
	AssetId     *jsonAssetId `json:"asset_id,omitempty"`
	GroupIndex  uint16       `json:"group_index,omitempty"`
	Description string       `json:"description,omitempty"`
}

type jsonAssetRefInvalidFixture struct {
	Name          string `json:"name"`
	TypeRaw       uint8  `json:"type_raw"`
	ExpectedError string `json:"expected_error"`
}

type jsonAssetRefsFixtures struct {
	Valid   []jsonAssetRefFixture        `json:"valid"`
	Invalid []jsonAssetRefInvalidFixture `json:"invalid"`
}

type jsonMetadataListFixture struct {
	Name  string     `json:"name"`
	Items []Metadata `json:"items"`
}

type jsonAssetInputsFixture struct {
	Name          string      `json:"name"`
	Inputs        []jsonInput `json:"inputs"`
	ExpectedError string      `json:"expected_error,omitempty"`
}

type jsonAssetInputsFixtures struct {
	Valid   []jsonAssetInputsFixture `json:"valid"`
	Invalid []jsonAssetInputsFixture `json:"invalid"`
}

type jsonAssetOutputsFixture struct {
	Name          string       `json:"name"`
	Outputs       []jsonOutput `json:"outputs"`
	ExpectedError string       `json:"expected_error,omitempty"`
}

type jsonAssetOutputsFixtures struct {
	Valid   []jsonAssetOutputsFixture `json:"valid"`
	Invalid []jsonAssetOutputsFixture `json:"invalid"`
}

type jsonPresenceBitCase struct {
	Name      string `json:"name"`
	AssetId   bool   `json:"asset_id"`
	Control   bool   `json:"control"`
	Metadata  bool   `json:"metadata"`
	Immutable bool   `json:"immutable"`
}

type jsonNormalizeSlicesCase struct {
	Name        string      `json:"name"`
	Seed        byte        `json:"seed"`
	HasOutputs  bool        `json:"has_outputs"`
	HasInputs   bool        `json:"has_inputs"`
	HasMetadata bool        `json:"has_metadata"`
	UseNil      bool        `json:"use_nil,omitempty"`
	Output      *jsonOutput `json:"output,omitempty"`
	Input       *jsonInput  `json:"input,omitempty"`
	Metadata    *Metadata   `json:"metadata,omitempty"`
}

type encodingsFixturesJSON struct {
	AssetRefs            jsonAssetRefsFixtures     `json:"asset_refs"`
	MetadataLists        []jsonMetadataListFixture `json:"metadata_lists"`
	AssetInputs          jsonAssetInputsFixtures   `json:"asset_inputs"`
	AssetOutputs         jsonAssetOutputsFixtures  `json:"asset_outputs"`
	PresenceBitCases     []jsonPresenceBitCase     `json:"presence_bit_cases"`
	NormalizeSlicesCases []jsonNormalizeSlicesCase `json:"normalize_slices_cases"`
}

var encodingsFixtures encodingsFixturesJSON

func init() {
	file, err := os.ReadFile("testdata/asset_group_encodings_fixtures.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(file, &encodingsFixtures); err != nil {
		panic(err)
	}
}

func getAssetRefFixture(name string) *jsonAssetRefFixture {
	for _, f := range encodingsFixtures.AssetRefs.Valid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getInvalidAssetRefFixture(name string) *jsonAssetRefInvalidFixture {
	for _, f := range encodingsFixtures.AssetRefs.Invalid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToAssetRef(f *jsonAssetRefFixture) (*AssetRef, error) {
	ref := &AssetRef{}
	switch f.Type {
	case "AssetRefByID":
		ref.Type = AssetRefByID
	case "AssetRefByGroup":
		ref.Type = AssetRefByGroup
	}
	ref.GroupIndex = f.GroupIndex
	if f.AssetId != nil && f.AssetId.Txid != "" {
		b, err := hex.DecodeString(f.AssetId.Txid)
		if err != nil {
			return nil, err
		}
		var arr [32]byte
		copy(arr[:], b)
		ref.AssetId = AssetId{Txid: arr, Index: f.AssetId.Index}
	}
	return ref, nil
}

func getMetadataListFixture(name string) []Metadata {
	for _, f := range encodingsFixtures.MetadataLists {
		if f.Name == name {
			return f.Items
		}
	}
	return nil
}

func getAssetInputsFixture(name string) *jsonAssetInputsFixture {
	for _, f := range encodingsFixtures.AssetInputs.Valid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getInvalidAssetInputsFixture(name string) *jsonAssetInputsFixture {
	for _, f := range encodingsFixtures.AssetInputs.Invalid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToAssetInputs(inputs []jsonInput) ([]AssetInput, error) {
	result := make([]AssetInput, 0, len(inputs))
	for _, in := range inputs {
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
					return nil, err
				}
				ai.Witness.Script = s
			}
			if in.Witness.Txid != "" {
				b, err := hex.DecodeString(in.Witness.Txid)
				if err != nil {
					return nil, err
				}
				var arr [32]byte
				copy(arr[:], b)
				ai.Witness.Txid = arr
			}
			ai.Witness.Index = in.Witness.Index
		}
		result = append(result, ai)
	}
	return result, nil
}

func getAssetOutputsFixture(name string) *jsonAssetOutputsFixture {
	for _, f := range encodingsFixtures.AssetOutputs.Valid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getInvalidAssetOutputsFixture(name string) *jsonAssetOutputsFixture {
	for _, f := range encodingsFixtures.AssetOutputs.Invalid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToAssetOutputs(outputs []jsonOutput) ([]AssetOutput, error) {
	result := make([]AssetOutput, 0, len(outputs))
	for _, o := range outputs {
		out := AssetOutput{Amount: o.Amount, Vout: o.Vout}
		if o.TypeRaw != nil {
			out.Type = AssetType(*o.TypeRaw)
		} else {
			switch o.Type {
			case "local":
				out.Type = AssetTypeLocal
			case "teleport":
				out.Type = AssetTypeTeleport
				if o.Script != "" {
					script, err := hex.DecodeString(o.Script)
					if err != nil {
						return nil, err
					}
					out.Script = script
				}
			}
		}
		result = append(result, out)
	}
	return result, nil
}

func TestEncodeAssetGroups(t *testing.T) {
	t.Parallel()

	// grab from fixtures
	assetGroups := []AssetGroup{controlAsset, normalAsset}
	data, err := encodeAssetGroups(assetGroups)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	assetGroups = []AssetGroup{}
	data, err = encodeAssetGroups(assetGroups)
	require.Error(t, err)
	require.Equal(t, "cannot encode empty asset group", err.Error())
	require.Nil(t, data)
}

func TestEncodeAssetGroups_Single(t *testing.T) {
	t.Parallel()
	// single group should encode fine
	assetGroups := []AssetGroup{normalAsset}
	data, err := encodeAssetGroups(assetGroups)
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

func TestEncodeDecodeAssetRef(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	// AssetRef with AssetId
	refFixture := getAssetRefFixture("by_id")
	require.NotNil(t, refFixture)
	ref, err := fixtureToAssetRef(refFixture)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref, &scratch))

	decoded, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref.Type, decoded.Type)
	require.Equal(t, ref.AssetId.Index, decoded.AssetId.Index)
	require.Equal(t, ref.AssetId.Txid, decoded.AssetId.Txid)

	// AssetRef with GroupIndex
	ref2Fixture := getAssetRefFixture("by_group")
	require.NotNil(t, ref2Fixture)
	ref2, err := fixtureToAssetRef(ref2Fixture)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref2, &scratch))
	decoded2, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref2.Type, decoded2.Type)
	require.Equal(t, ref2.GroupIndex, decoded2.GroupIndex)

	// Mix type with wrong fields (asset by ID but has GroupIndex set)
	ref3Fixture := getAssetRefFixture("by_id_with_extra_group_index")
	require.NotNil(t, ref3Fixture)
	ref3, err := fixtureToAssetRef(ref3Fixture)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref3, &scratch))
	decoded3, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref3.Type, decoded3.Type)
	require.NotEqual(t, ref3.GroupIndex, decoded3.GroupIndex)
	require.Equal(t, uint16(0), decoded3.GroupIndex)
	require.Equal(t, emptyAssetId.Index, decoded3.AssetId.Index)
	require.Equal(t, emptyAssetId.Txid, decoded3.AssetId.Txid)

	// Mix type with wrong fields (asset by Group but has AssetId set)
	ref4Fixture := getAssetRefFixture("by_group_with_extra_asset_id")
	require.NotNil(t, ref4Fixture)
	ref4, err := fixtureToAssetRef(ref4Fixture)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref4, &scratch))
	decoded4, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref4.GroupIndex, decoded4.GroupIndex)
	require.Equal(t, uint16(0), decoded4.GroupIndex)
	require.Equal(t, ref4.Type, decoded4.Type)
	require.Equal(t, emptyAssetId.Index, decoded4.AssetId.Index)
	require.Equal(t, emptyAssetId.Txid, decoded4.AssetId.Txid)

	// unknown type
	invalidFixture := getInvalidAssetRefFixture("unknown_type")
	require.NotNil(t, invalidFixture)
	ref5 := &AssetRef{Type: AssetRefType(invalidFixture.TypeRaw)}
	buf = bytes.NewBuffer(nil)
	err = encodeAssetRef(buf, ref5, &scratch)
	require.Error(t, err)
	require.Equal(t, err.Error(), invalidFixture.ExpectedError)
	decoded5, err := decodeAssetRef(buf, &scratch)
	require.Error(t, err)
	require.Equal(t, invalidFixture.ExpectedError, err.Error())
	require.Nil(t, decoded5)
}

func TestDecodeAssetRef_Truncated(t *testing.T) {
	t.Parallel()
	var scratch [8]byte
	// create a buffer that's too short for an AssetRefByID
	short := []byte{byte(AssetRefByID)}
	buf := bytes.NewBuffer(short)
	_, err := decodeAssetRef(buf, &scratch)
	require.Error(t, err)
}

func TestEncodeDecodeMetadataList(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	meta := getMetadataListFixture("varied")
	require.NotNil(t, meta)
	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeMetadataList(buf, meta, &scratch))

	out, err := decodeMetadataList(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, 4, len(meta))
	require.Equal(t, len(meta), len(out))
	for i := range meta {
		require.Equal(t, meta[i].Key, out[i].Key)
		require.Equal(t, meta[i].Value, out[i].Value)
	}

	emptyMeta := getMetadataListFixture("empty")
	require.NotNil(t, emptyMeta)
	buf2 := bytes.NewBuffer(nil)
	require.NoError(t, encodeMetadataList(buf2, emptyMeta, &scratch))
	out, err = decodeMetadataList(buf2, &scratch)
	require.NoError(t, err)
	require.Equal(t, 0, len(emptyMeta))
	require.Equal(t, len(emptyMeta), len(out))

	// test long keys and value
	longKey := make([]byte, 1024)
	longVal := make([]byte, 2048)
	for i := range longKey {
		longKey[i] = 'k'
	}
	for i := range longVal {
		longVal[i] = 'v'
	}
	longMeta := []Metadata{{Key: string(longKey), Value: string(longVal)}}
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeMetadataList(buf, longMeta, &scratch))
	out, err = decodeMetadataList(buf, &scratch)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, longMeta[0].Key, out[0].Key)
	require.Equal(t, longMeta[0].Value, out[0].Value)
}

func TestEncodeDecodeAssetInputList(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	inputsFixture := getAssetInputsFixture("comprehensive")
	require.NotNil(t, inputsFixture)
	inputs, err := fixtureToAssetInputs(inputsFixture.Inputs)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetInputList(buf, inputs, &scratch))

	got, err := decodeAssetInputList(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, len(inputs), len(got))
	for idx := range inputs {
		require.Equal(t, inputs[idx].Type, got[idx].Type)
		require.Equal(t, inputs[idx].Amount, got[idx].Amount)
		switch inputs[idx].Type {
		case AssetTypeLocal:
			require.Equal(t, inputs[idx].Vin, got[idx].Vin)
		case AssetTypeTeleport:
			switch {
			case idx == 5 || idx == 6:
				require.True(t, bytes.Equal([]byte{}, got[idx].Witness.Script))
				require.True(t, bytes.Equal(inputs[idx].Witness.Txid[:], got[idx].Witness.Txid[:]))
				require.Equal(t, inputs[idx].Witness.Index, got[idx].Witness.Index)
			case idx == 7 || idx == 8:
				require.True(t, bytes.Equal(inputs[idx].Witness.Script, got[idx].Witness.Script))
				require.True(t, bytes.Equal(emptyAssetId.Txid[:], got[idx].Witness.Txid[:]))
				require.Equal(t, inputs[idx].Witness.Index, got[idx].Witness.Index)
			default:
				require.True(t, bytes.Equal(inputs[idx].Witness.Script, got[idx].Witness.Script))
				require.True(t, bytes.Equal(inputs[idx].Witness.Txid[:], got[idx].Witness.Txid[:]))
				require.Equal(t, inputs[idx].Witness.Index, got[idx].Witness.Index)
			}
		}
	}

	// test with unknown type
	invalidFixture := getInvalidAssetInputsFixture("unknown_type")
	require.NotNil(t, invalidFixture)
	invalidInputs, err := fixtureToAssetInputs(invalidFixture.Inputs)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	err = encodeAssetInputList(buf, invalidInputs, &scratch)
	require.Error(t, err)
	require.Equal(t, invalidFixture.ExpectedError, err.Error())

	// test decode with truncated data
	singleFixture := getAssetInputsFixture("single_local")
	require.NotNil(t, singleFixture)
	singleInputs, err := fixtureToAssetInputs(singleFixture.Inputs)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetInputList(buf, singleInputs, &scratch))
	b := buf.Bytes()
	// truncate buffer to simulate corruption
	if len(b) > 0 {
		tr := bytes.NewBuffer(b[:len(b)-1])
		_, err := decodeAssetInputList(tr, &scratch)
		require.Error(t, err)
		require.Equal(t, "unexpected EOF", err.Error())
	}
}

func TestPresenceBitCombinations(t *testing.T) {
	t.Parallel()

	for _, c := range encodingsFixtures.PresenceBitCases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			var ag AssetGroup
			if c.AssetId {
				var txh [TX_HASH_SIZE]byte
				txh[0] = 1
				ag.AssetId = &AssetId{Txid: txh, Index: 1}
			}
			if c.Control {
				ag.ControlAsset = &AssetRef{Type: AssetRefByGroup, GroupIndex: 2}
			}
			if c.Metadata {
				ag.Metadata = []Metadata{{Key: "k", Value: "v"}}
			}
			ag.Immutable = c.Immutable

			data, err := ag.Encode()
			require.NoError(t, err)
			require.True(t, len(data) > 0)

			// first byte is the presence
			presence := data[0]
			expected := uint8(0)
			if c.AssetId {
				expected |= maskAssetId
			}
			if c.Control {
				expected |= maskControlAsset
			}
			if c.Metadata {
				expected |= maskMetadata
			}
			if c.Immutable {
				expected |= maskImmutable
			}
			require.Equal(t, expected, presence)

			// decode and verify fields
			var out AssetGroup
			require.NoError(t, out.Decode(bytes.NewReader(data)))
			if c.AssetId {
				require.NotNil(t, out.AssetId)
			} else {
				require.Nil(t, out.AssetId)
			}
			if c.Control {
				require.NotNil(t, out.ControlAsset)
			} else {
				require.Nil(t, out.ControlAsset)
			}
			if c.Metadata {
				require.NotZero(t, len(out.Metadata))
			} else {
				require.Zero(t, len(out.Metadata))
			}
			require.Equal(t, c.Immutable, out.Immutable)
		})
	}
}

type failWriter struct{}

func (f failWriter) Write(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestEncodeAssetRef_WriteFail(t *testing.T) {
	t.Parallel()
	// failing writer that always returns an error
	var scratch [8]byte
	ref := &AssetRef{Type: AssetRefByGroup, GroupIndex: 1}
	fw := failWriter{}
	err := encodeAssetRef(fw, ref, &scratch)
	require.Error(t, err)
	require.Equal(t, io.ErrUnexpectedEOF, err)
}

func TestEncodeDecodeAssetOutputList(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	outputsFixture := getAssetOutputsFixture("comprehensive")
	require.NotNil(t, outputsFixture)
	outputs, err := fixtureToAssetOutputs(outputsFixture.Outputs)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetOutputList(buf, outputs, &scratch))

	got, err := decodeAssetOutputList(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, len(outputs), len(got))
	for i := range outputs {
		require.Equal(t, outputs[i].Type, got[i].Type)
		require.Equal(t, outputs[i].Amount, got[i].Amount)
		if outputs[i].Type == AssetTypeLocal {
			require.Equal(t, outputs[i].Vout, got[i].Vout)
		} else {
			require.True(t, bytes.Equal(outputs[i].Script, got[i].Script))
		}
	}

	// test with unknown type
	invalidFixture := getInvalidAssetOutputsFixture("unknown_type")
	require.NotNil(t, invalidFixture)
	invalidOutputs, err := fixtureToAssetOutputs(invalidFixture.Outputs)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	err = encodeAssetOutputList(buf, invalidOutputs, &scratch)
	require.Error(t, err)
	require.Equal(t, invalidFixture.ExpectedError, err.Error())

	// trigger unknown type on decode
	buf = bytes.NewBuffer(nil)
	// manually craft invalid data
	buf.Write([]byte{1})  // count = 1
	buf.Write([]byte{10}) // invalid type
	_, err = decodeAssetOutputList(buf, &scratch)
	require.Error(t, err)
	require.Equal(t, "unknown asset output type: 10", err.Error())

	// test decode with truncated data
	singleFixture := getAssetOutputsFixture("single_local")
	require.NotNil(t, singleFixture)
	singleOutputs, err := fixtureToAssetOutputs(singleFixture.Outputs)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetOutputList(buf, singleOutputs, &scratch))
	b := buf.Bytes()
	// truncate buffer to simulate corruption
	if len(b) > 0 {
		tr := bytes.NewBuffer(b[:len(b)-1])
		_, err := decodeAssetOutputList(tr, &scratch)
		require.Error(t, err)
		require.Equal(t, "unexpected EOF", err.Error())
	}
}

func TestAssetGroupEncodeDecodeWithSubDustKey(t *testing.T) {
	subDustKey := deterministicPubKey(t, 0x55)
	assetPacket := AssetPacket{
		Assets: []AssetGroup{normalAsset},
	}

	ep := &ExtensionPacket{
		Asset:   &assetPacket,
		SubDust: &SubDustPacket{Key: &subDustKey, Amount: 220},
	}

	txOut, err := ep.Encode()
	require.NoError(t, err)

	tokenizer := txscript.MakeScriptTokenizer(0, txOut.PkScript)
	require.True(t, tokenizer.Next())
	require.Equal(t, txscript.OP_RETURN, int(tokenizer.Opcode()))
	require.True(t, tokenizer.Next())
	payload := tokenizer.Data()
	require.NotEmpty(t, payload)
	require.False(t, tokenizer.Next())
	require.NoError(t, tokenizer.Err())

	require.True(t, bytes.HasPrefix(payload, ArkadeMagic))
	reader := bytes.NewReader(payload[len(ArkadeMagic):])
	var scratch [8]byte

	typ, err := reader.ReadByte()
	require.NoError(t, err)
	require.Equal(t, MarkerSubDustKey, typ)

	length, err := tlv.ReadVarInt(reader, &scratch)
	require.NoError(t, err)
	subDustValue := make([]byte, length)
	_, err = io.ReadFull(reader, subDustValue)
	require.NoError(t, err)
	require.Equal(t, schnorr.SerializePubKey(&subDustKey), subDustValue)

	typ, err = reader.ReadByte()
	require.NoError(t, err)
	require.Equal(t, MarkerAssetPayload, typ)

	length, err = tlv.ReadVarInt(reader, &scratch)
	require.NoError(t, err)
	assetValue := make([]byte, length)
	_, err = io.ReadFull(reader, assetValue)
	require.NoError(t, err)
	require.NotEmpty(t, assetValue)
	// No version byte check as it is removed

	decodedExt, err := DecodeToExtensionPacket(txOut)
	require.NoError(t, err)
	require.NotNil(t, decodedExt.SubDust)
	require.True(t, subDustKey.IsEqual(decodedExt.SubDust.Key))
	require.NotNil(t, decodedExt.Asset)
	require.Len(t, decodedExt.Asset.Assets, 1)
	require.Equal(t, normalAsset, decodedExt.Asset.Assets[0])
}

func TestAssetOutputListEncodeDecode(t *testing.T) {
	outputsFixture := getAssetOutputsFixture("simple_pair")
	require.NotNil(t, outputsFixture)
	outputs, err := fixtureToAssetOutputs(outputsFixture.Outputs)
	require.NoError(t, err)

	var scratch [8]byte
	var buf bytes.Buffer
	require.NoError(t, encodeAssetOutputList(&buf, outputs, &scratch))

	var decoded []AssetOutput
	reader := bytes.NewReader(buf.Bytes())
	decoded, err = decodeAssetOutputList(reader, &scratch)
	require.NoError(t, err)
	require.Equal(t, outputs, decoded)
}

func TestAssetInputListEncodeDecode(t *testing.T) {
	inputsFixture := getAssetInputsFixture("simple_pair")
	require.NotNil(t, inputsFixture)
	inputs, err := fixtureToAssetInputs(inputsFixture.Inputs)
	require.NoError(t, err)

	var scratch [8]byte
	var buf bytes.Buffer
	require.NoError(t, encodeAssetInputList(&buf, inputs, &scratch))

	var decoded []AssetInput
	reader := bytes.NewReader(buf.Bytes())
	decoded, err = decodeAssetInputList(reader, &scratch)
	require.NoError(t, err)
	require.Equal(t, inputs, decoded)
}

func TestAssetGroupEncodeDecodeWithGroupIndexRef(t *testing.T) {
	t.Parallel()

	groupIndex := uint16(1)
	modifiedNormalAsset := normalAsset
	// Set ControlAsset to reference by group index
	modifiedNormalAsset.ControlAsset = AssetRefFromGroupIndex(groupIndex)

	encoded, err := modifiedNormalAsset.Encode()
	require.NoError(t, err)

	var decoded AssetGroup
	require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))
	require.NotNil(t, decoded.ControlAsset)
	require.Equal(t, AssetRefByGroup, decoded.ControlAsset.Type)
	require.Equal(t, groupIndex, decoded.ControlAsset.GroupIndex)
}

func TestAssetRef_Constructors(t *testing.T) {
	randTxHash := RandTxHash()
	id := AssetId{Txid: randTxHash, Index: 1}

	ref := AssetRefFromId(id)
	require.Equal(t, AssetRefByID, ref.Type)
	require.Equal(t, id, ref.AssetId)
	require.Equal(t, uint16(0), ref.GroupIndex)

	gref := AssetRefFromGroupIndex(42)
	require.Equal(t, AssetRefByGroup, gref.Type)
	require.Equal(t, uint16(42), gref.GroupIndex)
	require.Equal(t, AssetId{}, gref.AssetId)

}

func TestNormalizeAssetSlices(t *testing.T) {
	t.Parallel()

	for _, c := range encodingsFixtures.NormalizeSlicesCases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()

			ag := AssetGroup{
				AssetId: ptrAssetId(deterministicAssetId(c.Seed)),
			}

			if c.HasOutputs && c.Output != nil {
				out, err := fixtureToAssetOutputs([]jsonOutput{*c.Output})
				require.NoError(t, err)
				ag.Outputs = out
			} else if !c.UseNil {
				ag.Outputs = []AssetOutput{}
			}

			if c.HasInputs && c.Input != nil {
				in, err := fixtureToAssetInputs([]jsonInput{*c.Input})
				require.NoError(t, err)
				ag.Inputs = in
			} else if !c.UseNil {
				ag.Inputs = []AssetInput{}
			}

			if c.HasMetadata && c.Metadata != nil {
				ag.Metadata = []Metadata{*c.Metadata}
			} else if !c.UseNil {
				ag.Metadata = []Metadata{}
			}

			if c.HasOutputs || c.HasInputs || c.HasMetadata {
				ag.ControlAsset = deterministicAssetRefId(0x3c)
			}

			ag.normalizeAssetSlices()

			if c.HasOutputs {
				require.NotNil(t, ag.Outputs)
				require.Equal(t, 1, len(ag.Outputs))
				if c.Output != nil {
					require.Equal(t, c.Output.Vout, ag.Outputs[0].Vout)
				}
			} else {
				require.Nil(t, ag.Outputs)
			}

			if c.HasInputs {
				require.NotNil(t, ag.Inputs)
				require.Equal(t, 1, len(ag.Inputs))
				if c.Input != nil {
					require.Equal(t, c.Input.Vin, ag.Inputs[0].Vin)
				}
			} else {
				require.Nil(t, ag.Inputs)
			}

			if c.HasMetadata {
				require.NotNil(t, ag.Metadata)
				require.Equal(t, 1, len(ag.Metadata))
				if c.Metadata != nil {
					require.Equal(t, c.Metadata.Key, ag.Metadata[0].Key)
				}
			} else {
				require.Nil(t, ag.Metadata)
			}
		})
	}
}

func deterministicPubKey(t *testing.T, seed byte) btcec.PublicKey {
	t.Helper()

	keyBytes := bytes.Repeat([]byte{seed}, 32)
	priv, pub := btcec.PrivKeyFromBytes(keyBytes)
	require.NotNil(t, priv)
	require.NotNil(t, pub)

	return *pub
}

func deterministicTxhash(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, 32)
}

func deterministicBytesArray(seed byte) [32]byte {
	var arr [32]byte
	copy(arr[:], deterministicTxhash(seed))
	return arr
}

func deterministicAssetId(seed byte) AssetId {
	return AssetId{
		Txid:  deterministicBytesArray(seed),
		Index: 0,
	}
}

func ptrAssetId(id AssetId) *AssetId {
	return &id
}

func deterministicAssetRefId(seed byte) *AssetRef {
	return AssetRefFromId(deterministicAssetId(seed))
}
