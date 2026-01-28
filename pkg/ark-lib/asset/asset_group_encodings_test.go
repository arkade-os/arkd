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

type jsonEncodeAssetGroupsErrorCase struct {
	Name                     string                 `json:"name"`
	Description              string                 `json:"description,omitempty"`
	AssetGroups              []jsonEncodeAssetGroup `json:"asset_groups"`
	UseNormalAssetFirst      bool                   `json:"use_normal_asset_first,omitempty"`
	UseControlAndNormalFirst bool                   `json:"use_control_and_normal_first,omitempty"`
	ExpectedError            string                 `json:"expected_error"`
}

type jsonEncodeAssetGroupsValidCase struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	AssetGroups []jsonEncodeAssetGroup `json:"asset_groups"`
}

type jsonEncodeAssetGroup struct {
	AssetId      *jsonAssetId         `json:"asset_id,omitempty"`
	Immutable    bool                 `json:"immutable,omitempty"`
	ControlAsset *jsonControlAssetRef `json:"control_asset,omitempty"`
	Inputs       []jsonInput          `json:"inputs,omitempty"`
	Outputs      []jsonOutput         `json:"outputs,omitempty"`
	Metadata     []Metadata           `json:"metadata,omitempty"`
}

type jsonControlAssetRef struct {
	Type       string       `json:"type,omitempty"`
	TypeRaw    *uint8       `json:"type_raw,omitempty"`
	AssetId    *jsonAssetId `json:"asset_id,omitempty"`
	GroupIndex uint16       `json:"group_index,omitempty"`
}

type jsonWriteTestData struct {
	AssetRefByID      jsonAssetRefFixture `json:"asset_ref_by_id"`
	AssetRefByGroup   jsonAssetRefFixture `json:"asset_ref_by_group"`
	MetadataSingle    []Metadata          `json:"metadata_single"`
	MetadataEmptyKey  []Metadata          `json:"metadata_empty_key"`
	InputLocal        jsonInput           `json:"input_local"`
	InputIntent       jsonInput           `json:"input_intent"`
	InputIntentTxid   jsonInput           `json:"input_intent_with_txid"`
	OutputLocal       jsonOutput          `json:"output_local"`
	OutputIntent      jsonOutput          `json:"output_intent"`
}

type encodingsFixturesJSON struct {
	AssetRefs               jsonAssetRefsFixtures            `json:"asset_refs"`
	MetadataLists           []jsonMetadataListFixture        `json:"metadata_lists"`
	AssetInputs             jsonAssetInputsFixtures          `json:"asset_inputs"`
	AssetOutputs            jsonAssetOutputsFixtures         `json:"asset_outputs"`
	PresenceBitCases        []jsonPresenceBitCase            `json:"presence_bit_cases"`
	NormalizeSlicesCases    []jsonNormalizeSlicesCase        `json:"normalize_slices_cases"`
	EncodeAssetGroupsErrors []jsonEncodeAssetGroupsErrorCase `json:"encode_asset_groups_errors"`
	EncodeAssetGroupsValid  []jsonEncodeAssetGroupsValidCase `json:"encode_asset_groups_valid"`
	WriteTestData           jsonWriteTestData                `json:"write_test_data"`
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
			case "intent":
				ai.Type = AssetTypeIntent
				ai.Vin = in.Vin
				if in.Txid != "" {
					b, err := hex.DecodeString(in.Txid)
					if err != nil {
						return nil, err
					}
					copy(ai.Txid[:], b)
				}
			}
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
			case "intent":
				out.Type = AssetTypeIntent
			}
		}
		result = append(result, out)
	}
	return result, nil
}

func fixtureToEncodeAssetGroup(jag jsonEncodeAssetGroup) (AssetGroup, error) {
	var ag AssetGroup

	if jag.AssetId != nil && jag.AssetId.Txid != "" {
		b, err := hex.DecodeString(jag.AssetId.Txid)
		if err != nil {
			return ag, err
		}
		var arr [32]byte
		copy(arr[:], b)
		ag.AssetId = &AssetId{Txid: arr, Index: jag.AssetId.Index}
	}

	ag.Immutable = jag.Immutable

	if jag.ControlAsset != nil {
		if jag.ControlAsset.TypeRaw != nil {
			ag.ControlAsset = &AssetRef{Type: AssetRefType(*jag.ControlAsset.TypeRaw)}
		} else if jag.ControlAsset.Type == "AssetRefByGroup" {
			ag.ControlAsset = AssetRefFromGroupIndex(jag.ControlAsset.GroupIndex)
		} else if jag.ControlAsset.AssetId != nil && jag.ControlAsset.AssetId.Txid != "" {
			b, err := hex.DecodeString(jag.ControlAsset.AssetId.Txid)
			if err != nil {
				return ag, err
			}
			var arr [32]byte
			copy(arr[:], b)
			ag.ControlAsset = AssetRefFromId(AssetId{Txid: arr, Index: jag.ControlAsset.AssetId.Index})
		}
	}

	if len(jag.Inputs) > 0 {
		inputs, err := fixtureToAssetInputs(jag.Inputs)
		if err != nil {
			return ag, err
		}
		ag.Inputs = inputs
	}

	if len(jag.Outputs) > 0 {
		outputs, err := fixtureToAssetOutputs(jag.Outputs)
		if err != nil {
			return ag, err
		}
		ag.Outputs = outputs
	}

	if len(jag.Metadata) > 0 {
		ag.Metadata = jag.Metadata
	}

	return ag, nil
}

func getWriteTestInput(name string) (AssetInput, error) {
	var ji jsonInput
	switch name {
	case "local":
		ji = encodingsFixtures.WriteTestData.InputLocal
	case "intent":
		ji = encodingsFixtures.WriteTestData.InputIntent
	case "intent_with_txid":
		ji = encodingsFixtures.WriteTestData.InputIntentTxid
	default:
		return AssetInput{}, nil
	}
	inputs, err := fixtureToAssetInputs([]jsonInput{ji})
	if err != nil {
		return AssetInput{}, err
	}
	return inputs[0], nil
}

func getWriteTestOutput(name string) (AssetOutput, error) {
	var jo jsonOutput
	switch name {
	case "local":
		jo = encodingsFixtures.WriteTestData.OutputLocal
	case "intent":
		jo = encodingsFixtures.WriteTestData.OutputIntent
	default:
		return AssetOutput{}, nil
	}
	outputs, err := fixtureToAssetOutputs([]jsonOutput{jo})
	if err != nil {
		return AssetOutput{}, err
	}
	return outputs[0], nil
}

func getWriteTestAssetRef(name string) (*AssetRef, error) {
	var jf jsonAssetRefFixture
	switch name {
	case "by_id":
		jf = encodingsFixtures.WriteTestData.AssetRefByID
	case "by_group":
		jf = encodingsFixtures.WriteTestData.AssetRefByGroup
	default:
		return nil, nil
	}
	return fixtureToAssetRef(&jf)
}

func getWriteTestMetadata(name string) []Metadata {
	switch name {
	case "single":
		return encodingsFixtures.WriteTestData.MetadataSingle
	case "empty_key":
		return encodingsFixtures.WriteTestData.MetadataEmptyKey
	default:
		return nil
	}
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

func TestEncodeAssetGroups_Errors(t *testing.T) {
	t.Parallel()

	for _, tc := range encodingsFixtures.EncodeAssetGroupsErrors {
		t.Run(tc.Name, func(t *testing.T) {
			var assetGroups []AssetGroup

			// Prepend control and/or normal assets if specified
			if tc.UseControlAndNormalFirst {
				assetGroups = append(assetGroups, controlAsset, normalAsset)
			} else if tc.UseNormalAssetFirst {
				assetGroups = append(assetGroups, normalAsset)
			}

			// Convert fixture asset groups
			for _, jag := range tc.AssetGroups {
				ag, err := fixtureToEncodeAssetGroup(jag)
				require.NoError(t, err)
				assetGroups = append(assetGroups, ag)
			}

			data, err := encodeAssetGroups(assetGroups)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.ExpectedError)
			require.Nil(t, data)
		})
	}
}

func TestEncodeAssetGroups_ValidCases(t *testing.T) {
	t.Parallel()

	for _, tc := range encodingsFixtures.EncodeAssetGroupsValid {
		t.Run(tc.Name, func(t *testing.T) {
			var assetGroups []AssetGroup
			for _, jag := range tc.AssetGroups {
				ag, err := fixtureToEncodeAssetGroup(jag)
				require.NoError(t, err)
				assetGroups = append(assetGroups, ag)
			}

			data, err := encodeAssetGroups(assetGroups)
			require.NoError(t, err)
			require.NotEmpty(t, data)
		})
	}
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

func TestEncodeAssetRef_WriteFails(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	refByID, err := getWriteTestAssetRef("by_id")
	require.NoError(t, err)
	require.NotNil(t, refByID)

	refByGroup, err := getWriteTestAssetRef("by_group")
	require.NoError(t, err)
	require.NotNil(t, refByGroup)

	// Test write failure on type byte (first write)
	t.Run("fail_on_type_byte", func(t *testing.T) {
		lw := &limitedWriter{limit: 0}
		err := encodeAssetRef(lw, refByID, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Txid (AssetRefByID)
	t.Run("fail_on_txid", func(t *testing.T) {
		lw := &limitedWriter{limit: 1} // allow type byte, fail on txid
		err := encodeAssetRef(lw, refByID, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Index (AssetRefByID)
	t.Run("fail_on_index", func(t *testing.T) {
		lw := &limitedWriter{limit: 33} // allow type byte + txid, fail on index
		err := encodeAssetRef(lw, refByID, &scratch)
		require.Error(t, err)
	})

	// Test write failure on GroupIndex (AssetRefByGroup)
	t.Run("fail_on_group_index", func(t *testing.T) {
		lw := &limitedWriter{limit: 1} // allow type byte, fail on group index
		err := encodeAssetRef(lw, refByGroup, &scratch)
		require.Error(t, err)
	})
}

func TestDecodeAssetRef_TruncatedAtVariousPoints(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	// Test decode with empty buffer (no type byte)
	t.Run("empty_buffer", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{})
		_, err := decodeAssetRef(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode AssetRefByID truncated after type (no txid)
	t.Run("by_id_truncated_after_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{byte(AssetRefByID)})
		_, err := decodeAssetRef(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode AssetRefByID truncated after partial txid
	t.Run("by_id_truncated_partial_txid", func(t *testing.T) {
		data := make([]byte, 17) // type + 16 bytes of txid (need 32)
		data[0] = byte(AssetRefByID)
		buf := bytes.NewBuffer(data)
		_, err := decodeAssetRef(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode AssetRefByID truncated after txid (no index)
	t.Run("by_id_truncated_after_txid", func(t *testing.T) {
		data := make([]byte, 33) // type + 32 bytes txid, but no index
		data[0] = byte(AssetRefByID)
		buf := bytes.NewBuffer(data)
		_, err := decodeAssetRef(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode AssetRefByGroup truncated after type (no group index)
	t.Run("by_group_truncated_after_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{byte(AssetRefByGroup)})
		_, err := decodeAssetRef(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode with unknown type
	t.Run("unknown_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{99}) // unknown type
		_, err := decodeAssetRef(buf, &scratch)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown asset ref type")
	})
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

func TestEncodeMetadataList_WriteFails(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	meta := getWriteTestMetadata("single")
	require.NotNil(t, meta)

	metaEmptyKey := getWriteTestMetadata("empty_key")
	require.NotNil(t, metaEmptyKey)

	// Test write failure on count (first write)
	t.Run("fail_on_count", func(t *testing.T) {
		lw := &limitedWriter{limit: 0}
		err := encodeMetadataList(lw, meta, &scratch)
		require.Error(t, err)
	})

	// Test write failure on key length
	t.Run("fail_on_key_length", func(t *testing.T) {
		lw := &limitedWriter{limit: 1} // allow count, fail on key length
		err := encodeMetadataList(lw, meta, &scratch)
		require.Error(t, err)
	})

	// Test write failure on key bytes
	t.Run("fail_on_key_bytes", func(t *testing.T) {
		lw := &limitedWriter{limit: 2} // allow count + key length, fail on key bytes
		err := encodeMetadataList(lw, meta, &scratch)
		require.Error(t, err)
	})

	// Test write failure on value length
	t.Run("fail_on_value_length", func(t *testing.T) {
		lw := &limitedWriter{limit: 9} // allow count + key length + key bytes, fail on value length
		err := encodeMetadataList(lw, meta, &scratch)
		require.Error(t, err)
	})

	// Test write failure on value bytes
	t.Run("fail_on_value_bytes", func(t *testing.T) {
		lw := &limitedWriter{limit: 10} // allow count + key length + key bytes + value length, fail on value bytes
		err := encodeMetadataList(lw, meta, &scratch)
		require.Error(t, err)
	})

	// Test with empty key (write still happens for length)
	t.Run("fail_on_empty_key_value_length", func(t *testing.T) {
		lw := &limitedWriter{limit: 2} // allow count + key length (0), fail on value length
		err := encodeMetadataList(lw, metaEmptyKey, &scratch)
		require.Error(t, err)
	})
}

func TestDecodeMetadataList_TruncatedAtVariousPoints(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	// Test decode with empty buffer (no count)
	t.Run("empty_buffer", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{})
		_, err := decodeMetadataList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode with only count, no key length
	t.Run("only_count", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1}) // count = 1, but no key length
		_, err := decodeMetadataList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode truncated after key length (no key bytes)
	t.Run("truncated_after_key_length", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, 5}) // count=1, key_len=5, but no key bytes
		_, err := decodeMetadataList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode truncated after key bytes (no value length)
	t.Run("truncated_after_key_bytes", func(t *testing.T) {
		// Encode a valid metadata, then truncate
		var encodeBuf bytes.Buffer
		meta := []Metadata{{Key: "key", Value: "value"}}
		require.NoError(t, encodeMetadataList(&encodeBuf, meta, &scratch))
		// Truncate to just count + key_length + key bytes (no value length)
		truncated := encodeBuf.Bytes()[:5]
		_, err := decodeMetadataList(bytes.NewBuffer(truncated), &scratch)
		require.Error(t, err)
	})

	// Test decode truncated after value length (no value bytes)
	t.Run("truncated_after_value_length", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, 3, 'k', 'e', 'y', 5}) // count=1, key_len=3, key="key", value_len=5, but no value bytes
		_, err := decodeMetadataList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode with empty key but truncated value
	t.Run("empty_key_truncated_value", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, 0, 5}) // count=1, key_len=0, value_len=5, but no value bytes
		_, err := decodeMetadataList(buf, &scratch)
		require.Error(t, err)
	})
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
		case AssetTypeIntent:
			require.True(t, bytes.Equal(inputs[idx].Txid[:], got[idx].Txid[:]))
			require.Equal(t, inputs[idx].Vin, got[idx].Vin)
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

// limitedWriter writes up to limit bytes, then returns an error
type limitedWriter struct {
	limit   int
	written int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.written
	if remaining <= 0 {
		return 0, io.ErrShortWrite
	}
	if len(p) <= remaining {
		lw.written += len(p)
		return len(p), nil
	}
	lw.written += remaining
	return remaining, io.ErrShortWrite
}

func TestEncodeAssetInputList_WriteFails(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	inputLocal, err := getWriteTestInput("local")
	require.NoError(t, err)

	inputIntent, err := getWriteTestInput("intent")
	require.NoError(t, err)

	inputIntentTxid, err := getWriteTestInput("intent_with_txid")
	require.NoError(t, err)

	// Test write failure on count (first write)
	t.Run("fail_on_count", func(t *testing.T) {
		inputs := []AssetInput{inputLocal}
		lw := &limitedWriter{limit: 0}
		err := encodeAssetInputList(lw, inputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on type byte
	t.Run("fail_on_type_byte", func(t *testing.T) {
		inputs := []AssetInput{inputLocal}
		lw := &limitedWriter{limit: 1} // allow count, fail on type
		err := encodeAssetInputList(lw, inputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Local Vin
	t.Run("fail_on_local_vin", func(t *testing.T) {
		inputs := []AssetInput{inputLocal}
		lw := &limitedWriter{limit: 2} // allow count + type, fail on vin
		err := encodeAssetInputList(lw, inputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Local Amount
	t.Run("fail_on_local_amount", func(t *testing.T) {
		inputs := []AssetInput{inputLocal}
		lw := &limitedWriter{limit: 6} // allow count + type + vin, fail on amount
		err := encodeAssetInputList(lw, inputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Intent Amount
	t.Run("fail_on_intent_amount", func(t *testing.T) {
		inputs := []AssetInput{inputIntent}
		lw := &limitedWriter{limit: 2} // allow count + type, fail on amount
		err := encodeAssetInputList(lw, inputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Intent Txid
	t.Run("fail_on_intent_txid", func(t *testing.T) {
		inputs := []AssetInput{inputIntentTxid}
		lw := &limitedWriter{limit: 10} // allow count + type + amount, fail on txid
		err := encodeAssetInputList(lw, inputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Intent Vin (index)
	t.Run("fail_on_intent_vin", func(t *testing.T) {
		inputs := []AssetInput{inputIntentTxid}
		lw := &limitedWriter{limit: 42} // allow count + type + amount + txid(32), fail on vin
		err := encodeAssetInputList(lw, inputs, &scratch)
		require.Error(t, err)
	})
}

func TestDecodeAssetInputList_TruncatedAtVariousPoints(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	// Test decode with empty buffer (no count)
	t.Run("empty_buffer", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{})
		_, err := decodeAssetInputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode with only count, no type
	t.Run("only_count", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1}) // count = 1, but no type
		_, err := decodeAssetInputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode Local truncated after type
	t.Run("local_truncated_after_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, byte(AssetTypeLocal)}) // count=1, type=local, but no vin
		_, err := decodeAssetInputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode Intent truncated after type
	t.Run("intent_truncated_after_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, byte(AssetTypeIntent)}) // count=1, type=intent, but no amount
		_, err := decodeAssetInputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode with unknown type
	t.Run("unknown_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, 99}) // count=1, type=99 (unknown)
		_, err := decodeAssetInputList(buf, &scratch)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown asset input type")
	})

	// Test using fixtures with unknown type
	t.Run("unknown_type_first_fixture", func(t *testing.T) {
		invalidFixture := getInvalidAssetInputsFixture("unknown_type_first")
		require.NotNil(t, invalidFixture)
		inputs, err := fixtureToAssetInputs(invalidFixture.Inputs)
		require.NoError(t, err)

		buf := bytes.NewBuffer(nil)
		err = encodeAssetInputList(buf, inputs, &scratch)
		require.Error(t, err)
		require.Contains(t, err.Error(), invalidFixture.ExpectedError)
	})
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

func TestEncodeAssetOutputList_WriteFails(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	outputLocal, err := getWriteTestOutput("local")
	require.NoError(t, err)

	outputIntent, err := getWriteTestOutput("intent")
	require.NoError(t, err)

	// Test write failure on count (first write)
	t.Run("fail_on_count", func(t *testing.T) {
		outputs := []AssetOutput{outputLocal}
		lw := &limitedWriter{limit: 0}
		err := encodeAssetOutputList(lw, outputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on type byte
	t.Run("fail_on_type_byte", func(t *testing.T) {
		outputs := []AssetOutput{outputLocal}
		lw := &limitedWriter{limit: 1} // allow count, fail on type
		err := encodeAssetOutputList(lw, outputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Local Vout
	t.Run("fail_on_local_vout", func(t *testing.T) {
		outputs := []AssetOutput{outputLocal}
		lw := &limitedWriter{limit: 2} // allow count + type, fail on vout
		err := encodeAssetOutputList(lw, outputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Local Amount
	t.Run("fail_on_local_amount", func(t *testing.T) {
		outputs := []AssetOutput{outputLocal}
		lw := &limitedWriter{limit: 6} // allow count + type + vout, fail on amount
		err := encodeAssetOutputList(lw, outputs, &scratch)
		require.Error(t, err)
	})

	// Test write failure on Intent Amount
	t.Run("fail_on_intent_amount", func(t *testing.T) {
		outputs := []AssetOutput{outputIntent}
		lw := &limitedWriter{limit: 2} // allow count + type, fail on amount
		err := encodeAssetOutputList(lw, outputs, &scratch)
		require.Error(t, err)
	})
}

func TestDecodeAssetOutputList_TruncatedAtVariousPoints(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	// Test decode with empty buffer (no count)
	t.Run("empty_buffer", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{})
		_, err := decodeAssetOutputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode with only count, no type
	t.Run("only_count", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1}) // count = 1, but no type
		_, err := decodeAssetOutputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode Local truncated after type
	t.Run("local_truncated_after_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, byte(AssetTypeLocal)}) // count=1, type=local, but no vout
		_, err := decodeAssetOutputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode Local truncated after vout (no amount)
	t.Run("local_truncated_after_vout", func(t *testing.T) {
		// Encode a valid local output, then truncate
		var encodeBuf bytes.Buffer
		outputs := []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: 100}}
		require.NoError(t, encodeAssetOutputList(&encodeBuf, outputs, &scratch))
		// Truncate to just count + type + vout (no amount)
		truncated := encodeBuf.Bytes()[:6]
		_, err := decodeAssetOutputList(bytes.NewBuffer(truncated), &scratch)
		require.Error(t, err)
	})

	// Test decode Intent truncated after type (no amount)
	t.Run("intent_truncated_after_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, byte(AssetTypeIntent)}) // count=1, type=intent, but no amount
		_, err := decodeAssetOutputList(buf, &scratch)
		require.Error(t, err)
	})

	// Test decode with unknown type
	t.Run("unknown_type", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{1, 99}) // count=1, type=99 (unknown)
		_, err := decodeAssetOutputList(buf, &scratch)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown asset output type")
	})

	// Test using fixtures with unknown type
	t.Run("unknown_type_first_fixture", func(t *testing.T) {
		invalidFixture := getInvalidAssetOutputsFixture("unknown_type_first")
		require.NotNil(t, invalidFixture)
		outputs, err := fixtureToAssetOutputs(invalidFixture.Outputs)
		require.NoError(t, err)

		buf := bytes.NewBuffer(nil)
		err = encodeAssetOutputList(buf, outputs, &scratch)
		require.Error(t, err)
		require.Contains(t, err.Error(), invalidFixture.ExpectedError)
	})
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

func TestBoundaryValues(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	t.Run("max_uint64_amount_output", func(t *testing.T) {
		// Test max uint64 amount (18446744073709551615)
		maxAmount := uint64(18446744073709551615)
		outputs := []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: maxAmount}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetOutputList(buf, outputs, &scratch))

		decoded, err := decodeAssetOutputList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, maxAmount, decoded[0].Amount)
	})

	t.Run("max_uint64_amount_input", func(t *testing.T) {
		maxAmount := uint64(18446744073709551615)
		inputs := []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: maxAmount}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetInputList(buf, inputs, &scratch))

		decoded, err := decodeAssetInputList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, maxAmount, decoded[0].Amount)
	})

	t.Run("max_uint32_vout", func(t *testing.T) {
		// Test max uint32 vout (4294967295)
		maxVout := uint32(4294967295)
		outputs := []AssetOutput{{Type: AssetTypeLocal, Vout: maxVout, Amount: 100}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetOutputList(buf, outputs, &scratch))

		decoded, err := decodeAssetOutputList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, maxVout, decoded[0].Vout)
	})

	t.Run("max_uint32_vin", func(t *testing.T) {
		maxVin := uint32(4294967295)
		inputs := []AssetInput{{Type: AssetTypeLocal, Vin: maxVin, Amount: 100}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetInputList(buf, inputs, &scratch))

		decoded, err := decodeAssetInputList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, maxVin, decoded[0].Vin)
	})

	t.Run("zero_values", func(t *testing.T) {
		outputs := []AssetOutput{{Type: AssetTypeLocal, Vout: 0, Amount: 0}}
		inputs := []AssetInput{{Type: AssetTypeLocal, Vin: 0, Amount: 0}}

		bufOut := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetOutputList(bufOut, outputs, &scratch))
		decodedOut, err := decodeAssetOutputList(bufOut, &scratch)
		require.NoError(t, err)
		require.Equal(t, uint32(0), decodedOut[0].Vout)
		require.Equal(t, uint64(0), decodedOut[0].Amount)

		bufIn := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetInputList(bufIn, inputs, &scratch))
		decodedIn, err := decodeAssetInputList(bufIn, &scratch)
		require.NoError(t, err)
		require.Equal(t, uint32(0), decodedIn[0].Vin)
		require.Equal(t, uint64(0), decodedIn[0].Amount)
	})

	t.Run("varint_boundary_253", func(t *testing.T) {
		// 253 is the first value that requires 3-byte varint encoding
		outputs := make([]AssetOutput, 253)
		for i := range outputs {
			outputs[i] = AssetOutput{Type: AssetTypeLocal, Vout: uint32(i), Amount: 1}
		}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetOutputList(buf, outputs, &scratch))

		decoded, err := decodeAssetOutputList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 253)
	})

	t.Run("max_uint16_group_index", func(t *testing.T) {
		maxGroupIndex := uint16(65535)
		ref := AssetRefFromGroupIndex(maxGroupIndex)

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetRef(buf, ref, &scratch))

		decoded, err := decodeAssetRef(buf, &scratch)
		require.NoError(t, err)
		require.Equal(t, AssetRefByGroup, decoded.Type)
		require.Equal(t, maxGroupIndex, decoded.GroupIndex)
	})

	t.Run("max_uint16_asset_id_index", func(t *testing.T) {
		maxIndex := uint16(65535)
		assetId := AssetId{Txid: deterministicBytesArray(0xAA), Index: maxIndex}
		ref := AssetRefFromId(assetId)

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeAssetRef(buf, ref, &scratch))

		decoded, err := decodeAssetRef(buf, &scratch)
		require.NoError(t, err)
		require.Equal(t, maxIndex, decoded.AssetId.Index)
	})
}

func TestMetadataEdgeCases(t *testing.T) {
	t.Parallel()
	var scratch [8]byte

	t.Run("empty_key_and_value", func(t *testing.T) {
		meta := []Metadata{{Key: "", Value: ""}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeMetadataList(buf, meta, &scratch))

		decoded, err := decodeMetadataList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, "", decoded[0].Key)
		require.Equal(t, "", decoded[0].Value)
	})

	t.Run("empty_key_with_value", func(t *testing.T) {
		meta := []Metadata{{Key: "", Value: "somevalue"}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeMetadataList(buf, meta, &scratch))

		decoded, err := decodeMetadataList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, "", decoded[0].Key)
		require.Equal(t, "somevalue", decoded[0].Value)
	})

	t.Run("key_with_empty_value", func(t *testing.T) {
		meta := []Metadata{{Key: "somekey", Value: ""}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeMetadataList(buf, meta, &scratch))

		decoded, err := decodeMetadataList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, "somekey", decoded[0].Key)
		require.Equal(t, "", decoded[0].Value)
	})

	t.Run("special_characters", func(t *testing.T) {
		meta := []Metadata{
			{Key: "emoji🔥", Value: "火"},
			{Key: "newline\nkey", Value: "tab\tvalue"},
			{Key: "null\x00byte", Value: "value\x00here"},
		}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeMetadataList(buf, meta, &scratch))

		decoded, err := decodeMetadataList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 3)
		require.Equal(t, meta[0].Key, decoded[0].Key)
		require.Equal(t, meta[0].Value, decoded[0].Value)
		require.Equal(t, meta[1].Key, decoded[1].Key)
		require.Equal(t, meta[1].Value, decoded[1].Value)
		require.Equal(t, meta[2].Key, decoded[2].Key)
		require.Equal(t, meta[2].Value, decoded[2].Value)
	})

	t.Run("large_metadata_value", func(t *testing.T) {
		// Create a 10KB value
		largeValue := make([]byte, 10*1024)
		for i := range largeValue {
			largeValue[i] = byte(i % 256)
		}
		meta := []Metadata{{Key: "large", Value: string(largeValue)}}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeMetadataList(buf, meta, &scratch))

		decoded, err := decodeMetadataList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 1)
		require.Equal(t, string(largeValue), decoded[0].Value)
	})

	t.Run("many_metadata_items", func(t *testing.T) {
		meta := make([]Metadata, 100)
		for i := range meta {
			meta[i] = Metadata{Key: string(rune('a' + i%26)), Value: string(rune('A' + i%26))}
		}

		buf := bytes.NewBuffer(nil)
		require.NoError(t, encodeMetadataList(buf, meta, &scratch))

		decoded, err := decodeMetadataList(buf, &scratch)
		require.NoError(t, err)
		require.Len(t, decoded, 100)
	})
}

func TestPresenceBitDecodeVerification(t *testing.T) {
	t.Parallel()

	t.Run("no_flags_fields_nil", func(t *testing.T) {
		// AssetGroup with no optional fields
		ag := AssetGroup{
			Inputs:  []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: 100}},
			Outputs: []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: 100}},
		}

		encoded, err := ag.Encode()
		require.NoError(t, err)

		// Verify presence byte has no flags set
		require.Equal(t, uint8(0), encoded[0])

		var decoded AssetGroup
		require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))

		// Verify optional fields are nil/empty
		require.Nil(t, decoded.AssetId)
		require.Nil(t, decoded.ControlAsset)
		require.Nil(t, decoded.Metadata)
		require.False(t, decoded.Immutable)
	})

	t.Run("only_asset_id_set", func(t *testing.T) {
		ag := AssetGroup{
			AssetId: ptrAssetId(deterministicAssetId(0x11)),
			Inputs:  []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: 100}},
			Outputs: []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: 100}},
		}

		encoded, err := ag.Encode()
		require.NoError(t, err)

		var decoded AssetGroup
		require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))

		require.NotNil(t, decoded.AssetId)
		require.Nil(t, decoded.ControlAsset)
		require.Nil(t, decoded.Metadata)
		require.False(t, decoded.Immutable)
	})

	t.Run("only_control_asset_set", func(t *testing.T) {
		ag := AssetGroup{
			ControlAsset: AssetRefFromGroupIndex(5),
			Inputs:       []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: 100}},
			Outputs:      []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: 100}},
		}

		encoded, err := ag.Encode()
		require.NoError(t, err)

		var decoded AssetGroup
		require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))

		require.Nil(t, decoded.AssetId)
		require.NotNil(t, decoded.ControlAsset)
		require.Nil(t, decoded.Metadata)
		require.False(t, decoded.Immutable)
	})

	t.Run("only_metadata_set", func(t *testing.T) {
		ag := AssetGroup{
			Metadata: []Metadata{{Key: "k", Value: "v"}},
			Inputs:   []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: 100}},
			Outputs:  []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: 100}},
		}

		encoded, err := ag.Encode()
		require.NoError(t, err)

		var decoded AssetGroup
		require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))

		require.Nil(t, decoded.AssetId)
		require.Nil(t, decoded.ControlAsset)
		require.NotNil(t, decoded.Metadata)
		require.Len(t, decoded.Metadata, 1)
		require.False(t, decoded.Immutable)
	})

	t.Run("only_immutable_set", func(t *testing.T) {
		ag := AssetGroup{
			Immutable: true,
			Inputs:    []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: 100}},
			Outputs:   []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: 100}},
		}

		encoded, err := ag.Encode()
		require.NoError(t, err)

		var decoded AssetGroup
		require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))

		require.Nil(t, decoded.AssetId)
		require.Nil(t, decoded.ControlAsset)
		require.Nil(t, decoded.Metadata)
		require.True(t, decoded.Immutable)
	})

	t.Run("immutable_false_explicit", func(t *testing.T) {
		ag := AssetGroup{
			Immutable: false,
			Inputs:    []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: 100}},
			Outputs:   []AssetOutput{{Type: AssetTypeLocal, Vout: 1, Amount: 100}},
		}

		encoded, err := ag.Encode()
		require.NoError(t, err)

		// Verify immutable bit is NOT set
		require.Equal(t, uint8(0), encoded[0]&maskImmutable)

		var decoded AssetGroup
		require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))
		require.False(t, decoded.Immutable)
	})
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
