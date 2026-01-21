package extension

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	emptyAssetId = AssetId{
		TxHash: [32]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		Index:  uint16(0),
	}
)

func TestEncodeAssetGroups(t *testing.T) {
	t.Parallel()

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

	var txh [TX_HASH_SIZE]byte
	for i := 0; i < TX_HASH_SIZE; i++ {
		txh[i] = byte(i + 1)
	}
	// AssetRef with AssetId
	ref := &AssetRef{Type: AssetRefByID}
	ref.AssetId = AssetId{TxHash: txh, Index: 0x1234}

	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref, &scratch))

	decoded, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref.Type, decoded.Type)
	require.Equal(t, ref.AssetId.Index, decoded.AssetId.Index)
	require.Equal(t, ref.AssetId.TxHash, decoded.AssetId.TxHash)

	// AssetRef with GroupIndex
	ref2 := &AssetRef{Type: AssetRefByGroup}
	ref2.GroupIndex = 42
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref2, &scratch))
	decoded2, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref2.Type, decoded2.Type)
	require.Equal(t, ref2.GroupIndex, decoded2.GroupIndex)

	// Mix type with wrong fields (asset by ID but has GroupIndex set)
	ref3 := &AssetRef{Type: AssetRefByID, GroupIndex: 10}
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref3, &scratch))
	decoded3, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref3.Type, decoded3.Type)
	require.NotEqual(t, ref3.GroupIndex, decoded3.GroupIndex)
	require.Equal(t, uint16(0), decoded3.GroupIndex)
	require.Equal(t, emptyAssetId.Index, decoded3.AssetId.Index)
	require.Equal(t, emptyAssetId.TxHash, decoded3.AssetId.TxHash)

	// Mix type with wrong fields (asset by Group but has AssetId set)
	ref4 := &AssetRef{Type: AssetRefByGroup}
	ref4.AssetId = AssetId{TxHash: txh, Index: 0x1234}
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref4, &scratch))
	decoded4, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref4.GroupIndex, decoded4.GroupIndex)
	require.Equal(t, uint16(0), decoded4.GroupIndex)
	require.Equal(t, ref4.Type, decoded4.Type)
	require.Equal(t, emptyAssetId.Index, decoded4.AssetId.Index)
	require.Equal(t, emptyAssetId.TxHash, decoded4.AssetId.TxHash)

	// unknown type
	ref5 := &AssetRef{Type: AssetRefType(99)}
	buf = bytes.NewBuffer(nil)
	err = encodeAssetRef(buf, ref5, &scratch)
	require.Error(t, err)
	require.Equal(t, err.Error(), "unknown asset ref type: 99")
	decoded5, err := decodeAssetRef(buf, &scratch)
	require.Error(t, err)
	require.Equal(t, "unknown asset ref type: 99", err.Error())
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
	meta := []Metadata{{Key: "k1", Value: "v1"}, {Key: "", Value: "v2"}, {Key: "v3", Value: ""}, {Key: "", Value: ""}}
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

	meta = []Metadata{}
	buf2 := bytes.NewBuffer(nil)
	require.NoError(t, encodeMetadataList(buf2, meta, &scratch))
	out, err = decodeMetadataList(buf2, &scratch)
	require.NoError(t, err)
	require.Equal(t, 0, len(meta))
	require.Equal(t, len(meta), len(out))

	// test long keys and value
	longKey := make([]byte, 1024)
	longVal := make([]byte, 2048)
	for i := range longKey {
		longKey[i] = 'k'
	}
	for i := range longVal {
		longVal[i] = 'v'
	}
	meta = []Metadata{{Key: string(longKey), Value: string(longVal)}}
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeMetadataList(buf, meta, &scratch))
	out, err = decodeMetadataList(buf, &scratch)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, meta[0].Key, out[0].Key)
	require.Equal(t, meta[0].Value, out[0].Value)
}

func TestEncodeDecodeAssetInputList(t *testing.T) {
	t.Parallel()
	var scratch [8]byte
	inputs := []AssetInput{
		{Type: AssetTypeLocal, Vin: 3, Amount: 1000},
		{Type: AssetTypeLocal, Vin: 0, Amount: 0},
		{Type: AssetTypeTeleport, Amount: 2000},
		{Type: AssetTypeTeleport, Vin: 3, Amount: 2000},
		{Type: AssetTypeTeleport, Vin: 3, Amount: 2000, Witness: TeleportWitness{
			Script:   []byte{0xde, 0xad, 0xbe, 0xef},
			IntentId: []byte{0xca, 0xfe, 0xba, 0xbe},
		}},
		{Type: AssetTypeTeleport, Witness: TeleportWitness{
			Script:   []byte{},
			IntentId: []byte{0xca, 0xfe, 0xba, 0xbe},
		}},
		{Type: AssetTypeTeleport, Witness: TeleportWitness{
			Script:   []byte{0xde, 0xad, 0xbe, 0xef},
			IntentId: []byte{},
		}},
	}
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
			switch idx {
			case 5:
				require.True(t, bytes.Equal([]byte{}, got[idx].Witness.Script))
				require.True(t, bytes.Equal(inputs[idx].Witness.IntentId, got[idx].Witness.IntentId))
			case 6:
				require.True(t, bytes.Equal(inputs[idx].Witness.Script, got[idx].Witness.Script))
				require.True(t, bytes.Equal([]byte{}, got[idx].Witness.IntentId))
			default:
				require.True(t, bytes.Equal(inputs[idx].Witness.Script, got[idx].Witness.Script))
				require.True(t, bytes.Equal(inputs[idx].Witness.IntentId, got[idx].Witness.IntentId))
			}
		}
	}
	inputs = []AssetInput{
		{Type: AssetTypeLocal, Vin: 3, Amount: 1000},
		{Type: AssetType(10)},
	}

	buf = bytes.NewBuffer(nil)
	err = encodeAssetInputList(buf, inputs, &scratch)
	require.Error(t, err)
	require.Equal(t, "unknown asset input type: 10", err.Error())

	inputs = []AssetInput{{Type: AssetTypeLocal, Vin: 1, Amount: 10}}
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetInputList(buf, inputs, &scratch))
	b := buf.Bytes()
	// truncate buffer to simulate corruption
	if len(b) > 0 {
		tr := bytes.NewBuffer(b[:len(b)-1])
		_, err := decodeAssetInputList(tr, &scratch)
		require.Error(t, err)
	}
}

func TestEncodeDecodeAssetInputList_MixedTeleportCombos(t *testing.T) {
	t.Parallel()
	var scratch [8]byte
	// build inputs without referencing AssetWitness type directly
	in1 := AssetInput{Type: AssetTypeLocal, Vin: 7, Amount: 700}
	in2 := AssetInput{Type: AssetTypeTeleport, Amount: 2000} // empty witness
	in3 := AssetInput{Type: AssetTypeTeleport, Amount: 3000}
	// set witness fields on in2 and in3 by accessing the anonymous Witness field
	in2.Witness.Script = []byte{}
	in2.Witness.IntentId = []byte{}
	in3.Witness.Script = []byte{0x01}
	in3.Witness.IntentId = []byte{}

	inputs := []AssetInput{in1, in2, in3}
	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetInputList(buf, inputs, &scratch))
	got, err := decodeAssetInputList(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, len(inputs), len(got))
	for i := range inputs {
		require.Equal(t, inputs[i].Type, got[i].Type)
		require.Equal(t, inputs[i].Amount, got[i].Amount)
		if inputs[i].Type == AssetTypeLocal {
			require.Equal(t, inputs[i].Vin, got[i].Vin)
		} else {
			require.True(t, bytes.Equal(inputs[i].Witness.Script, got[i].Witness.Script))
			require.True(t, bytes.Equal(inputs[i].Witness.IntentId, got[i].Witness.IntentId))
		}
	}
}

func TestEncodeDecodeAssetOutputList_MixedTeleportCombos(t *testing.T) {
	t.Parallel()
	var scratch [8]byte
	outputs := []AssetOutput{
		// local
		{Type: AssetTypeLocal, Vout: 2, Amount: 250},
		// teleport with nil script
		{Type: AssetTypeTeleport, Script: nil, Amount: 9999},
		// teleport with short script
		{Type: AssetTypeTeleport, Script: []byte{0xaa, 0xbb}, Amount: 12345},
	}
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
}

func TestPresenceBitCombinations(t *testing.T) {
	t.Parallel()
	// construct a presence byte with metadata + immutable but no asset id or control asset
	presence := uint8(0)
	presence |= maskMetadata
	presence |= maskImmutable
	// check bits
	require.Equal(t, uint8(maskMetadata|maskImmutable), presence)

	// ensure mask operations are idempotent
	presence |= maskMetadata
	require.Equal(t, uint8(maskMetadata|maskImmutable), presence)
}

func TestEncodeDecodeAssetOutputList(t *testing.T) {
	t.Parallel()
	var scratch [8]byte
	outputs := []AssetOutput{
		{Type: AssetTypeLocal, Vout: 1, Amount: 500},
		{Type: AssetTypeTeleport, Script: []byte{0x03, 0x04}, Amount: 1500},
	}
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
}

func TestEncodeDecodeAssetOutputList_EdgeCases(t *testing.T) {
	t.Parallel()
	var scratch [8]byte
	// teleport with zero-length script and large amount
	outputs := []AssetOutput{
		{Type: AssetTypeTeleport, Script: []byte{}, Amount: ^uint64(0) - 1},
	}
	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetOutputList(buf, outputs, &scratch))
	got, err := decodeAssetOutputList(buf, &scratch)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, outputs[0].Type, got[0].Type)
	require.Equal(t, outputs[0].Amount, got[0].Amount)
	// truncated decode should fail
	b := buf.Bytes()
	if len(b) > 2 {
		tr := bytes.NewBuffer(b[:len(b)-2])
		_, err := decodeAssetOutputList(tr, &scratch)
		require.Error(t, err)
	}
}
