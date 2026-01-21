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
}

func TestEncodeDecodeAssetInputList(t *testing.T) {
	t.Parallel()
	var scratch [8]byte
	inputs := []AssetInput{
		{Type: AssetTypeLocal, Vin: 3, Amount: 1000},
		{Type: AssetTypeTeleport, Amount: 2000},
	}
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
		}
	}
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
			require.Equal(t, outputs[i].Script, got[i].Script)
		}
	}
}
