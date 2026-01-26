package asset

import (
	"bytes"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

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

	var txh [TX_HASH_SIZE]byte
	for i := 0; i < TX_HASH_SIZE; i++ {
		txh[i] = byte(i + 1)
	}
	// AssetRef with AssetId
	ref := &AssetRef{Type: AssetRefByID}
	ref.AssetId = AssetId{Txid: txh, Index: 0x1234}

	buf := bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetRef(buf, ref, &scratch))

	decoded, err := decodeAssetRef(buf, &scratch)
	require.NoError(t, err)
	require.Equal(t, ref.Type, decoded.Type)
	require.Equal(t, ref.AssetId.Index, decoded.AssetId.Index)
	require.Equal(t, ref.AssetId.Txid, decoded.AssetId.Txid)

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
	require.Equal(t, emptyAssetId.Txid, decoded3.AssetId.Txid)

	// Mix type with wrong fields (asset by Group but has AssetId set)
	ref4 := &AssetRef{Type: AssetRefByGroup}
	ref4.AssetId = AssetId{Txid: txh, Index: 0x1234}
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
			Script: []byte{0xde, 0xad, 0xbe, 0xef},
			Txid:   [32]byte{0xca, 0xfe, 0xba, 0xbe},
			Index:  42,
		}},
		{Type: AssetTypeTeleport, Witness: TeleportWitness{
			Script: []byte{},
			Txid:   [32]byte{0xca, 0xfe, 0xba, 0xbe},
			Index:  99,
		}},
		{Type: AssetTypeTeleport, Witness: TeleportWitness{
			Script: nil,
			Txid:   [32]byte{0xca, 0xfe, 0xba, 0xbe},
			Index:  100,
		}},
		{Type: AssetTypeTeleport, Witness: TeleportWitness{
			Script: []byte{0xde, 0xad, 0xbe, 0xef},
			Txid:   [32]byte{},
			Index:  101,
		},
		},
		{Type: AssetTypeTeleport, Witness: TeleportWitness{
			Script: []byte{0xde, 0xad, 0xbe, 0xef},
			Txid:   [32]byte{},
			// large Index value using max value of uint32
			Index: 4294967295,
		},
		},
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
		require.Equal(t, "unexpected EOF", err.Error())
	}
}

func TestPresenceBitCombinations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		assetId   bool
		control   bool
		metadata  bool
		immutable bool
	}{
		{"none", false, false, false, false},
		{"assetId", true, false, false, false},
		{"control", false, true, false, false},
		{"metadata", false, false, true, false},
		{"immutable", false, false, false, true},
		{"assetId_control", true, true, false, false},
		{"all", true, true, true, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var ag AssetGroup
			if c.assetId {
				var txh [TX_HASH_SIZE]byte
				txh[0] = 1
				ag.AssetId = &AssetId{Txid: txh, Index: 1}
			}
			if c.control {
				ag.ControlAsset = &AssetRef{Type: AssetRefByGroup, GroupIndex: 2}
			}
			if c.metadata {
				ag.Metadata = []Metadata{{Key: "k", Value: "v"}}
			}
			ag.Immutable = c.immutable

			data, err := ag.Encode()
			require.NoError(t, err)
			require.True(t, len(data) > 0)

			// first byte is the presence
			presence := data[0]
			expected := uint8(0)
			if c.assetId {
				expected |= maskAssetId
			}
			if c.control {
				expected |= maskControlAsset
			}
			if c.metadata {
				expected |= maskMetadata
			}
			if c.immutable {
				expected |= maskImmutable
			}
			require.Equal(t, expected, presence)

			// decode and verify fields
			var out AssetGroup
			require.NoError(t, out.Decode(bytes.NewReader(data)))
			if c.assetId {
				require.NotNil(t, out.AssetId)
			} else {
				require.Nil(t, out.AssetId)
			}
			if c.control {
				require.NotNil(t, out.ControlAsset)
			} else {
				require.Nil(t, out.ControlAsset)
			}
			if c.metadata {
				require.NotZero(t, len(out.Metadata))
			} else {
				require.Zero(t, len(out.Metadata))
			}
			require.Equal(t, c.immutable, out.Immutable)
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
	outputs := []AssetOutput{
		{Type: AssetTypeLocal, Vout: 3, Amount: 1000},
		{Type: AssetTypeLocal, Vout: 0, Amount: 0},
		{Type: AssetTypeTeleport, Amount: 2000},
		{Type: AssetTypeTeleport, Vout: 3, Amount: 2000},
		{Type: AssetTypeTeleport, Vout: 3, Amount: 2000, Script: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Type: AssetTypeTeleport, Script: []byte{}},
		{Type: AssetTypeTeleport, Script: nil},
		{Type: AssetTypeLocal, Vout: 3, Amount: 2000, Script: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Type: AssetTypeLocal, Script: []byte{}},
		{Type: AssetTypeLocal, Script: nil},
		// large Amount values
		{Type: AssetTypeLocal, Amount: ^uint64(0) - 1},
		{Type: AssetTypeTeleport, Amount: ^uint64(0) - 1, Script: []byte{0xde, 0xad, 0xbe, 0xef}},
		// case for large Vout value
		{Type: AssetTypeLocal, Vout: ^uint32(0), Amount: 5000},
		{Type: AssetTypeTeleport, Vout: ^uint32(0), Amount: 5000, Script: []byte{0xde, 0xad, 0xbe, 0xef}},
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
	// test with unknown type
	outputs = []AssetOutput{
		{Type: AssetType(10), Vout: 3, Amount: 1000},
	}
	buf = bytes.NewBuffer(nil)
	err = encodeAssetOutputList(buf, outputs, &scratch)
	require.Error(t, err)
	require.Equal(t, "unknown asset output type: 10", err.Error())

	// trigger unknown type on decode
	buf = bytes.NewBuffer(nil)
	// manually craft invalid data
	buf.Write([]byte{1})  // count = 1
	buf.Write([]byte{10}) // invalid type
	_, err = decodeAssetOutputList(buf, &scratch)
	require.Error(t, err)
	require.Equal(t, "unknown asset output type: 10", err.Error())

	// test decode with truncated data
	outputs = []AssetOutput{
		{Type: AssetTypeLocal, Vout: 1, Amount: 10},
	}
	buf = bytes.NewBuffer(nil)
	require.NoError(t, encodeAssetOutputList(buf, outputs, &scratch))
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
	outputs := []AssetOutput{
		{
			Type:   AssetTypeLocal,
			Vout:   0,
			Amount: 100,
		},
		{
			Type:   AssetTypeTeleport,
			Script: deterministicTxhash(0xEE),
			Amount: 200,
		},
	}

	var scratch [8]byte
	var buf bytes.Buffer
	require.NoError(t, encodeAssetOutputList(&buf, outputs, &scratch))

	var decoded []AssetOutput
	reader := bytes.NewReader(buf.Bytes())
	decoded, err := decodeAssetOutputList(reader, &scratch)
	require.NoError(t, err)
	require.Equal(t, outputs, decoded)
}

func TestAssetInputListEncodeDecode(t *testing.T) {
	inputs := []AssetInput{
		{
			Type:   AssetTypeLocal,
			Amount: 80,
			Vin:    1,
		},
		{
			Type:   AssetTypeTeleport,
			Vin:    0,
			Amount: 20,
			Witness: TeleportWitness{
				Script: []byte{0xde, 0xad, 0xbe, 0xef},
				Txid:   deterministicBytesArray(0x11),
				Index:  456,
			},
		},
	}

	var scratch [8]byte
	var buf bytes.Buffer
	require.NoError(t, encodeAssetInputList(&buf, inputs, &scratch))

	var decoded []AssetInput
	reader := bytes.NewReader(buf.Bytes())
	decoded, err := decodeAssetInputList(reader, &scratch)
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

	t.Run("non-empty remains", func(t *testing.T) {
		ag := AssetGroup{
			AssetId:      ptrAssetId(deterministicAssetId(0x12)),
			Outputs:      []AssetOutput{{Type: AssetTypeLocal, Amount: 10, Vout: 1}},
			ControlAsset: deterministicAssetRefId(0x3c),
			Inputs: []AssetInput{{
				Type:   AssetTypeLocal,
				Vin:    1,
				Amount: 5,
			}},
			Metadata: []Metadata{{Key: "kind", Value: "normal"}},
		}

		ag.normalizeAssetSlices()

		require.Equal(t, 1, len(ag.Outputs))
		require.Equal(t, 1, len(ag.Inputs))
		require.Equal(t, 1, len(ag.Metadata))
	})

	t.Run("empty slices become nil", func(t *testing.T) {
		ag := AssetGroup{
			AssetId: ptrAssetId(deterministicAssetId(0x13)),
			// explicitly empty slices
			Outputs:  []AssetOutput{},
			Inputs:   []AssetInput{},
			Metadata: []Metadata{},
		}

		ag.normalizeAssetSlices()

		require.Nil(t, ag.Outputs)
		require.Nil(t, ag.Inputs)
		require.Nil(t, ag.Metadata)
	})

	t.Run("nil slices remain nil and idempotent", func(t *testing.T) {
		ag := AssetGroup{
			AssetId: ptrAssetId(deterministicAssetId(0x14)),
			// nil slices
			Outputs:  nil,
			Inputs:   nil,
			Metadata: nil,
		}

		ag.normalizeAssetSlices()
		ag.normalizeAssetSlices() // idempotent

		require.Nil(t, ag.Outputs)
		require.Nil(t, ag.Inputs)
		require.Nil(t, ag.Metadata)
	})

	t.Run("preserve elements after normalize", func(t *testing.T) {
		ag := AssetGroup{
			AssetId:  ptrAssetId(deterministicAssetId(0x15)),
			Outputs:  []AssetOutput{{Type: AssetTypeLocal, Vout: 4, Amount: 44}},
			Inputs:   []AssetInput{{Type: AssetTypeLocal, Vin: 5, Amount: 55}},
			Metadata: []Metadata{{Key: "a", Value: "b"}},
		}

		ag.normalizeAssetSlices()

		require.NotNil(t, ag.Outputs)
		require.Equal(t, uint32(4), ag.Outputs[0].Vout)
		require.NotNil(t, ag.Inputs)
		require.Equal(t, uint32(5), ag.Inputs[0].Vin)
		require.NotNil(t, ag.Metadata)
		require.Equal(t, "a", ag.Metadata[0].Key)
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
