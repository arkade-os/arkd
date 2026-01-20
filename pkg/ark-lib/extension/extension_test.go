package extension

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

func TestExtension(t *testing.T) {
	t.Parallel()
	t.Run("AssetEncodeDecodeRoundTrip", testAssetEncodeDecodeRoundTrip)
	t.Run("AssetGroupEncodeDecode", testAssetGroupEncodeDecode)
	t.Run("AssetGroupEncodeDecodeWithSubDustKey", testAssetGroupEncodeDecodeWithSubDustKey)
	t.Run("AssetIdStringConversion", testAssetIdStringConversion)
	t.Run("AssetOutputListEncodeDecode", testAssetOutputListEncodeDecode)
	t.Run("AssetInputListEncodeDecode", testAssetInputListEncodeDecode)
	t.Run("AssetGroupEncodeDecodeWithGroupIndexRef", testAssetGroupEncodeDecodeWithGroupIndexRef)
}

var (
	controlAsset = AssetGroup{
		AssetId:      ptrAssetId(deterministicAssetId(0x11)),
		Outputs:      []AssetOutput{{Type: AssetTypeTeleport, Script: deterministicTxhash(0xdd), Amount: 1}},
		ControlAsset: deterministicAssetRefId(0x3c),
		Metadata:     []Metadata{{Key: "kind", Value: "control"}},
	}
	normalAsset = AssetGroup{
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
)

func testAssetEncodeDecodeRoundTrip(t *testing.T) {
	asset := AssetGroup{
		AssetId: &AssetId{
			Txid:  deterministicBytesArray(0x3c),
			Index: 2,
		},
		Outputs: []AssetOutput{
			{
				Type:   AssetTypeLocal,
				Amount: 11,
				Vout:   0,
			},
			{
				Type:   AssetTypeIntent,
				Amount: 22,
			},
		},
		ControlAsset: AssetRefFromId(AssetId{
			Txid:  deterministicBytesArray(0x3c),
			Index: 1,
		}),
		Inputs: []AssetInput{
			{
				Type:   AssetTypeLocal,
				Vin:    7,
				Amount: 20,
			},
			{
				Type: AssetTypeIntent,
				// Vin is not encoded for Intent inputs
				Vin:    123,
				Txid:   deterministicBytesArray(0x55),
				Amount: 40,
			},
		},
		Metadata: []Metadata{
			{Key: "purpose", Value: "roundtrip"},
			{Key: "owner", Value: "arkade"},
		},
		Immutable: true,
	}

	encoded, err := asset.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	var decoded AssetGroup

	require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))
	require.Equal(t, asset, decoded)

	var nilAssetGroup *AssetGroup
	_, err = nilAssetGroup.Encode()
	require.Error(t, err)
	require.Equal(t, "cannot encode nil AssetGroup", fmt.Sprint(err))
}

func testAssetGroupEncodeDecode(t *testing.T) {
	controlAsset := AssetGroup{
		AssetId:      ptrAssetId(deterministicAssetId(0x11)),
		Outputs:      []AssetOutput{{Type: AssetTypeIntent, Amount: 1}},
		ControlAsset: deterministicAssetRefId(0x3c),
		Metadata:     []Metadata{{Key: "kind", Value: "control"}},
	}

	normalAsset := AssetGroup{
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

func testAssetGroupEncodeDecodeWithGroupIndexRef(t *testing.T) {
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
	fmt.Printf("check spot -\n")
}

func testAssetIdStringConversion(t *testing.T) {
	txid := deterministicBytesArray(0x01)
	index := uint16(12345)
	assetId := AssetId{Txid: txid, Index: index}

	s := assetId.ToString()
	decoded, err := AssetIdFromString(s)
	require.NoError(t, err)
	require.Equal(t, &assetId, decoded)

	// Test invalid hex
	_, err = AssetIdFromString("invalid")
	require.Error(t, err)

	// Test invalid length
	_, err = AssetIdFromString(hex.EncodeToString(make([]byte, 35)))
	require.Error(t, err)
}

func testAssetGroupEncodeDecodeWithSubDustKey(t *testing.T) {
	subDustKey := deterministicPubKey(t, 0x55)
	assetPacket := AssetPacket{
		Assets: []AssetGroup{normalAsset},
	}

	opReturnPacket := &ExtensionPacket{
		Asset:   &assetPacket,
		SubDust: &SubDustPacket{Key: &subDustKey, Amount: 220},
	}

	txOut, err := opReturnPacket.Encode()
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

func testAssetOutputListEncodeDecode(t *testing.T) {
	outputs := []AssetOutput{
		{
			Type:   AssetTypeLocal,
			Vout:   0,
			Amount: 100,
		},
		{
			Type:   AssetTypeIntent,
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

func testAssetInputListEncodeDecode(t *testing.T) {
	inputs := []AssetInput{
		{
			Type:   AssetTypeLocal,
			Amount: 80,
			Vin:    1,
		},
		{
			Type:   AssetTypeIntent,
			Vin:    456,
			Txid:   deterministicBytesArray(0x11),
			Amount: 20,
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
