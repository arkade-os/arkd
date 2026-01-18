package extension

import (
	"bytes"
	"encoding/hex"
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
	testAssetEncodeDecodeRoundTrip(t)
	testAssetGroupEncodeDecode(t)
	testAssetGroupEncodeDecodeWithSubDustKey(t)
	testAssetIdStringConversion(t)
	testAssetOutputListEncodeDecode(t)
	testAssetInputListEncodeDecode(t)
}

func testAssetEncodeDecodeRoundTrip(t *testing.T) {
	asset := AssetGroup{
		AssetId: &AssetId{
			TxHash: deterministicBytesArray(0x2a),
			Index:  0,
		},
		Outputs: []AssetOutput{
			{
				Type:   AssetTypeLocal,
				Amount: 11,
				Vout:   0,
			},
			{
				Type:   AssetTypeTeleport,
				Script: deterministicTxhash(0xcc),
				Amount: 22,
			},
		},
		ControlAsset: AssetRefFromId(AssetId{
			TxHash: deterministicBytesArray(0x3c),
			Index:  1,
		}),
		Inputs: []AssetInput{
			{
				Type:   AssetTypeLocal,
				Vin:    7,
				Amount: 20,
			},
			{
				Type:       AssetTypeTeleport,
				Vin:        2,
				Witness: TeleportWitness{
					Script:   []byte{0x00, 0x01, 0x02, 0x03},
					IntentId: deterministicBytesArray(0x55),
				},
				Amount: 40,
			},
		},
		Metadata: []Metadata{
			{Key: "purpose", Value: "roundtrip"},
			{Key: "owner", Value: "arkade"},
		},
		Immutable: true,
	}

	encoded, err := asset.EncodeTlv()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	var decoded AssetGroup

	require.NoError(t, decoded.DecodeTlv(encoded))
	require.Equal(t, asset, decoded)
}

func testAssetGroupEncodeDecode(t *testing.T) {
	controlAsset := AssetGroup{
		AssetId:      ptrAssetId(deterministicAssetId(0x11)),
		Outputs:      []AssetOutput{{Type: AssetTypeTeleport, Script: deterministicTxhash(0xdd), Amount: 1}},
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
		Assets:  []AssetGroup{controlAsset, normalAsset},
		Version: AssetVersion,
	}

	txOut, err := packet.EncodeAssetPacket()
	require.NoError(t, err)

	decodedPacket, err := DecodeAssetPacket(txOut)
	require.NoError(t, err)
	require.Equal(t, packet, *decodedPacket)
}

func testAssetGroupEncodeDecodeWithGroupIndexRef(t *testing.T) {
	t.Parallel()

	groupIndex := uint16(1)
	assetGroup := AssetGroup{
		AssetId:      ptrAssetId(deterministicAssetId(0x21)),
		ControlAsset: AssetRefFromGroupIndex(groupIndex),
		Outputs:      []AssetOutput{{Type: AssetTypeLocal, Amount: 10, Vout: 0}},
	}

	encoded, err := assetGroup.EncodeTlv()
	require.NoError(t, err)

	var decoded AssetGroup
	require.NoError(t, decoded.DecodeTlv(encoded))
	require.NotNil(t, decoded.ControlAsset)
	require.Equal(t, AssetRefByGroup, decoded.ControlAsset.Type)
	require.Equal(t, groupIndex, decoded.ControlAsset.GroupIndex)
}

func testAssetIdStringConversion(t *testing.T) {
	txid := deterministicBytesArray(0x01)
	index := uint16(12345)
	assetId := AssetId{TxHash: txid, Index: index}

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
	normalAsset := AssetGroup{
		AssetId:      ptrAssetId(deterministicAssetId(0x12)),
		Outputs:      []AssetOutput{{Type: AssetTypeLocal, Amount: 10, Vout: 1}},
		ControlAsset: deterministicAssetRefId(0xaa),
	}

	assetPacket := AssetPacket{
		Assets:  []AssetGroup{normalAsset},
		Version: AssetVersion,
	}

	opReturnPacket := &ExtensionPacket{
		Asset:   &assetPacket,
		SubDust: &SubDustPacket{Key: &subDustKey, Amount: 220},
	}

	txOut, err := opReturnPacket.EncodeExtensionPacket()
	require.NoError(t, err)
	require.True(t, ContainsAssetPacket(txOut.PkScript))

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
	require.Equal(t, AssetVersion, assetValue[0])

	decodedPacket, err := DecodeAssetPacket(txOut)
	require.NoError(t, err)
	decodedSubDust, err := DecodeSubDustPacket(txOut)
	require.NoError(t, err)
	require.NotNil(t, decodedSubDust)
	require.NotNil(t, decodedSubDust.Key)
	require.True(t, subDustKey.IsEqual(decodedSubDust.Key))
	require.Len(t, decodedPacket.Assets, 1)
	require.Equal(t, normalAsset, decodedPacket.Assets[0])
}

func testAssetOutputListEncodeDecode(t *testing.T) {
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
	require.NoError(t, EAssetOutputList(&buf, &outputs, &scratch))

	var decoded []AssetOutput
	reader := bytes.NewReader(buf.Bytes())
	require.NoError(t, DAssetOutputList(reader, &decoded, &scratch, uint64(buf.Len())))
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
			Type:       AssetTypeTeleport,
			Vin:        2,
			Amount:     20,
			Witness: TeleportWitness{
				Script:   []byte{0xde, 0xad, 0xbe, 0xef},
				IntentId: deterministicBytesArray(0x11),
			},
		},
	}

	var scratch [8]byte
	var buf bytes.Buffer
	require.NoError(t, EAssetInputList(&buf, &inputs, &scratch))

	var decoded []AssetInput
	reader := bytes.NewReader(buf.Bytes())
	require.NoError(t, DAssetInputList(reader, &decoded, &scratch, uint64(buf.Len())))
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
		TxHash: deterministicBytesArray(seed),
		Index:  0,
	}
}

func ptrAssetId(id AssetId) *AssetId {
	return &id
}

func deterministicAssetRefId(seed byte) *AssetRef {
	return AssetRefFromId(deterministicAssetId(seed))
}
