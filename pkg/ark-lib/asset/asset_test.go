package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var charset = "0123456789"
var maxUint16 = 65535

func RandTxHash() [TX_HASH_SIZE]byte {
	var txh [TX_HASH_SIZE]byte
	for i := 0; i < TX_HASH_SIZE; i++ {
		txh[i] = charset[rand.Intn(len(charset))]
	}
	return txh
}

func RandIndex() uint16 {
	return uint16(rand.Intn(maxUint16))
}

func TestAssetId_Roundtrip(t *testing.T) {
	assetId := AssetId{
		Txid:  RandTxHash(),
		Index: RandIndex(),
	}

	assetString := assetId.ToString()
	require.Equal(t, ASSET_ID_SIZE*2, len(assetString))

	derivedAssetId, err := AssetIdFromString(assetString)
	require.NoError(t, err)
	require.Equal(t, assetId.Index, derivedAssetId.Index)
	require.Equal(t, assetId.Txid, derivedAssetId.Txid)
}

func TestAssetIdFromString_InvalidLength(t *testing.T) {
	shortString := "0123"
	// hex encoding means string length is double the byte length
	shortLen := len(shortString) / 2
	assetId, err := AssetIdFromString(shortString)
	require.Error(t, err)
	require.Equal(t, fmt.Sprintf("invalid asset id length: %d", shortLen), err.Error())
	require.Nil(t, assetId)
}



func TestEncodeDecodeAssetPacket(t *testing.T) {
	packet := &AssetPacket{
		Assets: []AssetGroup{controlAsset, normalAsset},
	}
	txOut, err := packet.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, txOut)

	decodedPacket, err := DecodeOutputToAssetPacket(txOut)
	require.NoError(t, err)

	// check original and decoded packet fields are equal
	require.Equal(t, packet.Version, decodedPacket.Version)
	require.Equal(t, len(packet.Assets), len(decodedPacket.Assets))
	require.True(t, assetGroupsEqual(packet.Assets, decodedPacket.Assets))

	// fail to encode empty asset packet
	emptyPacket := &AssetPacket{
		Assets: []AssetGroup{},
	}

	wireTx, err := emptyPacket.Encode()
	require.Error(t, err)
	require.Equal(t, "cannot encode empty asset group", err.Error())
	require.Equal(t, int64(0), wireTx.Value)
	require.Equal(t, 0, len(wireTx.PkScript))

	// empty asset packet decode failure
	emptyTxOut := wire.TxOut{}
	pkt, err := DecodeOutputToAssetPacket(emptyTxOut)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, "OP_RETURN not present", err.Error())

	// asset packet with no opreturn prefix
	missingOpReturnTx := wire.TxOut{
		PkScript: []byte{0x01, 0x02, 0x03},
		Value:    0,
	}
	pkt, err = DecodeOutputToAssetPacket(missingOpReturnTx)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, "OP_RETURN not present", err.Error())
}

func TestDeriveAssetPacketFromTx(t *testing.T) {
	empty := wire.MsgTx{}
	packet, idx, err := DeriveAssetPacketFromTx(empty)
	require.Error(t, err)
	require.Equal(t, "no asset opreturn found in transaction", err.Error())
	require.Nil(t, packet)
	require.Equal(t, 0, idx)

	arkTxNoAssetPackets := wire.MsgTx{
		TxOut: []*wire.TxOut{
			{Value: int64(1000)},
		},
	}
	packet, idx, err = DeriveAssetPacketFromTx(arkTxNoAssetPackets)
	require.Error(t, err)
	require.Equal(t, "no asset opreturn found in transaction", err.Error())
	require.Nil(t, packet)
	require.Equal(t, 0, idx)

	arkTxWithAssetPacket := wire.MsgTx{
		TxOut: []*wire.TxOut{
			{Value: int64(1000), PkScript: []byte{0x6a, 0x01, 0x02}},
		},
	}
	packet, idx, err = DeriveAssetPacketFromTx(arkTxWithAssetPacket)
	require.Error(t, err)
	require.Equal(t, "no asset opreturn found in transaction", err.Error())
	require.Nil(t, packet)
	require.Equal(t, 0, idx)

	// check valid asset packet
	packet = &AssetPacket{
		Assets: []AssetGroup{controlAsset, normalAsset},
	}
	txOut, err := packet.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, txOut)

	badMagicScript := append([]byte{0x6a}, ArkadeMagic...)
	arkTxWithAssetPacket = wire.MsgTx{
		TxOut: []*wire.TxOut{
			{Value: int64(1000), PkScript: []byte{0x00, 0x01}},
			&txOut,
			{Value: int64(2000), PkScript: []byte{0x6a, 0x02, 0x03}},
			{Value: int64(2000), PkScript: badMagicScript},
			&txOut,
		},
	}
	packet, idx, err = DeriveAssetPacketFromTx(arkTxWithAssetPacket)
	require.NoError(t, err)
	require.NotNil(t, packet)
	// should find first valid asset packet at index 1, second TxOut
	// with valid asset packet is at index 4 but is never reached
	require.Equal(t, 1, idx)
	require.True(t, assetGroupsEqual(packet.Assets, []AssetGroup{controlAsset, normalAsset}))
}

func TestAssetIdStringConversion(t *testing.T) {
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



// helper function to deep equal compare []AssetGroup slices
func assetGroupsEqual(a, b []AssetGroup) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i].AssetId == nil) != (b[i].AssetId == nil) {
			return false
		}
		// check each field in the AssetId matches
		if a[i].AssetId != nil && b[i].AssetId != nil {
			if a[i].AssetId.Index != b[i].AssetId.Index {
				return false
			}
			if a[i].AssetId.Txid != b[i].AssetId.Txid {
				return false
			}
		}
		if a[i].Immutable != b[i].Immutable {
			return false
		}
		// check each field in the Outputs slice match
		if len(a[i].Outputs) != len(b[i].Outputs) {
			return false
		}
		for idx, o := range a[i].Outputs {
			if o.Type != b[i].Outputs[idx].Type ||
				o.Vout != b[i].Outputs[idx].Vout ||
				len(o.Script) != len(b[i].Outputs[idx].Script) ||
				bytes.Equal(o.Script, b[i].Outputs[idx].Script) == false ||
				o.Amount != b[i].Outputs[idx].Amount {
				return false
			}
		}
		// check each ControlAsset field matches
		if (a[i].ControlAsset == nil) != (b[i].ControlAsset == nil) {
			return false
		}
		if a[i].ControlAsset != nil && b[i].ControlAsset != nil {
			if a[i].ControlAsset.Type != b[i].ControlAsset.Type ||
				a[i].ControlAsset.GroupIndex != b[i].ControlAsset.GroupIndex ||
				a[i].ControlAsset.AssetId != b[i].ControlAsset.AssetId {
				return false
			}
		}
		// check each field in the Inputs slice match
		if len(a[i].Inputs) != len(b[i].Inputs) {
			return false
		}
		for idx, in := range a[i].Inputs {
			if in.Type != b[i].Inputs[idx].Type ||
				in.Vin != b[i].Inputs[idx].Vin ||
				// check Witness fields
				len(in.Witness.Script) != len(b[i].Inputs[idx].Witness.Script) ||
				bytes.Equal(in.Witness.Script, b[i].Inputs[idx].Witness.Script) == false ||
				len(in.Witness.Txid) != len(b[i].Inputs[idx].Witness.Txid) ||
				bytes.Equal(in.Witness.Txid[:], b[i].Inputs[idx].Witness.Txid[:]) == false ||
				in.Amount != b[i].Inputs[idx].Amount {
				return false
			}
		}
		// check each field in the Metadata slice match
		if len(a[i].Metadata) != len(b[i].Metadata) {
			return false
		}
		for idx, md := range a[i].Metadata {
			if md.Key != b[i].Metadata[idx].Key ||
				md.Value != b[i].Metadata[idx].Value {
				return false
			}
		}
	}
	return true
}
