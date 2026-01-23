package asset

import (
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

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
