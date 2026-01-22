package extension

import (
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeSubDustPacket(t *testing.T) {
	key := deterministicPubKey(t, 0x55)
	packet := &SubDustPacket{
		Key:    &key,
		Amount: 150,
	}
	txOut, err := packet.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, txOut)

	decodedPacket, err := DecodeToSubDustPacket(txOut)
	require.NoError(t, err)
	require.NotNil(t, decodedPacket)

	// check original and decoded packet fields are equal
	require.Equal(t, packet.Amount, decodedPacket.Amount)
	require.True(t, key.IsEqual(decodedPacket.Key))

	// empty asset packet decode failure
	emptyTxOut := wire.TxOut{}
	pkt, err := DecodeToSubDustPacket(emptyTxOut)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, "OP_RETURN not present", err.Error())

	// asset packet with no opreturn prefix
	missingOpReturnTx := wire.TxOut{
		PkScript: []byte{0x01, 0x02, 0x03},
		Value:    0,
	}
	pkt, err = DecodeToSubDustPacket(missingOpReturnTx)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, "OP_RETURN not present", err.Error())

	// fail to encode empty subdust packet
	packet = &SubDustPacket{Key: nil, Amount: 0}
	txOut, err = packet.Encode()
	require.Error(t, err)
	require.Equal(t, "empty op_return packet", err.Error())
	require.Equal(t, int64(0), txOut.Value)
	require.Equal(t, 0, len(txOut.PkScript))
}
