package extension

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
)

type SubDustPacket struct {
	Key    *btcec.PublicKey
	Amount uint64
}

func (packet *SubDustPacket) EncodeSubDustPacket() (wire.TxOut, error) {
	opReturnPacket := &ExtensionPacket{
		SubDust: packet,
	}
	return opReturnPacket.EncodeExtensionPacket()
}

func DecodeSubDustPacket(txOut wire.TxOut) (*SubDustPacket, error) {
	packet, err := DecodeExtensionPacket(txOut)
	if err != nil {
		return nil, err
	}
	return packet.SubDust, nil
}
