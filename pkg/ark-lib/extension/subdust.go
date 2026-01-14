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
	opReturnPacket := &OpReturnPacket{
		SubDust: packet,
	}
	return opReturnPacket.EncodeOpReturnPacket()
}

func DecodeSubDustPacket(txOut wire.TxOut) (*SubDustPacket, error) {
	packet, err := DecodeOpReturnPacket(txOut)
	if err != nil {
		return nil, err
	}
	return packet.SubDust, nil
}
