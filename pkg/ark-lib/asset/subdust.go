package asset

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
)

type SubDustPacket struct {
	Key    *btcec.PublicKey
	Amount uint64
}

func (packet *SubDustPacket) Encode() (wire.TxOut, error) {
	opReturnPacket := &ExtensionPacket{
		SubDust: packet,
	}
	return opReturnPacket.Encode()
}

func DecodeToSubDustPacket(txOut wire.TxOut) (*SubDustPacket, error) {
	packet, err := DecodeToExtensionPacket(txOut)
	if err != nil {
		return nil, err
	}
	if packet.SubDust == nil {
		return nil, errors.New("missing subdust payload")
	}
	return packet.SubDust, nil
}
