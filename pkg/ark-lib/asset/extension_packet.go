package asset

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
)

var ArkadeMagic []byte = []byte{0x41, 0x52, 0x4B} // "ARK"

type ExtensionPacket struct {
	Asset   *AssetPacket
	SubDust *SubDustPacket
}

const (
	MarkerSubDustKey   byte = 0x01
	MarkerAssetPayload byte = 0x00
)

func (packet *ExtensionPacket) Encode() (wire.TxOut, error) {
	if packet == nil || (packet.Asset == nil && (packet.SubDust == nil || packet.SubDust.Key == nil)) {
		return wire.TxOut{}, errors.New("empty op_return packet")
	}
	// SubDust key must be present if SubDust packet is included
	if packet.SubDust != nil && packet.SubDust.Key == nil {
		return wire.TxOut{}, errors.New("subdust key missing")
	}

	var scratch [8]byte
	var tlvData bytes.Buffer
	if _, err := tlvData.Write(ArkadeMagic); err != nil {
		return wire.TxOut{}, err
	}
	if packet.SubDust != nil && packet.SubDust.Key != nil {
		if err := tlvData.WriteByte(MarkerSubDustKey); err != nil {
			return wire.TxOut{}, err
		}
		subDustKey := schnorr.SerializePubKey(packet.SubDust.Key)
		if err := tlv.WriteVarInt(&tlvData, uint64(len(subDustKey)), &scratch); err != nil {
			return wire.TxOut{}, err
		}
		if _, err := tlvData.Write(subDustKey); err != nil {
			return wire.TxOut{}, err
		}
	}
	if packet.Asset != nil {
		encodedAssets, err := encodeAssetGroups(packet.Asset.Assets)
		if err != nil {
			return wire.TxOut{}, err
		}

		// Spec does not mention a version byte in the payload value for Type 0x00.
		// "Value: Asset_Payload ... Asset_Payload: The TLV packet containing asset group data"
		// "Packet := { GroupCount, Groups }"
		// So we just write encodedAssets.

		if err := tlvData.WriteByte(MarkerAssetPayload); err != nil {
			return wire.TxOut{}, err
		}
		if err := tlv.WriteVarInt(&tlvData, uint64(len(encodedAssets)), &scratch); err != nil {
			return wire.TxOut{}, err
		}
		if _, err := tlvData.Write(encodedAssets); err != nil {
			return wire.TxOut{}, err
		}
	}

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	builder.AddFullData(tlvData.Bytes())
	opReturnPubkey, err := builder.Script()
	if err != nil {
		return wire.TxOut{}, err
	}

	var amount uint64
	if packet.SubDust != nil {
		amount = packet.SubDust.Amount
	}

	return wire.TxOut{
		Value:    int64(amount),
		PkScript: opReturnPubkey,
	}, nil
}

func DecodeToExtensionPacket(txOut wire.TxOut) (*ExtensionPacket, error) {
	opReturnData := txOut.PkScript

	if len(opReturnData) == 0 || opReturnData[0] != txscript.OP_RETURN {
		return nil, errors.New("OP_RETURN not present")
	}

	assetPayload, subDustKey, err := parsePacketOpReturn(opReturnData)
	if err != nil {
		return nil, err
	}

	packet := &ExtensionPacket{}

	if len(assetPayload) > 0 {
		assetPacket, err := decodeToAssetPacket(assetPayload)
		if err != nil {
			return nil, err
		}
		packet.Asset = assetPacket
	}

	if len(subDustKey) > 0 {
		key, err := schnorr.ParsePubKey(subDustKey)
		if err != nil {
			return nil, err
		}
		packet.SubDust = &SubDustPacket{Key: key, Amount: uint64(txOut.Value)}
	}

	if packet.Asset == nil && packet.SubDust == nil {
		return nil, errors.New("missing op_return payload")
	}

	return packet, nil
}

func IsExtensionPacket(opReturnData []byte) bool {
	asset, subdust, err := parsePacketOpReturn(opReturnData)
	return err == nil && len(asset) > 0 || len(subdust) > 0
}
