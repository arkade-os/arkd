package extension

import (
	"bytes"
	"errors"
	"io"

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

func (packet *ExtensionPacket) EncodeExtensionPacket() (wire.TxOut, error) {
	if packet == nil || (packet.Asset == nil && (packet.SubDust == nil || packet.SubDust.Key == nil)) {
		return wire.TxOut{}, errors.New("empty op_return packet")
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
		encodedAssets, err := encodeAssetPacket(packet.Asset.Assets)
		if err != nil {
			return wire.TxOut{}, err
		}

		version := packet.Asset.Version
		if version == 0 {
			version = AssetVersion
		}

		assetData := append([]byte{version}, encodedAssets...)

		if err := tlvData.WriteByte(MarkerAssetPayload); err != nil {
			return wire.TxOut{}, err
		}
		if err := tlv.WriteVarInt(&tlvData, uint64(len(assetData)), &scratch); err != nil {
			return wire.TxOut{}, err
		}
		if _, err := tlvData.Write(assetData); err != nil {
			return wire.TxOut{}, err
		}
	}

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	builder.AddFullData(tlvData.Bytes())
	opReturnPubkey, err := builder.Script()
	if err != nil {
		return wire.TxOut{}, err
	}

	var amount uint64 = 0
	if packet.SubDust != nil {
		amount = packet.SubDust.Amount
	}

	return wire.TxOut{
		Value:    int64(amount),
		PkScript: opReturnPubkey,
	}, nil
}

func DecodeExtensionPacket(txOut wire.TxOut) (*ExtensionPacket, error) {
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
		version := assetPayload[0]
		payload := assetPayload[1:]

		assetPacket, err := decodeAssetPacket(payload, version)
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

// parsePacketOpReturn extracts the asset payload and optional sub-dust pubkey from an OP_RETURN script.
// (OP_RETURN <type><length><value> <type><length><value> ...).
func parsePacketOpReturn(opReturnData []byte) ([]byte, []byte, error) {
	if len(opReturnData) == 0 || opReturnData[0] != txscript.OP_RETURN {
		return nil, nil, errors.New("OP_RETURN not present")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, opReturnData)
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_RETURN {
		if err := tokenizer.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("invalid OP_RETURN script")
	}

	var payload []byte

	for tokenizer.Next() {
		data := tokenizer.Data()
		if data == nil {
			return nil, nil, errors.New("invalid OP_RETURN data push")
		}

		payload = append(payload, data...)
	}

	if err := tokenizer.Err(); err != nil {
		return nil, nil, err
	}

	if len(payload) == 0 {
		return nil, nil, errors.New("missing OP_RETURN payload")
	}

	if len(payload) < len(ArkadeMagic) || !bytes.HasPrefix(payload, ArkadeMagic) {
		return nil, nil, errors.New("invalid op_return payload magic")
	}

	payload = payload[len(ArkadeMagic):]

	var subDustKey []byte
	var assetPayload []byte
	reader := bytes.NewReader(payload)
	var scratch [8]byte

	for reader.Len() > 0 {
		typ, err := reader.ReadByte()
		if err != nil {
			return nil, nil, err
		}

		length, err := tlv.ReadVarInt(reader, &scratch)
		if err != nil {
			return nil, nil, err
		}
		if uint64(reader.Len()) < length {
			return nil, nil, errors.New("invalid TLV length for OP_RETURN payload")
		}

		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, nil, err
		}

		switch typ {
		case MarkerSubDustKey:
			if subDustKey == nil {
				subDustKey = value
			}
		case MarkerAssetPayload:
			if assetPayload == nil {
				assetPayload = value
			}
		}
	}

	if len(assetPayload) == 0 && len(subDustKey) == 0 {
		return nil, nil, errors.New("missing op_return payload")
	}

	return assetPayload, subDustKey, nil
}

func normalizeAssetSlices(a *AssetGroup) {
	if len(a.Inputs) == 0 {
		a.Inputs = nil
	}
	if len(a.Outputs) == 0 {
		a.Outputs = nil
	}
	if len(a.Metadata) == 0 {
		a.Metadata = nil
	}
}
