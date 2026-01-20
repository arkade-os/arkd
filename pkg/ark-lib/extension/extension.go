package extension

import (
	"bytes"
	"errors"
	"fmt"
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
		assetPacket, err := decodeAssetPacket(assetPayload)
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
func parsePacketOpReturn(opReturnData []byte) (assetPayload []byte, subDustKey []byte, err error) {
	if len(opReturnData) == 0 || opReturnData[0] != txscript.OP_RETURN {
		return nil, nil, errors.New("OP_RETURN not present")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, opReturnData)
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_RETURN {
		if err = tokenizer.Err(); err != nil {
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

	if err = tokenizer.Err(); err != nil {
		return nil, nil, err
	}

	if len(payload) == 0 {
		return nil, nil, errors.New("missing OP_RETURN payload")
	}

	if len(payload) < len(ArkadeMagic) || !bytes.HasPrefix(payload, ArkadeMagic) {
		return nil, nil, errors.New("invalid op_return payload magic")
	}

	payload = payload[len(ArkadeMagic):]

	reader := bytes.NewReader(payload)
	var scratch [8]byte

	for reader.Len() > 0 {
		typ, readErr := reader.ReadByte()
		if readErr != nil {
			return nil, nil, readErr
		}

		length, readVarErr := tlv.ReadVarInt(reader, &scratch)
		if readVarErr != nil {
			return nil, nil, readVarErr
		}
		if uint64(reader.Len()) < length {
			return nil, nil, errors.New("invalid TLV length for OP_RETURN payload")
		}

		value := make([]byte, length)
		if _, readFullErr := io.ReadFull(reader, value); readFullErr != nil {
			return nil, nil, readFullErr
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

func encodeAssetPacket(assets []AssetGroup) ([]byte, error) {
	var scratch [8]byte
	var buf bytes.Buffer

	totalCount := uint64(len(assets))
	if totalCount == 0 {
		return nil, errors.New("cannot encode empty asset group")
	}

	if err := tlv.WriteVarInt(&buf, totalCount, &scratch); err != nil {
		return nil, err
	}

	for _, asset := range assets {
		encodedAsset, err := asset.Encode()
		if err != nil {
			return nil, err
		}

		// No length prefix, groups are self-delimiting/known
		if _, err := buf.Write(encodedAsset); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func decodeAssetPacket(payload []byte) (*AssetPacket, error) {
	reader := bytes.NewReader(payload)
	var scratch [8]byte

	assetCount, err := tlv.ReadVarInt(reader, &scratch)
	if err != nil {
		return nil, fmt.Errorf("invalid asset group count: %w", err)
	}

	if assetCount == 0 {
		return nil, errors.New("empty asset group")
	}

	assets := make([]AssetGroup, 0, int(assetCount))
	for i := uint64(0); i < assetCount; i++ {
		var decoded AssetGroup
		if err := decoded.Decode(reader); err != nil {
			return nil, fmt.Errorf("failed to decode asset group %d: %w", i, err)
		}

		assets = append(assets, decoded)
	}

	for i := range assets {
		ag := &assets[i]
		ag.normalizeAssetSlices()
	}

	if reader.Len() != 0 {
		return nil, errors.New("unexpected trailing bytes in asset group payload")
	}

	group := &AssetPacket{
		Assets: assets,
	}

	return group, nil
}
