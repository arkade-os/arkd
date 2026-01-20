package extension

import (
	"bytes"
	"errors"
	"io"

	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/tlv"
)

func ContainsAssetPacket(opReturnData []byte) bool {
	payload, _, err := parsePacketOpReturn(opReturnData)
	return err == nil && len(payload) > 0
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
