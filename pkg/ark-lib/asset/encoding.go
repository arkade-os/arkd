package asset

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	tlvTypeAssetID        tlv.Type = 1
	tlvTypeImmutable      tlv.Type = 2
	tlvTypeOutput         tlv.Type = 3
	tlvTypeControlAssetId tlv.Type = 4
	tlvTypeInput          tlv.Type = 5
	tlvTypeMetadata       tlv.Type = 6
)

func EAssetId(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*AssetId); ok {
		if err := tlv.EBytes32(w, &t.TxId, buf); err != nil {
			return err
		}
		if err := tlv.EUint32(w, &t.Index, buf); err != nil {
			return err
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "assetId")
}

func DAssetId(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*AssetId); ok && l == 36 {
		if err := tlv.DBytes32(r, &t.TxId, buf, 32); err != nil {
			return err
		}
		if err := tlv.DUint32(r, &t.Index, buf, 4); err != nil {
			return err
		}
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "assetId", l, 36)
}

func AssetIdSize(val *AssetId) tlv.SizeFunc {
	return func() uint64 {
		return 36
	}
}

func EAssetInput(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*AssetInput); ok {
		if err := tlv.EUint8(w, (*uint8)(&t.Type), buf); err != nil {
			return err
		}

		switch t.Type {
		case AssetInputTypeLocal:
			if err := tlv.EUint32(w, &t.Vin, buf); err != nil {
				return err
			}
		case AssetInputTypeTeleport:
			if err := tlv.EBytes32(w, &t.Commitment, buf); err != nil {
				return err
			}

			if t.Witness.PublicKey == nil {
				return fmt.Errorf("missing public key for teleport input")
			}
			pubKey := t.Witness.PublicKey.SerializeCompressed()
			var pubKeyArray [33]byte
			copy(pubKeyArray[:], pubKey)
			if err := tlv.EBytes33(w, &pubKeyArray, buf); err != nil {
				return err
			}
			if err := tlv.EBytes32(w, &t.Witness.Nonce, buf); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown asset input type: %d", t.Type)
		}

		if err := tlv.EUint64(w, &t.Amount, buf); err != nil {
			return err
		}

		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "assetInput")
}

func EAssetInputList(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*[]AssetInput); ok {
		for _, input := range *t {
			if err := EAssetInput(w, &input, buf); err != nil {
				return err
			}
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "assetInputList")
}

func AssetInputListSize(inputs []AssetInput) tlv.SizeFunc {
	return func() uint64 {
		var size uint64
		for _, input := range inputs {
			size += 1 // Type
			switch input.Type {
			case AssetInputTypeLocal:
				size += 4 // Vin
			case AssetInputTypeTeleport:
				size += 32 // Commitment
				size += 33 // Public Key
				size += 32 // Nonce
			}
			size += 8 // Amount
		}
		return size
	}
}

func DAssetInput(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*AssetInput); ok {
		var typ uint8
		if err := tlv.DUint8(r, &typ, buf, 1); err != nil {
			return err
		}
		t.Type = AssetInputType(typ)

		var expectedLen uint64
		switch t.Type {
		case AssetInputTypeLocal:
			expectedLen = 1 + 4 + 8 // Type + Vin + Amount
		case AssetInputTypeTeleport:
			expectedLen = 1 + 32 + 33 + 32 + 8 // Type + Commitment + Witness(Pk+Nonce) + Amount
		default:
			return fmt.Errorf("unknown asset input type: %d", t.Type)
		}

		if l != expectedLen {
			return tlv.NewTypeForDecodingErr(val, "assetInput", l, expectedLen)
		}

		switch t.Type {
		case AssetInputTypeLocal:
			if err := tlv.DUint32(r, &t.Vin, buf, 4); err != nil {
				return err
			}
		case AssetInputTypeTeleport:
			if err := tlv.DBytes32(r, &t.Commitment, buf, 32); err != nil {
				return err
			}

			var pubKeyBytes [33]byte
			if err := tlv.DBytes33(r, &pubKeyBytes, buf, 33); err != nil {
				return err
			}
			pubKey, err := btcec.ParsePubKey(pubKeyBytes[:])
			if err != nil {
				return err
			}
			t.Witness.PublicKey = pubKey

			if err := tlv.DBytes32(r, &t.Witness.Nonce, buf, 32); err != nil {
				return err
			}
		}

		if err := tlv.DUint64(r, &t.Amount, buf, 8); err != nil {
			return err
		}

		return nil
	}
	// Note: Generic error here as detailed length check is inside the function
	return tlv.NewTypeForDecodingErr(val, "assetInput", l, l)
}

func DAssetInputList(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*[]AssetInput); ok {
		if l == 0 {
			*t = nil
			return nil
		}

		data := make([]byte, l)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}

		reader := bytes.NewReader(data)
		var inputs []AssetInput

		for reader.Len() > 0 {
			startLen := reader.Len()

			typesByte, err := reader.ReadByte()
			if err != nil {
				return err
			}
			reader.UnreadByte()

			var itemLen uint64
			switch AssetInputType(typesByte) {
			case AssetInputTypeLocal:
				itemLen = 1 + 4 + 8
			case AssetInputTypeTeleport:
				itemLen = 1 + 32 + 33 + 32 + 8
			default:
				return fmt.Errorf("unknown asset input type: %d", typesByte)
			}

			if uint64(reader.Len()) < itemLen {
				return fmt.Errorf("not enough data for asset input type %d", typesByte)
			}

			var input AssetInput
			if err := DAssetInput(reader, &input, buf, itemLen); err != nil {
				return err
			}
			inputs = append(inputs, input)

			if reader.Len() >= startLen {
				return fmt.Errorf("infinite loop reading asset inputs")
			}
		}
		*t = inputs
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "assetInputList", l, l)
}

func EAssetOutput(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*AssetOutput); ok {
		if err := tlv.EUint8(w, (*uint8)(&t.Type), buf); err != nil {
			return err
		}

		switch t.Type {
		case AssetOutputTypeLocal:
			if err := tlv.EUint32(w, &t.Vout, buf); err != nil {
				return err
			}
		case AssetOutputTypeTeleport:
			if err := tlv.EBytes32(w, &t.Commitment, buf); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown asset output type: %d", t.Type)
		}

		if err := tlv.EUint64(w, &t.Amount, buf); err != nil {
			return err
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "assetOutput")
}

func AssetOutputListSize(outputs []AssetOutput) tlv.SizeFunc {
	return func() uint64 {
		var size uint64
		for _, output := range outputs {
			size += 1 // Type
			switch output.Type {
			case AssetOutputTypeLocal:
				size += 4 // Vout
			case AssetOutputTypeTeleport:
				// size += 33 // PublicKey -- Removed
				size += 32 // Commitment
			}
			size += 8 // Amount
		}
		return size
	}
}

func EAssetOutputList(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*[]AssetOutput); ok {
		for _, output := range *t {
			if err := EAssetOutput(w, &output, buf); err != nil {
				return err
			}
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "assetOutputList")
}

func DAssetOutput(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*AssetOutput); ok {
		var typ uint8
		if err := tlv.DUint8(r, &typ, buf, 1); err != nil {
			return err
		}
		t.Type = AssetOutputType(typ)

		var expectedLen uint64
		switch t.Type {
		case AssetOutputTypeLocal:
			expectedLen = 1 + 4 + 8 // Type + Vout + Amount
		case AssetOutputTypeTeleport:
			expectedLen = 1 + 32 + 8 // Type + Commitment + Amount
		default:
			return fmt.Errorf("unknown asset output type: %d", t.Type)
		}

		if l != expectedLen {
			return tlv.NewTypeForDecodingErr(val, "assetOutput", l, expectedLen)
		}

		switch t.Type {
		case AssetOutputTypeLocal:
			if err := tlv.DUint32(r, &t.Vout, buf, 4); err != nil {
				return err
			}
		case AssetOutputTypeTeleport:
			// No PublicKey read
			if err := tlv.DBytes32(r, &t.Commitment, buf, 32); err != nil {
				return err
			}
		}

		if err := tlv.DUint64(r, &t.Amount, buf, 8); err != nil {
			return err
		}
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "assetOutput", l, l)
}

func DAssetOutputList(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*[]AssetOutput); ok {
		if l == 0 {
			*t = nil
			return nil
		}

		data := make([]byte, l)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}

		reader := bytes.NewReader(data)
		var outputs []AssetOutput

		for reader.Len() > 0 {
			startLen := reader.Len()

			typeByte, err := reader.ReadByte()
			if err != nil {
				return err
			}
			reader.UnreadByte()

			var itemLen uint64
			switch AssetOutputType(typeByte) {
			case AssetOutputTypeLocal:
				itemLen = 1 + 4 + 8
			case AssetOutputTypeTeleport:
				itemLen = 1 + 32 + 8
			default:
				return fmt.Errorf("unknown asset output type: %d", typeByte)
			}

			if uint64(reader.Len()) < itemLen {
				return fmt.Errorf("not enough data for asset output type %d", typeByte)
			}

			var output AssetOutput
			if err := DAssetOutput(reader, &output, buf, itemLen); err != nil {
				return err
			}
			outputs = append(outputs, output)

			if reader.Len() >= startLen {
				return fmt.Errorf("infinite loop reading asset outputs")
			}
		}
		*t = outputs
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "assetOutputList", l, l)
}

func EMetadata(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*Metadata); ok {
		keyBytes := []byte(t.Key)
		if err := tlv.WriteVarInt(w, uint64(len(keyBytes)), buf); err != nil {
			return err
		}
		if _, err := w.Write(keyBytes); err != nil {
			return err
		}

		valueBytes := []byte(t.Value)
		if err := tlv.WriteVarInt(w, uint64(len(valueBytes)), buf); err != nil {
			return err
		}
		_, err := w.Write(valueBytes)
		return err
	}
	return tlv.NewTypeForEncodingErr(val, "metadata")
}

func DMetadata(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*Metadata); ok {
		readField := func() (string, error) {
			length, err := tlv.ReadVarInt(r, buf)
			if err != nil {
				return "", err
			}

			data := make([]byte, length)
			if _, err := io.ReadFull(r, data); err != nil {
				return "", err
			}

			return string(data), nil
		}

		key, err := readField()
		if err != nil {
			return err
		}

		value, err := readField()
		if err != nil {
			return err
		}

		t.Key = key
		t.Value = value

		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "metadata", l, l)
}

func EMetadataList(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*[]Metadata); ok {
		for _, md := range *t {
			if err := EMetadata(w, &md, buf); err != nil {
				return err
			}
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "metadataList")
}

func MetadataListSize(metadataList []Metadata) tlv.SizeFunc {
	return func() uint64 {
		var total uint64
		for _, md := range metadataList {
			keyLen := uint64(len(md.Key))
			valueLen := uint64(len(md.Value))

			total += uint64(tlv.VarIntSize(keyLen)) + keyLen
			total += uint64(tlv.VarIntSize(valueLen)) + valueLen
		}
		return total
	}
}

func DMetadataList(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*[]Metadata); ok {
		if l == 0 {
			*t = nil
			return nil
		}

		data := make([]byte, l)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}

		reader := bytes.NewReader(data)
		var metadataList []Metadata

		for reader.Len() > 0 {
			startLen := reader.Len()
			var md Metadata
			if err := DMetadata(reader, &md, buf, uint64(reader.Len())); err != nil {
				return err
			}

			if reader.Len() >= startLen {
				return tlv.NewTypeForDecodingErr(val, "metadataList", l, l)
			}

			metadataList = append(metadataList, md)
		}

		*t = metadataList
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "metadataList", l, l)
}
