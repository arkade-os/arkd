package extension

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

// Presence byte masks
const (
	maskAssetId      uint8 = 1 << 0 // 0x01
	maskControlAsset uint8 = 1 << 1 // 0x02
	maskMetadata     uint8 = 1 << 2 // 0x04
	maskImmutable    uint8 = 1 << 3 // 0x08
)

func (a *AssetGroup) Encode() ([]byte, error) {
	var buf bytes.Buffer
	var scratch [8]byte

	// 1. Calculate and write Presence Byte
	var presence uint8
	if a.AssetId != nil {
		presence |= maskAssetId
	}
	if a.ControlAsset != nil {
		presence |= maskControlAsset
	}
	if len(a.Metadata) > 0 {
		presence |= maskMetadata
	}
	if a.Immutable {
		presence |= maskImmutable
	}

	if err := buf.WriteByte(presence); err != nil {
		return nil, err
	}

	// 2. Write fields in fixed order based on presence

	// AssetId
	if (presence & maskAssetId) != 0 {
		if _, err := buf.Write(a.AssetId.Txid[:]); err != nil {
			return nil, err
		}
		if err := tlv.EUint16(&buf, &a.AssetId.Index, &scratch); err != nil {
			return nil, err
		}
	}

	// ControlAsset
	if (presence & maskControlAsset) != 0 {
		if err := encodeAssetRef(&buf, a.ControlAsset, &scratch); err != nil {
			return nil, err
		}
	}

	// Metadata
	if (presence & maskMetadata) != 0 {
		if err := encodeMetadataList(&buf, a.Metadata, &scratch); err != nil {
			return nil, err
		}
	}

	// Immutable: No payload, presence bit is the value (true).

	// 3. Inputs
	if err := encodeAssetInputList(&buf, a.Inputs, &scratch); err != nil {
		return nil, err
	}

	// 4. Outputs
	if err := encodeAssetOutputList(&buf, a.Outputs, &scratch); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (a *AssetGroup) Decode(r io.Reader) error {
	var scratch [8]byte

	// 1. Read Presence Byte
	var presenceBuf [1]byte
	if _, err := io.ReadFull(r, presenceBuf[:]); err != nil {
		return err
	}
	presence := presenceBuf[0]

	// 2. Read fields

	// AssetId
	if (presence & maskAssetId) != 0 {
		a.AssetId = &AssetId{}
		if _, err := io.ReadFull(r, a.AssetId.Txid[:]); err != nil {
			return err
		}
		if err := tlv.DUint16(r, &a.AssetId.Index, &scratch, 2); err != nil {
			return err
		}
	}

	// ControlAsset
	if (presence & maskControlAsset) != 0 {
		var err error
		a.ControlAsset, err = decodeAssetRef(r, &scratch)
		if err != nil {
			return err
		}
	}

	// Metadata
	if (presence & maskMetadata) != 0 {
		var err error
		a.Metadata, err = decodeMetadataList(r, &scratch)
		if err != nil {
			return err
		}
	}

	// Immutable
	if (presence & maskImmutable) != 0 {
		a.Immutable = true
	} else {
		a.Immutable = false
	}

	// 3. Inputs
	var err error
	a.Inputs, err = decodeAssetInputList(r, &scratch)
	if err != nil {
		return err
	}

	// 4. Outputs
	a.Outputs, err = decodeAssetOutputList(r, &scratch)
	if err != nil {
		return err
	}

	return nil
}

func encodeAssetRef(w io.Writer, ref *AssetRef, scratch *[8]byte) error {
	if _, err := w.Write([]byte{byte(ref.Type)}); err != nil {
		return err
	}
	switch ref.Type {
	case AssetRefByID:
		if _, err := w.Write(ref.AssetId.Txid[:]); err != nil {
			return err
		}
		if err := tlv.EUint16(w, &ref.AssetId.Index, scratch); err != nil {
			return err
		}
	case AssetRefByGroup:
		if err := tlv.EUint16(w, &ref.GroupIndex, scratch); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown asset ref type: %d", ref.Type)
	}
	return nil
}

func decodeAssetRef(r io.Reader, scratch *[8]byte) (*AssetRef, error) {
	var typBuf [1]byte
	if _, err := io.ReadFull(r, typBuf[:]); err != nil {
		return nil, err
	}
	typ := AssetRefType(typBuf[0])

	ref := &AssetRef{Type: typ}
	switch typ {
	case AssetRefByID:
		if _, err := io.ReadFull(r, ref.AssetId.Txid[:]); err != nil {
			return nil, err
		}
		if err := tlv.DUint16(r, &ref.AssetId.Index, scratch, 2); err != nil {
			return nil, err
		}
	case AssetRefByGroup:
		if err := tlv.DUint16(r, &ref.GroupIndex, scratch, 2); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown asset ref type: %d", typ)
	}
	return ref, nil
}

func encodeMetadataList(w io.Writer, meta []Metadata, scratch *[8]byte) error {
	if err := tlv.WriteVarInt(w, uint64(len(meta)), scratch); err != nil {
		return err
	}
	for _, m := range meta {
		keyBytes := []byte(m.Key)
		valBytes := []byte(m.Value)

		if err := tlv.WriteVarInt(w, uint64(len(keyBytes)), scratch); err != nil {
			return err
		}
		if _, err := w.Write(keyBytes); err != nil {
			return err
		}
		if err := tlv.WriteVarInt(w, uint64(len(valBytes)), scratch); err != nil {
			return err
		}
		if _, err := w.Write(valBytes); err != nil {
			return err
		}
	}
	return nil
}

func decodeMetadataList(r io.Reader, scratch *[8]byte) ([]Metadata, error) {
	count, err := tlv.ReadVarInt(r, scratch)
	if err != nil {
		return nil, err
	}

	meta := make([]Metadata, count)
	for i := uint64(0); i < count; i++ {
		// Key
		kLen, err := tlv.ReadVarInt(r, scratch)
		if err != nil {
			return nil, err
		}
		kBytes := make([]byte, kLen)
		if _, err := io.ReadFull(r, kBytes); err != nil {
			return nil, err
		}

		// Value
		vLen, err := tlv.ReadVarInt(r, scratch)
		if err != nil {
			return nil, err
		}
		vBytes := make([]byte, vLen)
		if _, err := io.ReadFull(r, vBytes); err != nil {
			return nil, err
		}

		meta[i] = Metadata{Key: string(kBytes), Value: string(vBytes)}
	}
	return meta, nil
}

func encodeAssetInputList(w io.Writer, inputs []AssetInput, scratch *[8]byte) error {
	if err := tlv.WriteVarInt(w, uint64(len(inputs)), scratch); err != nil {
		return err
	}
	for _, in := range inputs {
		if _, err := w.Write([]byte{byte(in.Type)}); err != nil {
			return err
		}
		switch in.Type {
		case AssetTypeLocal:
			if err := tlv.EUint32(w, &in.Vin, scratch); err != nil {
				return err
			}
			if err := tlv.EUint64(w, &in.Amount, scratch); err != nil {
				return err
			}
		case AssetTypeIntent:
			if err := tlv.EUint64(w, &in.Amount, scratch); err != nil {
				return err
			}
			if _, err := w.Write(in.Txid[:]); err != nil {
				return err
			}

			if err := tlv.EUint32(w, &in.Vin, scratch); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown asset input type: %d", in.Type)
		}
	}
	return nil
}

func decodeAssetInputList(r io.Reader, scratch *[8]byte) ([]AssetInput, error) {
	count, err := tlv.ReadVarInt(r, scratch)
	if err != nil {
		return nil, err
	}
	inputs := make([]AssetInput, count)
	for i := uint64(0); i < count; i++ {
		var typBuf [1]byte
		if _, err := io.ReadFull(r, typBuf[:]); err != nil {
			return nil, err
		}
		inputs[i].Type = AssetType(typBuf[0])

		switch inputs[i].Type {
		case AssetTypeLocal:
			if err := tlv.DUint32(r, &inputs[i].Vin, scratch, 4); err != nil {
				return nil, err
			}
			if err := tlv.DUint64(r, &inputs[i].Amount, scratch, 8); err != nil {
				return nil, err
			}
		case AssetTypeIntent:
			inputs[i].Type = AssetTypeIntent
			if err := tlv.DUint64(r, &inputs[i].Amount, scratch, 8); err != nil {
				return nil, err
			}
			if _, err := io.ReadFull(r, inputs[i].Txid[:]); err != nil {
				return nil, err
			}

			// Index
			if err := tlv.DUint32(r, &inputs[i].Vin, scratch, 4); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown asset input type: %d", inputs[i].Type)
		}
	}
	return inputs, nil
}

func encodeAssetOutputList(w io.Writer, outputs []AssetOutput, scratch *[8]byte) error {
	if err := tlv.WriteVarInt(w, uint64(len(outputs)), scratch); err != nil {
		return err
	}
	for _, out := range outputs {
		if _, err := w.Write([]byte{byte(out.Type)}); err != nil {
			return err
		}
		switch out.Type {
		case AssetTypeLocal:
			if err := tlv.EUint32(w, &out.Vout, scratch); err != nil {
				return err
			}
			if err := tlv.EUint64(w, &out.Amount, scratch); err != nil {
				return err
			}
		case AssetTypeIntent:
			if err := tlv.EUint64(w, &out.Amount, scratch); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown asset output type: %d", out.Type)
		}
	}
	return nil
}

func decodeAssetOutputList(r io.Reader, scratch *[8]byte) ([]AssetOutput, error) {
	count, err := tlv.ReadVarInt(r, scratch)
	if err != nil {
		return nil, err
	}
	outputs := make([]AssetOutput, count)
	for i := uint64(0); i < count; i++ {
		var typBuf [1]byte
		if _, err := io.ReadFull(r, typBuf[:]); err != nil {
			return nil, err
		}
		outputs[i].Type = AssetType(typBuf[0])

		switch outputs[i].Type {
		case AssetTypeLocal:
			if err := tlv.DUint32(r, &outputs[i].Vout, scratch, 4); err != nil {
				return nil, err
			}
			if err := tlv.DUint64(r, &outputs[i].Amount, scratch, 8); err != nil {
				return nil, err
			}
		case AssetTypeIntent:
			if err := tlv.DUint64(r, &outputs[i].Amount, scratch, 8); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown asset output type: %d", outputs[i].Type)
		}
	}
	return outputs, nil
}
