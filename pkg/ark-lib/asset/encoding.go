package asset

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	tlvTypeAssetID         tlv.Type = 1
	tlvTypeOutput          tlv.Type = 2
	tlvTypeControlAssetId  tlv.Type = 3
	tlvTypeInput           tlv.Type = 4
	tlvTypeMetadata        tlv.Type = 6
	tlvTypeOutScriptPubKey tlv.Type = 7
	tlvTypeInTxid          tlv.Type = 8
	tlvTypeOutAmount       tlv.Type = 9
	tlvTypeInVout          tlv.Type = 10
	tlvTypeImmutable       tlv.Type = 11
)

func EAssetInput(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*AssetInput); ok {
		if len(t.Txhash) != 32 {
			return fmt.Errorf("txhash must be 32 bytes, got %d", len(t.Txhash))
		}

		var txhash [32]byte
		copy(txhash[:], t.Txhash)

		if err := tlv.EBytes32(w, &txhash, buf); err != nil {
			return err
		}
		if err := tlv.EUint32(w, &t.Vout, buf); err != nil {
			return err
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

func AssetInputListSize(l int) tlv.SizeFunc {
	return func() uint64 {
		return uint64(l) * 44
	}
}

func DAssetInput(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*AssetInput); ok && l == 44 {
		var txhash [32]byte
		if err := tlv.DBytes32(r, &txhash, buf, 32); err != nil {
			return err
		}
		t.Txhash = make([]byte, 32)
		copy(t.Txhash, txhash[:])

		if err := tlv.DUint32(r, &t.Vout, buf, 4); err != nil {
			return err
		}
		if err := tlv.DUint64(r, &t.Amount, buf, 8); err != nil {
			return err
		}

		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "assetInput", l, 44)
}

func DAssetInputList(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*[]AssetInput); ok {
		if l%44 != 0 {
			return tlv.NewTypeForDecodingErr(val, "assetInputList", l, 44)
		}
		numInputs := int(l / 44)
		*t = make([]AssetInput, numInputs)
		for i := 0; i < numInputs; i++ {
			if err := DAssetInput(r, &(*t)[i], buf, 44); err != nil {
				return err
			}
		}
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "assetInputList", l, 44)
}

func EAssetOutput(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*AssetOutput); ok {
		pk := &t.PublicKey
		if err := tlv.EPubKey(w, &pk, buf); err != nil {
			return err
		}
		if err := tlv.EUint32(w, &t.Vout, buf); err != nil {
			return err
		}

		if err := tlv.EUint64(w, &t.Amount, buf); err != nil {
			return err
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "assetOutput")
}

func AssetOutputListSize(l int) tlv.SizeFunc {
	return func() uint64 {
		return uint64(l) * 45
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
	if t, ok := val.(*AssetOutput); ok && l == 45 {
		var pk *btcec.PublicKey
		if err := tlv.DPubKey(r, &pk, buf, 33); err != nil {
			return err
		}
		t.PublicKey = *pk

		if err := tlv.DUint32(r, &t.Vout, buf, 4); err != nil {
			return err
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
		if l%45 != 0 {
			return tlv.NewTypeForDecodingErr(val, "assetOutputList", l, 45)
		}
		numOutputs := int(l / 45)
		*t = make([]AssetOutput, numOutputs)
		for i := 0; i < numOutputs; i++ {
			if err := DAssetOutput(r, &(*t)[i], buf, 45); err != nil {
				return err
			}
		}
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
