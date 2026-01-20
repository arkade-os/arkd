package extension

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

type AssetGroup struct {
	AssetId      *AssetId
	Immutable    bool
	Outputs      []AssetOutput
	ControlAsset *AssetRef
	Inputs       []AssetInput
	Metadata     []Metadata
}

func (a *AssetGroup) Encode() ([]byte, error) {
	if a == nil {
		return nil, errors.New("cannot encode nil AssetGroup")
	}
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
		if _, err := buf.Write(a.AssetId.TxHash[:]); err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint16(scratch[:2], a.AssetId.Index)
		if _, err := buf.Write(scratch[:2]); err != nil {
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
		if _, err := io.ReadFull(r, a.AssetId.TxHash[:]); err != nil {
			return err
		}
		if _, err := io.ReadFull(r, scratch[:2]); err != nil {
			return err
		}
		a.AssetId.Index = binary.BigEndian.Uint16(scratch[:2])
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

func (a *AssetGroup) normalizeAssetSlices() {
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
