package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	AssetTypeUnspecified AssetType = iota
	AssetTypeLocal
	AssetTypeIntent

	// Presence byte masks
	maskAssetId      uint8 = 1 << 0 // 0x01
	maskControlAsset uint8 = 1 << 1 // 0x02
	maskMetadata     uint8 = 1 << 2 // 0x04
)

type AssetType uint8

func (t AssetType) String() string {
	switch t {
	case AssetTypeLocal:
		return "local"
	case AssetTypeIntent:
		return "intent"
	default:
		return "unspecified"
	}
}

type AssetGroup struct {
	// Can be nil in case of issuance
	AssetId *AssetId
	// Can be nil if not created in a issuance
	ControlAsset *AssetRef
	// Always true
	Immutable bool
	// Can be empty in case of burn
	Outputs []AssetOutput
	// Can be empty in case of issuance
	Inputs []AssetInput
	// Used to encode extra data
	Metadata []Metadata
}

// NewAssetGroup creates a new asset group and validates it
func NewAssetGroup(
	assetId *AssetId, controlAsset *AssetRef, ins []AssetInput, outs []AssetOutput, md []Metadata,
) (*AssetGroup, error) {
	ag := AssetGroup{
		AssetId:      assetId,
		ControlAsset: controlAsset,
		Immutable:    true,
		Outputs:      outs,
		Inputs:       ins,
		Metadata:     md,
	}
	if err := ag.validate(); err != nil {
		return nil, err
	}
	return &ag, nil
}

// NewAssetGroupFromString creates a new asset group from its string serialization in hex format
func NewAssetGroupFromString(s string) (*AssetGroup, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid format, must be hex")
	}
	return NewAssetGroupFromBytes(buf)
}

// NewAssetGroupFromString creates a new asset group from its raw serialization in bytes
func NewAssetGroupFromBytes(buf []byte) (*AssetGroup, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing asset")
	}
	r := bytes.NewReader(buf)
	return newAssetGroupFromReader(r)
}

// Serialize returns the raw serialization in bytes of the asset group upon its validation
func (ag AssetGroup) Serialize() ([]byte, error) {
	if err := ag.validate(); err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(nil)
	if err := ag.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (ag AssetGroup) String() string {
	// nolint
	buf, _ := ag.Serialize()
	return hex.EncodeToString(buf)
}

func (ag AssetGroup) validate() error {
	if ag.AssetId != nil {
		if err := ag.AssetId.validate(); err != nil {
			return err
		}
	}
	if ag.ControlAsset != nil {
		if err := ag.ControlAsset.validate(); err != nil {
			return err
		}
	}
	for _, in := range ag.Inputs {
		if err := in.validate(); err != nil {
			return err
		}
	}
	for _, out := range ag.Outputs {
		if err := out.validate(); err != nil {
			return err
		}
	}
	for _, md := range ag.Metadata {
		if err := md.validate(); err != nil {
			return err
		}
	}
	if !ag.Immutable {
		return fmt.Errorf("asset must be immutable")
	}
	return nil
}

func (ag AssetGroup) serialize(w io.Writer) error {
	// 1. Calculate and write Presence Byte
	var presence uint8
	if ag.AssetId != nil {
		presence |= maskAssetId
	}
	if ag.ControlAsset != nil {
		presence |= maskControlAsset
	}
	if len(ag.Metadata) > 0 {
		presence |= maskMetadata
	}
	if _, err := w.Write([]byte{presence}); err != nil {
		return err
	}

	// 2. Write fields in fixed order based on presence

	// AssetId
	if (presence & maskAssetId) != 0 {
		if err := ag.AssetId.serialize(w); err != nil {
			return err
		}
	}

	// ControlAsset
	if (presence & maskControlAsset) != 0 {
		if err := ag.ControlAsset.serialize(w); err != nil {
			return err
		}
	}

	// Metadata
	if (presence & maskMetadata) != 0 {
		if err := metadataList(ag.Metadata).serialize(w); err != nil {
			return err
		}
	}

	// Immutable: No payload, presence bit is the value (true).

	// 3. Inputs
	if err := AssetInputs(ag.Inputs).serialize(w); err != nil {
		return err
	}

	// 4. Outputs
	if err := AssetOutputs(ag.Outputs).serialize(w); err != nil {
		return err
	}

	return nil
}

func newAssetGroupFromReader(r *bytes.Reader) (*AssetGroup, error) {
	// 1. Read Presence Byte
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	var assetId *AssetId
	var controlAsset *AssetRef
	var metadata []Metadata
	// 2. Read fields

	// AssetId
	if (presence & maskAssetId) != 0 {
		assetId, err = newAssetIdFromReader(r)
		if err != nil {
			return nil, err
		}
	}

	// ControlAsset
	if (presence & maskControlAsset) != 0 {
		controlAsset, err = newAssetRefFromReader(r)
		if err != nil {
			return nil, err
		}
	}

	// Metadata
	if (presence & maskMetadata) != 0 {
		metadata, err = newMetadataListFromReader(r)
		if err != nil {
			return nil, err
		}
	}

	// 3. Inputs
	inputs, err := newAssetInputsFromReader(r)
	if err != nil {
		return nil, err
	}

	// 4. Outputs
	outputs, err := newAssetOutputsFromReader(r)
	if err != nil {
		return nil, err
	}

	ag := AssetGroup{
		AssetId:      assetId,
		ControlAsset: controlAsset,
		Metadata:     metadata,
		Immutable:    true,
		Inputs:       inputs,
		Outputs:      outputs,
	}
	if err := ag.validate(); err != nil {
		return nil, err
	}

	return &ag, nil
}
