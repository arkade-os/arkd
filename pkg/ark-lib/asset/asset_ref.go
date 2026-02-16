package asset

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// AssetRefType indicates how an asset reference resolves to an asset.
type AssetRefType uint8

const (
	// AssetRefUnspecified is the zero value, representing an invalid reference type.
	AssetRefUnspecified AssetRefType = iota
	// AssetRefByID references an asset by its full AssetId.
	AssetRefByID
	// AssetRefByGroup references an asset by its group index within the same packet.
	AssetRefByGroup
)

// AssetRef is a polymorphic reference to an asset, either by its full AssetId
// or by the group index within the same packet.
type AssetRef struct {
	// Type indicates how the asset is referenced (by ID or by group index).
	Type AssetRefType
	// AssetId is the full asset identifier, populated when Type is AssetRefByID.
	AssetId AssetId
	// GroupIndex is the index of the asset group within the same packet, populated when Type is AssetRefByGroup.
	GroupIndex uint16
}

// NewAssetRefFromId creates an AssetRef that references an asset by its full AssetId.
func NewAssetRefFromId(assetId AssetId) (*AssetRef, error) {
	ref := AssetRef{Type: AssetRefByID, AssetId: assetId}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	return &ref, nil
}

// NewAssetRefFromGroupIndex creates an AssetRef that references an asset by its group index
// within the same packet.
func NewAssetRefFromGroupIndex(groupIndex uint16) (*AssetRef, error) {
	ref := AssetRef{Type: AssetRefByGroup, GroupIndex: groupIndex}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	return &ref, nil
}

// NewAssetRefFromString parses a hex-encoded string into an AssetRef.
func NewAssetRefFromString(s string) (*AssetRef, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset ref format, must be hex")
	}
	return NewAssetRefFromBytes(buf)
}

// NewAssetRefFromBytes deserializes an AssetRef from a raw byte slice.
func NewAssetRefFromBytes(buf []byte) (*AssetRef, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing asset ref")
	}
	r := bytes.NewReader(buf)
	return newAssetRefFromReader(r)
}

// Serialize encodes the AssetRef into a byte slice.
func (ref AssetRef) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := ref.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized AssetRef.
func (ref AssetRef) String() string {
	// nolint
	buf, _ := ref.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks that the AssetRef has a valid type and, when referenced by ID,
// that the underlying AssetId is valid.
func (ref AssetRef) validate() error {
	switch ref.Type {
	case AssetRefByID:
		return ref.AssetId.validate()
	case AssetRefByGroup:
		// nothing to do
		return nil
	case AssetRefUnspecified:
		return fmt.Errorf("asset ref type unspecified")
	default:
		return fmt.Errorf("asset ref type unknown %d", ref.Type)
	}
}

// serialize writes the AssetRef type byte followed by the type-specific payload to the writer.
func (ref AssetRef) serialize(w io.Writer) error {
	if _, err := w.Write([]byte{byte(ref.Type)}); err != nil {
		return err
	}

	switch ref.Type {
	case AssetRefByID:
		if err := ref.AssetId.serialize(w); err != nil {
			return err
		}
	case AssetRefByGroup:
		if err := serializeUint16(w, ref.GroupIndex); err != nil {
			return err
		}
	}

	return nil
}

// newAssetRefFromReader deserializes an AssetRef by reading the type byte and the
// corresponding payload from the reader.
func newAssetRefFromReader(r *bytes.Reader) (*AssetRef, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	ref := &AssetRef{Type: AssetRefType(typ)}
	switch ref.Type {
	case AssetRefByID:
		assetId, err := newAssetIdFromReader(r)
		if err != nil {
			return nil, err
		}
		ref.AssetId = *assetId
	case AssetRefByGroup:
		grpIndex, err := deserializeUint16(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("invalid asset ref length")
			}
			return nil, err
		}
		ref.GroupIndex = grpIndex
	case AssetRefUnspecified:
		return nil, fmt.Errorf("asset ref type unspecified")
	default:
		return nil, fmt.Errorf("asset ref type unknown %d", typ)
	}

	if err := ref.validate(); err != nil {
		return nil, err
	}

	return ref, nil
}
