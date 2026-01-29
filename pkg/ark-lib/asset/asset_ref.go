package asset

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type AssetRefType uint8

const (
	AssetRefUnspecified AssetRefType = iota
	AssetRefByID
	AssetRefByGroup
)

type AssetRef struct {
	Type       AssetRefType
	AssetId    AssetId
	GroupIndex uint16
}

func NewAssetRefFromId(assetId AssetId) (*AssetRef, error) {
	ref := AssetRef{Type: AssetRefByID, AssetId: assetId}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	return &ref, nil
}

func NewAssetRefFromGroupIndex(groupIndex uint16) (*AssetRef, error) {
	ref := AssetRef{Type: AssetRefByGroup, GroupIndex: groupIndex}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	return &ref, nil
}

func NewAssetRefFromString(s string) (*AssetRef, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset ref format, must be hex")
	}
	return NewAssetRefFromBytes(buf)
}

func NewAssetRefFromBytes(buf []byte) (*AssetRef, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing asset ref")
	}
	r := bytes.NewReader(buf)
	return newAssetRefFromReader(r)
}

func (ref AssetRef) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := ref.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (ref AssetRef) String() string {
	// nolint
	buf, _ := ref.Serialize()
	return hex.EncodeToString(buf)
}

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
