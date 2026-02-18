package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Metadata is a key-value pair attached to an asset group.
type Metadata struct {
	// Key is the metadata entry name.
	Key []byte
	// Value is the metadata entry content.
	Value []byte
}

// NewMetadata creates a Metadata entry from string key and value. Both must be non-empty.
func NewMetadata(key, value string) (*Metadata, error) {
	md := Metadata{
		Key:   []byte(key),
		Value: []byte(value),
	}
	if err := md.validate(); err != nil {
		return nil, err
	}
	return &md, nil
}

// NewMetadataFromString parses a hex-encoded string into a Metadata entry.
func NewMetadataFromString(s string) (*Metadata, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata format, must be hex")
	}
	return NewMetadataFromBytes(buf)
}

// NewMetadataFromBytes deserializes a Metadata entry from a raw byte slice.
func NewMetadataFromBytes(buf []byte) (*Metadata, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing metadata")
	}
	r := bytes.NewReader(buf)
	return newMetadataFromReader(r)
}

func NewMetadataList(md []Metadata) (MetadataList, error) {
	if len(md) <= 0 {
		return nil, fmt.Errorf("missing metadata")
	}
	if err := MetadataList(md).validate(); err != nil {
		return nil, err
	}
	return md, nil
}

func NewMetadataListFromString(s string) (MetadataList, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata list format, must be hex")
	}
	return NewMetadataListFromBytes(buf)
}

func NewMetadataListFromBytes(buf []byte) (MetadataList, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing metadata list")
	}
	r := bytes.NewReader(buf)
	return newMetadataListFromReader(r)
}

// GenerateMetadataListHash computes a deterministic SHA-256 hash over all metadata entries.
// Each entry is individually hashed, the hashes are sorted lexicographically, concatenated,
// and hashed again to produce the final digest.
func GenerateMetadataListHash(md []Metadata) ([]byte, error) {
	if len(md) <= 0 {
		return nil, nil
	}

	// Hash all metadata
	hashes := make([][32]byte, 0, len(md))
	for _, m := range md {
		if err := m.validate(); err != nil {
			return nil, err
		}
		hashes = append(hashes, m.Hash())
	}

	// Sort the resulting hashes in lexicographic order
	sort.SliceStable(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i][:], hashes[j][:]) < 0
	})

	// Concat all hashes
	buf := make([]byte, 0, len(hashes)*32)
	for _, h := range hashes {
		buf = append(buf, h[:]...)
	}
	// Compute the resulting hash
	hash := sha256.Sum256(buf)
	return hash[:], nil
}

// Hash returns the SHA-256 digest of the concatenated key and value bytes.
func (md Metadata) Hash() [32]byte {
	buf := make([]byte, 0, len(md.Key)+len(md.Value))
	buf = append(buf, md.Key...)
	buf = append(buf, md.Value...)
	return sha256.Sum256(buf)
}

// Serialize encodes the Metadata entry into a byte slice.
func (md Metadata) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := md.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized Metadata entry.
func (md Metadata) String() string {
	// nolint
	buf, _ := md.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks that both key and value are non-empty.
func (md Metadata) validate() error {
	if len(md.Key) <= 0 {
		return fmt.Errorf("missing metadata key")
	}
	if len(md.Value) <= 0 {
		return fmt.Errorf("missing metadata value")
	}
	return nil
}

// serialize writes the key and value as variable-length slices to the writer.
func (md Metadata) serialize(w io.Writer) error {
	key := []byte(md.Key)
	value := []byte(md.Value)

	if err := serializeVarSlice(w, key); err != nil {
		return err
	}
	if err := serializeVarSlice(w, value); err != nil {
		return err
	}
	return nil
}

// MetadataList is a sortable list of Metadata used for deterministic serialization.
type MetadataList []Metadata

func (l MetadataList) String() string {
	buf, _ := l.Serialize()
	return hex.EncodeToString(buf)
}

func (l MetadataList) Serialize() ([]byte, error) {
	r := bytes.NewBuffer(nil)
	if err := l.serialize(r); err != nil {
		return nil, err
	}
	return r.Bytes(), nil
}

// validate ensures all metadata have non-empty keys and values.
func (l MetadataList) validate() error {
	for _, md := range l {
		if err := md.validate(); err != nil {
			return err
		}
	}
	return nil
}

// serialize sorts the entries by key in descending order and writes the length-prefixed
// list to the writer.
func (l MetadataList) serialize(w io.Writer) error {
	if err := serializeVarUint(w, uint64(len(l))); err != nil {
		return err
	}
	sort.SliceStable(l, func(i, j int) bool {
		return string(l[i].Key)+string(l[i].Value) > string(l[j].Key)+string(l[j].Value)
	})
	for _, md := range l {
		if err := md.serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// newMetadataFromReader deserializes a single Metadata entry from the reader.
func newMetadataFromReader(r *bytes.Reader) (*Metadata, error) {
	key, err := deserializeVarSlice(r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("invalid metadata length")
		}
		return nil, err
	}
	value, err := deserializeVarSlice(r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("invalid metadata length")
		}
		return nil, err
	}

	md := Metadata{Key: key, Value: value}
	if err := md.validate(); err != nil {
		return nil, err
	}

	return &md, nil
}

// newMetadataListFromReader deserializes a length-prefixed list of Metadata entries from the reader.
func newMetadataListFromReader(r *bytes.Reader) (MetadataList, error) {
	count, err := deserializeVarUint(r)
	if err != nil {
		return nil, err
	}

	l := make(MetadataList, 0, count)
	for range count {
		md, err := newMetadataFromReader(r)
		if err != nil {
			return nil, err
		}
		l = append(l, *md)
	}

	if err := l.validate(); err != nil {
		return nil, err
	}
	return l, nil
}
