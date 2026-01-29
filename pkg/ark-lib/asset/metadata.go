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

type Metadata struct {
	Key   []byte
	Value []byte
}

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

func NewMetadataFromString(s string) (*Metadata, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata format, must be hex")
	}
	return NewMetadataFromBytes(buf)
}

func NewMetadataFromBytes(buf []byte) (*Metadata, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing metadata")
	}
	r := bytes.NewReader(buf)
	return newMetadataFromReader(r)
}

func (md Metadata) Hash() [32]byte {
	return sha256.Sum256(append(md.Key, md.Value...))
}

func (md Metadata) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := md.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (md Metadata) String() string {
	// nolint
	buf, _ := md.Serialize()
	return hex.EncodeToString(buf)
}

func (md Metadata) validate() error {
	if len(md.Key) <= 0 {
		return fmt.Errorf("missing metadata key")
	}
	if len(md.Value) <= 0 {
		return fmt.Errorf("missing metadata value")
	}
	return nil
}

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

type metadataList []Metadata

func newMetadataListFromReader(r *bytes.Reader) ([]Metadata, error) {
	count, err := deserializeVarUint(r)
	if err != nil {
		return nil, err
	}

	l := make([]Metadata, 0, count)
	for range count {
		md, err := newMetadataFromReader(r)
		if err != nil {
			return nil, err
		}
		l = append(l, *md)
	}
	return l, nil
}

func (l metadataList) serialize(w io.Writer) error {
	if err := serializeVarUint(w, uint64(len(l))); err != nil {
		return err
	}
	sort.SliceStable(l, func(i, j int) bool {
		return string(l[i].Key) > string(l[j].Key)
	})
	for _, md := range l {
		if err := md.serialize(w); err != nil {
			return err
		}
	}
	return nil
}
