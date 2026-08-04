// Package varint provides canonical (minimal) LEB128 unsigned-integer decoding
// shared by the ark-lib wire formats.
package varint

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ErrNonMinimal is returned when a varint is encoded with more bytes than
// necessary (a droppable all-zero high 7-bit group), i.e. non-canonical.
var ErrNonMinimal = errors.New("non-canonical (non-minimal) varint encoding")

// ReadCanonical reads a canonical LEB128 unsigned integer from r. Decoding and
// 64-bit overflow detection are delegated to binary.ReadUvarint; non-minimal
// encodings are rejected by requiring the bytes consumed to equal the length of
// the value's canonical (shortest) re-encoding.
func ReadCanonical(r *bytes.Reader) (uint64, error) {
	before := r.Len()
	v, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}
	var buf [binary.MaxVarintLen64]byte
	if before-r.Len() != binary.PutUvarint(buf[:], v) {
		return 0, ErrNonMinimal
	}
	return v, nil
}
