package asset

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// serializeUint16 serializes a uint16 to the writer
func serializeUint16(w io.Writer, value uint16) error {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], value)
	_, err := w.Write(buf[:])
	return err
}

// serializeVarUint serializes a uint64 to the writer as varuint
func serializeVarUint(w io.Writer, value uint64) error {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf[:], value)
	_, err := w.Write(buf[:n])
	return err
}

// serializeSlice serializes a slice to the writer
func serializeSlice(w io.Writer, buf []byte) error {
	_, err := w.Write(buf)
	return err
}

// serializeVarSlice serializes a variable length slice to the writer as <len(buf),buf>
func serializeVarSlice(w io.Writer, buf []byte) error {
	b := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(b[:], uint64(len(buf)))
	if _, err := w.Write(b[:n]); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

// deserializeUint16 deserializes a uint16 from the reader
func deserializeUint16(r *bytes.Reader) (uint16, error) {
	if r.Len() < 2 {
		return 0, io.EOF
	}
	var buf [2]byte
	if _, err := r.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(buf[:]), nil
}

// deserializeVarUint deserializes a uint64 (as varuint) from the reader
func deserializeVarUint(r *bytes.Reader) (uint64, error) {
	return binary.ReadUvarint(r)
}

// deserializeSlice deserializes a byte slice from the reader with the given size
func deserializeSlice(r *bytes.Reader, size int) ([]byte, error) {
	if r.Len() < size {
		return nil, io.EOF
	}
	buf := make([]byte, size)
	if _, err := r.Read(buf[:]); err != nil {
		return nil, err
	}
	return buf[:], nil
}

// deserializeVarSlice deserializes a variable length slice from the reader
func deserializeVarSlice(r *bytes.Reader) ([]byte, error) {
	l, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if r.Len() < int(l) {
		return nil, io.EOF
	}
	buf := make([]byte, l)
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// deserializeTxHash deserializes a chainhash.Hash from the reader as reversed bytes
func deserializeTxHash(r *bytes.Reader) (chainhash.Hash, error) {
	buf, err := deserializeSlice(r, chainhash.HashSize)
	if err != nil {
		return chainhash.Hash{}, err
	}
	return chainhash.Hash(reverseBytes(buf)), nil
}

// serializeHash serializes a chainhash.Hash to the write as reversed bytes
// it ensures the encoded result is the txid
func serializeTxHash(w io.Writer, hash chainhash.Hash) error {
	clone := hash.CloneBytes()
	reversedBytes := reverseBytes(clone) // reverse the bytes to get the txid
	return serializeSlice(w, reversedBytes)
}

// reverseBytes reverses the bytes of a slice
func reverseBytes(buf []byte) []byte {
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-1-i] = buf[len(buf)-1-i], buf[i]
	}
	return buf
}
