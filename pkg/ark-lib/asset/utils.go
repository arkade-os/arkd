package asset

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// serializeUint16 writes a uint16 in little-endian byte order to the writer.
func serializeUint16(w io.Writer, value uint16) error {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], value)
	_, err := w.Write(buf[:])
	return err
}

// serializeVarUint writes a uint64 as a variable-length unsigned integer to the writer.
func serializeVarUint(w io.Writer, value uint64) error {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf[:], value)
	_, err := w.Write(buf[:n])
	return err
}

// serializeSlice writes a raw byte slice to the writer.
func serializeSlice(w io.Writer, buf []byte) error {
	_, err := w.Write(buf)
	return err
}

// serializeVarSlice writes a variable-length byte slice to the writer as a varint length prefix
// followed by the raw bytes.
func serializeVarSlice(w io.Writer, buf []byte) error {
	b := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(b[:], uint64(len(buf)))
	if _, err := w.Write(b[:n]); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

// deserializeUint16 reads a little-endian uint16 from the reader.
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

// deserializeVarUint reads a variable-length unsigned integer (uint64) from the reader.
func deserializeVarUint(r *bytes.Reader) (uint64, error) {
	return binary.ReadUvarint(r)
}

// deserializeSlice reads exactly size bytes from the reader into a new slice.
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

// deserializeVarSlice reads a varint length prefix followed by that many bytes from the reader.
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

// deserializeTxHash reads a chainhash.Hash from the reader, reversing the byte order
// to convert from the serialized (little-endian) format to the internal representation.
func deserializeTxHash(r *bytes.Reader) (chainhash.Hash, error) {
	buf, err := deserializeSlice(r, chainhash.HashSize)
	if err != nil {
		return chainhash.Hash{}, err
	}
	return chainhash.Hash(reverseBytes(buf)), nil
}

// serializeTxHash writes a chainhash.Hash to the writer with reversed byte order
// so that the encoded result matches the canonical txid format.
func serializeTxHash(w io.Writer, hash chainhash.Hash) error {
	clone := hash.CloneBytes()
	reversedBytes := reverseBytes(clone) // reverse the bytes to get the txid
	return serializeSlice(w, reversedBytes)
}

// reverseBytes reverses a byte slice in place and returns it.
func reverseBytes(buf []byte) []byte {
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-1-i] = buf[len(buf)-1-i], buf[i]
	}
	return buf
}
