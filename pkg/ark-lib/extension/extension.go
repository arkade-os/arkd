package extension

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	// ArkadeMagic is the 3-byte magic prefix ("ARK") that identifies the op_return output as an ark extension blob.
	ArkadeMagic = []byte{0x41, 0x52, 0x4B} // "ARK"
)

// Extension is a set of packet (typed data) encoded in OP_RETURN output script
type Extension []Packet

// Serialize the extension as a complete OP_RETURN script
// OP_RETURN <magic_bytes> <tlv_packets>
func (e Extension) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := w.WriteByte(txscript.OP_RETURN); err != nil {
		return nil, fmt.Errorf("failed to write OP_RETURN: %w", err)
	}
	
	if _, err := w.Write(ArkadeMagic); err != nil {
		return nil, fmt.Errorf("failed to write magic prefix: %w", err)
	}

	for _, packet := range e {
		packetBytes, err := packet.Serialize();
		if err != nil {
			return nil, fmt.Errorf("failed to serialize packet: %w", err)
		}

		// packet type 
		if err := w.WriteByte(packet.Type()); err != nil {
			return nil, fmt.Errorf("failed to write packet type: %w", err)
		}
		
		// packet data (varint length prefix followed by the raw bytes)
		if err := serializeVarSlice(w, packetBytes); err != nil {
			return nil, fmt.Errorf("failed to write packet: %w", err)
		}
	}

	return w.Bytes(), nil
}

// TxOut serializes the extension and returns it as an unspendable OP_RETURN transaction output.
func (e Extension) TxOut() (*wire.TxOut, error) {
	script, err := e.Serialize()
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(0, script), nil
}

// GetAssetPacket returns the asset.Packet embedded in the extension, or nil if none is present.
func (e Extension) GetAssetPacket() asset.Packet {
	for _, p := range e {
		if ap, ok := p.(asset.Packet); ok {
			return ap
		}
	}
	return nil
}

// IsExtension reports whether script is an ark extension blob,
// i.e. starts with OP_RETURN followed by the ArkadeMagic prefix.
func IsExtension(script []byte) bool {
	return len(script) > len(ArkadeMagic) &&
		script[0] == txscript.OP_RETURN &&
		bytes.Equal(script[1:1+len(ArkadeMagic)], ArkadeMagic)
}

// ErrExtensionNotFound is returned by NewExtensionFromTx when no extension output is present.
var ErrExtensionNotFound = errors.New("no extension output found in transaction")

// NewExtensionFromTx searches the transaction outputs for an extension blob and parses it.
func NewExtensionFromTx(tx *wire.MsgTx) (Extension, error) {
	for _, out := range tx.TxOut {
		if IsExtension(out.PkScript) {
			return NewExtensionFromBytes(out.PkScript)
		}
	}
	return nil, ErrExtensionNotFound
}

// NewExtensionFromBytes read from raw [OP_RETURN][MAGIC][PACKET][PACKET][PACKET].. bytes
func NewExtensionFromBytes(data []byte) (Extension, error) {
	r := bytes.NewReader(data)

	// first byte should be OP_RETURN
	firstByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("missing OP_RETURN: %w", err)
	}
	if firstByte != txscript.OP_RETURN {
		return nil, fmt.Errorf("expected OP_RETURN, got %d", firstByte)
	}

	// read magic prefix
	magicPrefix := make([]byte, len(ArkadeMagic))
	if _, err := io.ReadFull(r, magicPrefix); err != nil {
		return nil, fmt.Errorf("missing magic prefix: %w", err)
	}
	if !bytes.Equal(magicPrefix, ArkadeMagic) {
		return nil, fmt.Errorf("expected magic prefix %x, got %x", ArkadeMagic, magicPrefix)
	}

	extension := make(Extension, 0)

	for r.Len() > 0 {
		packetType, _ := r.ReadByte() // r.Len() > 0, so can't fail
		packetData, err := deserializeVarSlice(r)
		if err != nil {
			return nil, fmt.Errorf("missing packet data: %w", err)
		}

		packet, err := parsePacket(packetType, packetData)
		if err != nil {
			return nil, err
		}

		extension = append(extension, packet)
	}

	if len(extension) == 0 {
		return nil, fmt.Errorf("missing packets")
	}

	// prevent duplicate packet types
	seen := make(map[uint8]struct{}, len(extension))
	for _, p := range extension {
		if _, ok := seen[p.Type()]; ok {
			return nil, fmt.Errorf("duplicate packet type %d", p.Type())
		}
		seen[p.Type()] = struct{}{}
	}

	return extension, nil
}


// return to known packet (asset.Packet) or fallback to UnknownPacket
func parsePacket(packetType uint8, packetData []byte) (Packet, error) {
	switch packetType {
	case asset.PacketType:
		return asset.NewPacketFromBytes(packetData)
	default:
		return UnknownPacket{packetType,packetData}, nil
	}
}

// deserializeVarSlice reads a varint length prefix followed by that many bytes from the reader.
func deserializeVarSlice(r *bytes.Reader) ([]byte, error) {
	l, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if l > uint64(r.Len()) {
		return nil, io.EOF
	}
	buf := make([]byte, l)
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
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