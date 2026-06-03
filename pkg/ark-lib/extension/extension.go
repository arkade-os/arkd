package extension

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"

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

// NewExtensionFromPackets constructs an Extension from already-parsed packets.
// It rejects nil packets and duplicate type bytes.
func NewExtensionFromPackets(pkts ...Packet) (Extension, error) {
	if len(pkts) == 0 {
		return nil, fmt.Errorf("missing packets")
	}

	ext := make(Extension, 0, len(pkts))
	seen := make(map[uint8]struct{}, len(pkts))
	for _, p := range pkts {
		if p == nil {
			return nil, fmt.Errorf("extension packet must not be nil")
		}
		v := reflect.ValueOf(p)
		switch v.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if v.IsNil() {
				return nil, fmt.Errorf("extension packet must not be nil")
			}
		}
		t := p.Type()
		if _, dup := seen[t]; dup {
			return nil, fmt.Errorf("duplicate packet type 0x%02x", t)
		}
		seen[t] = struct{}{}
		ext = append(ext, p)
	}

	return ext, nil
}

// Serialize the extension as a complete OP_RETURN script
// OP_RETURN <magic_bytes> <tlv_packets>
func (e Extension) Serialize() ([]byte, error) {
	if len(e) == 0 {
		return nil, fmt.Errorf("cannot serialize empty extension: missing packets")
	}

	w := bytes.NewBuffer(nil)

	if _, err := w.Write(ArkadeMagic); err != nil {
		return nil, fmt.Errorf("failed to write magic prefix: %w", err)
	}

	for _, packet := range e {
		packetBytes, err := packet.Serialize()
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

	return opReturnScript(w.Bytes()), nil
}

// opReturnScript builds an OP_RETURN script with an arbitrary-length data push,
// bypassing txscript.ScriptBuilder which caps elements at 520 bytes.
func opReturnScript(data []byte) []byte {
	n := len(data)
	var script []byte
	switch {
	case n <= 75:
		script = make([]byte, 0, 2+n)
		script = append(script, txscript.OP_RETURN, byte(n))
	case n <= 255:
		script = make([]byte, 0, 3+n)
		script = append(script, txscript.OP_RETURN, txscript.OP_PUSHDATA1, byte(n))
	case n <= 65535:
		l := [2]byte{}
		binary.LittleEndian.PutUint16(l[:], uint16(n))
		script = make([]byte, 0, 4+n)
		script = append(script, txscript.OP_RETURN, txscript.OP_PUSHDATA2)
		script = append(script, l[:]...)
	default:
		l := [4]byte{}
		binary.LittleEndian.PutUint32(l[:], uint32(n))
		script = make([]byte, 0, 6+n)
		script = append(script, txscript.OP_RETURN, txscript.OP_PUSHDATA4)
		script = append(script, l[:]...)
	}
	return append(script, data...)
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

// GetPacketByType returns the first Packet in the extension whose type byte equals t.
// It returns nil if no match is present and is safe to call on a nil Extension.
//
//   - For type 0x00 (asset), prefer GetAssetPacket for the concrete asset.Packet type.
//   - NewExtensionFromBytes rejects duplicate type bytes; if an Extension is constructed manually with
//     duplicates, the first match in slice order is returned.
func (e Extension) GetPacketByType(t uint8) Packet {
	for _, p := range e {
		if p.Type() == t {
			return p
		}
	}
	return nil
}

// IsExtension reports whether script is an ark extension blob,
// i.e. starts with OP_RETURN followed by a data push whose payload begins with ArkadeMagic.
func IsExtension(script []byte) bool {
	tokenizer := txscript.MakeScriptTokenizer(0, script)
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_RETURN {
		return false
	}
	if !tokenizer.Next() {
		return false
	}
	data := tokenizer.Data()
	return len(data) >= len(ArkadeMagic) && bytes.Equal(data[:len(ArkadeMagic)], ArkadeMagic)
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

// NewExtensionFromBytes reads from raw [OP_RETURN][push_opcode][MAGIC][PACKET].. bytes.
func NewExtensionFromBytes(data []byte) (Extension, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, data)

	if !tokenizer.Next() {
		return nil, fmt.Errorf("missing OP_RETURN: %w", io.EOF)
	}
	if tokenizer.Opcode() != txscript.OP_RETURN {
		return nil, fmt.Errorf("expected OP_RETURN, got %d", tokenizer.Opcode())
	}

	if !tokenizer.Next() {
		return nil, fmt.Errorf("missing magic prefix: %w", io.EOF)
	}

	payload := tokenizer.Data()
	pr := bytes.NewReader(payload)

	// read magic prefix
	magicPrefix := make([]byte, len(ArkadeMagic))
	if _, err := io.ReadFull(pr, magicPrefix); err != nil {
		return nil, fmt.Errorf("missing magic prefix: %w", err)
	}
	if !bytes.Equal(magicPrefix, ArkadeMagic) {
		return nil, fmt.Errorf("expected magic prefix %x, got %x", ArkadeMagic, magicPrefix)
	}

	extension := make(Extension, 0)

	for pr.Len() > 0 {
		// pr.Len() > 0, so can't fail
		//nolint
		packetType, _ := pr.ReadByte()
		packetData, err := deserializeVarSlice(pr)
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
		return UnknownPacket{packetType, packetData}, nil
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
