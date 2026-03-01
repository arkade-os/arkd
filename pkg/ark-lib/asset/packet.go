package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	// ArkadeMagic is the 3-byte magic prefix ("ARK") that identifies an asset packet in a
	// OP_RETURN output.
	ArkadeMagic = []byte{0x41, 0x52, 0x4B} // "ARK"
	// MarkerAssetPayload is the marker byte that follows ArkadeMagic and indicates an asset
	// payload.
	MarkerAssetPayload = byte(0)
)

// AssetPacketNotFoundError is returned when a transaction does not contain an asset packet.
type AssetPacketNotFoundError struct {
	// Txid is the transaction ID that was expected to contain an asset packet.
	Txid string
}

// Error implements the error interface.
func (e AssetPacketNotFoundError) Error() string {
	return fmt.Sprintf("asset packet not found in tx %s", e.Txid)
}

// Packet represents a list of AssetGroup entries embedded in a transaction's OP_RETURN output.
type Packet []AssetGroup

// NewPacket creates a validated Packet from the given asset groups.
// At least one group is required when constructing a new packet.
func NewPacket(assets []AssetGroup) (Packet, error) {
	if len(assets) == 0 {
		return nil, fmt.Errorf("missing assets")
	}
	p := Packet(assets)
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// NewPacketFromTx extracts and deserializes a Packet from the first OP_RETURN output
// in the transaction that contains an asset packet.
func NewPacketFromTx(tx *wire.MsgTx) (Packet, error) {
	for _, out := range tx.TxOut {
		if IsAssetPacket(out.PkScript) {
			return NewPacketFromTxOut(*out)
		}
	}
	return nil, AssetPacketNotFoundError{Txid: tx.TxID()}
}

// NewPacketFromTxOut deserializes a Packet from a transaction output's script.
func NewPacketFromTxOut(txOut wire.TxOut) (Packet, error) {
	return NewPacketFromScript(txOut.PkScript)
}

// NewPacketFromScript deserializes a Packet from a raw OP_RETURN script.
func NewPacketFromScript(script []byte) (Packet, error) {
	rawPacket, err := rawPacketFromScript(script)
	if err != nil {
		return nil, err
	}
	return newPacketFromReader(bytes.NewReader(rawPacket))
}

// NewPacketFromString parses a hex-encoded OP_RETURN script into a Packet.
func NewPacketFromString(s string) (Packet, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid output script format, must be hex")
	}
	return NewPacketFromScript(buf)
}

// IsAssetPacket returns whether the given script is a valid OP_RETURN containing an asset packet.
func IsAssetPacket(script []byte) bool {
	_, err := rawPacketFromScript(script)
	return err == nil
}

// LeafTxPacket converts the packet into its batch-leaf form where each group's inputs
// are replaced by a single intent input referencing the given transaction hash.
func (p Packet) LeafTxPacket(intentTxid chainhash.Hash) Packet {
	batchLeafPacket := make(Packet, 0, len(p))
	for _, assetGroup := range p {
		batchLeafPacket = append(batchLeafPacket, assetGroup.toBatchLeafAssetGroup(intentTxid))
	}
	return batchLeafPacket
}

// TxOut serializes the packet into a zero-value OP_RETURN transaction output.
func (p Packet) TxOut() (*wire.TxOut, error) {
	script, err := p.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to build output script: %w", (err))
	}
	return wire.NewTxOut(0, script), nil
}

// Serialize encodes the packet as a complete OP_RETURN script (magic + marker + groups).
func (p Packet) Serialize() ([]byte, error) {
	if len(p) <= 0 {
		return nil, nil
	}

	w := bytes.NewBuffer(nil)
	if err := serializeSlice(w, ArkadeMagic); err != nil {
		return nil, fmt.Errorf("failed to serialize magic prefix: %w", err)
	}
	if err := w.WriteByte(MarkerAssetPayload); err != nil {
		return nil, fmt.Errorf("failed to serialize asset marker: %w", err)
	}

	if err := p.serialize(w); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	data := w.Bytes()
	return txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).AddData(data).Script()
}

// String returns the hex-encoded representation of the serialized packet script.
func (p Packet) String() string {
	// nolint
	buf, _ := p.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks that all groups are valid and control asset group index
// references are within bounds. An empty packet is considered valid because
// the OP_RETURN TLV stream may contain only non-asset records.
func (p Packet) validate() error {
	seen := make(map[AssetId]struct{})
	for _, asset := range p {
		if asset.AssetId != nil {
			if _, ok := seen[*asset.AssetId]; ok {
				return fmt.Errorf("duplicate asset group for asset %s", asset.AssetId)
			}
			seen[*asset.AssetId] = struct{}{}
		}

		if err := asset.validate(); err != nil {
			return err
		}

		if asset.ControlAsset != nil && asset.ControlAsset.Type == AssetRefByGroup &&
			int(asset.ControlAsset.GroupIndex) >= len(p) {
			return fmt.Errorf(
				"invalid control asset group index, %d out of range [0, %d]",
				asset.ControlAsset.GroupIndex, len(p)-1,
			)
		}
	}
	return nil
}

// serialize writes the varint group count followed by each serialized group to the writer.
func (p Packet) serialize(w io.Writer) error {
	if err := serializeVarUint(w, uint64(len(p))); err != nil {
		return err
	}

	for _, asset := range p {
		if err := asset.serialize(w); err != nil {
			return err
		}
	}

	return nil
}

// newPacketFromReader deserializes a Packet from the reader.
// Trailing bytes are tolerated because the OP_RETURN TLV stream may contain
// additional records (e.g. type 0x01 Introspector Packet) after the asset data.
func newPacketFromReader(r *bytes.Reader) (Packet, error) {
	packet, err := parseAssetGroups(r)
	if err != nil {
		return nil, err
	}
	if err := packet.validate(); err != nil {
		return nil, err
	}
	return packet, nil
}

// parseAssetGroups reads the varint group count and each asset group from the
// reader. It performs structural deserialization only — logical validation
// (e.g. group index bounds) is left to the caller.
func parseAssetGroups(r *bytes.Reader) (Packet, error) {
	count, err := deserializeVarUint(r)
	if err != nil {
		return nil, err
	}
	assets := make([]AssetGroup, 0, count)
	for range count {
		ag, err := newAssetGroupFromReader(r)
		if err != nil {
			return nil, err
		}
		assets = append(assets, *ag)
	}
	return Packet(assets), nil
}

// rawPacketFromScript extracts the raw asset packet bytes from an OP_RETURN
// script. The OP_RETURN TLV stream begins with the ARK magic ("ARK") followed
// by one or more self-delimiting type+value records. The asset record is
// identified by the MarkerAssetPayload (0x00) type byte, which may appear at
// any position in the stream (not necessarily first). The function scans for
// the marker and trial-parses to distinguish real markers from identical byte
// values embedded inside other records.
func rawPacketFromScript(script []byte) ([]byte, error) {
	if len(script) <= 0 {
		return nil, fmt.Errorf("missing output script")
	}
	if !bytes.HasPrefix(script, []byte{txscript.OP_RETURN}) {
		return nil, fmt.Errorf("OP_RETURN not found in output script")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, script)
	if !tokenizer.Next() {
		if err := tokenizer.Err(); err != nil {
			return nil, fmt.Errorf("invalid OP_RETURN output script: %w", err)
		}
		return nil, fmt.Errorf("invalid OP_RETURN output script")
	}

	var payload []byte
	for tokenizer.Next() {
		data := tokenizer.Data()
		if len(data) <= 0 {
			return nil, fmt.Errorf("missing OP_RETURN data")
		}
		payload = append(payload, data...)
	}
	if err := tokenizer.Err(); err != nil {
		return nil, fmt.Errorf("invalid OP_RETURN output script: %w", err)
	}
	if len(payload) <= 0 {
		return nil, fmt.Errorf("missing OP_RETURN data")
	}

	if len(payload) < len(ArkadeMagic) {
		return nil, fmt.Errorf("invalid script length")
	}
	if !bytes.Equal(payload[:len(ArkadeMagic)], ArkadeMagic) {
		return nil, fmt.Errorf("invalid magic prefix, got %x want %x",
			payload[:len(ArkadeMagic)], ArkadeMagic)
	}

	tlvData := payload[len(ArkadeMagic):]
	if len(tlvData) == 0 {
		return nil, fmt.Errorf("invalid script length")
	}

	// Scan for the asset marker byte. It may not be the first record in the
	// stream, so we try each candidate position and trial-parse to confirm.
	for i := 0; i < len(tlvData); i++ {
		if tlvData[i] != MarkerAssetPayload {
			continue
		}
		candidate := tlvData[i+1:]
		if len(candidate) == 0 {
			continue
		}
		// Trial-parse: if the candidate bytes form structurally valid asset
		// groups the marker is real; otherwise the 0x00 byte is part of
		// another record. Only structural parsing is done here — logical
		// validation (e.g. group index bounds) happens later in the caller.
		if _, err := parseAssetGroups(bytes.NewReader(candidate)); err == nil {
			return candidate, nil
		}
	}

	return nil, fmt.Errorf("asset marker not found in TLV stream")
}
