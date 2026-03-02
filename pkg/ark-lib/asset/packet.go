package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const PacketType = uint8(0)

// Packet represents a list of AssetGroup entries embedded in a transaction's OP_RETURN output.
type Packet []AssetGroup

// NewPacket creates a validated Packet from the given asset groups.
func NewPacket(assets []AssetGroup) (Packet, error) {
	p := Packet(assets)
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// NewPacketFromString parses a hex-encoded packet.
func NewPacketFromString(s string) (Packet, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("missing packet data")
	}
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid packet format, must be hex")
	}
	return NewPacketFromBytes(buf)
}

func NewPacketFromBytes(buf []byte) (Packet, error) {
	return newPacketFromReader(bytes.NewReader(buf))
}

func (p Packet) Type() uint8 {
	return PacketType
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

// Serialize encodes the packet as raw bytes.
func (p Packet) Serialize() ([]byte, error) {
	if len(p) <= 0 {
		return nil, nil
	}

	w := bytes.NewBuffer(nil)
	if err := p.serialize(w); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	return w.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized packet.
func (p Packet) String() string {
	// nolint
	buf, _ := p.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks that the packet is non-empty, all groups are valid, and control asset
// group index references are within bounds.
func (p Packet) validate() error {
	if len(p) <= 0 {
		return fmt.Errorf("missing assets")
	}
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

// newPacketFromReader deserializes a Packet from the reader, ensuring all bytes are consumed.
func newPacketFromReader(r *bytes.Reader) (Packet, error) {
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

	// Make sure we read the entire packet with no extra bytes left
	if r.Len() > 0 {
		return nil, fmt.Errorf("invalid packet length, left %d unknown bytes to read", r.Len())
	}

	packet := Packet(assets)
	if err := packet.validate(); err != nil {
		return nil, err
	}
	return packet, nil
}
