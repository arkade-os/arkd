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
	ArkadeMagic        = []byte{0x41, 0x52, 0x4B} // "ARK"
	MarkerAssetPayload = byte(0)
)

type AssetPacketNotFoundError struct {
	Txid string
}

func (e AssetPacketNotFoundError) Error() string {
	return fmt.Sprintf("asset packet not found in tx %s", e.Txid)
}

type Packet []AssetGroup

func NewPacket(assets []AssetGroup) (Packet, error) {
	p := Packet(assets)
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func NewPacketFromTx(tx *wire.MsgTx) (Packet, error) {
	for _, out := range tx.TxOut {
		if IsAssetPacket(out.PkScript) {
			return NewPacketFromTxOut(*out)
		}
	}
	return nil, AssetPacketNotFoundError{Txid: tx.TxID()}
}

func NewPacketFromTxOut(txOut wire.TxOut) (Packet, error) {
	return NewPacketFromScript(txOut.PkScript)
}

func NewPacketFromScript(script []byte) (Packet, error) {
	rawPacket, err := rawPacketFromScript(script)
	if err != nil {
		return nil, err
	}
	return newPacketFromReader(bytes.NewReader(rawPacket))
}

func NewPacketFromString(s string) (Packet, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid output script format, must be hex")
	}
	return NewPacketFromScript(buf)
}

func IsAssetPacket(script []byte) bool {
	_, err := rawPacketFromScript(script)
	return err == nil
}

func (p Packet) LeafTxPacket(intentTxid chainhash.Hash) Packet {
	batchLeafPacket := make(Packet, 0, len(p))
	for _, assetGroup := range p {
		batchLeafPacket = append(batchLeafPacket, assetGroup.toBatchLeafAssetGroup(intentTxid))
	}
	return batchLeafPacket
}

func (p Packet) TxOut() (*wire.TxOut, error) {
	script, err := p.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to build output script: %w", (err))
	}
	return wire.NewTxOut(0, script), nil
}

func (p Packet) Serialize() ([]byte, error) {
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

func (p Packet) String() string {
	// nolint
	buf, _ := p.Serialize()
	return hex.EncodeToString(buf)
}

func (p Packet) validate() error {
	if len(p) <= 0 {
		return fmt.Errorf("missing assets")
	}
	for _, asset := range p {
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

	// Make sure we read all packet with no extra bytes left
	if r.Len() > 0 {
		return nil, fmt.Errorf("invalid packet length, left %d unknown bytes to read", r.Len())
	}

	packet := Packet(assets)
	if err := packet.validate(); err != nil {
		return nil, err
	}
	return packet, nil
}

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

	r := bytes.NewReader(payload)

	buf := make([]byte, len(ArkadeMagic))
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	if !bytes.Equal(buf, ArkadeMagic) {
		return nil, fmt.Errorf("invalid magic prefix, got %x want %x", buf, ArkadeMagic)
	}

	marker, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if marker != MarkerAssetPayload {
		return nil, fmt.Errorf("invalid aset marker, got %d want %d", marker, MarkerAssetPayload)
	}

	if r.Len() <= 0 {
		return nil, fmt.Errorf("missing packet data")
	}

	return payload[len(ArkadeMagic)+1:], nil
}
