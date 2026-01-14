package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
)

const AssetVersion byte = 0x01

type AssetId struct {
	TxHash [32]byte
	Index  uint16
}

type AssetRefType uint8

const (
	AssetRefByID    AssetRefType = 0x01
	AssetRefByGroup AssetRefType = 0x02
)

type AssetRef struct {
	Type       AssetRefType
	AssetId    AssetId
	GroupIndex uint16
}

func AssetRefFromId(assetId AssetId) *AssetRef {
	return &AssetRef{
		Type:    AssetRefByID,
		AssetId: assetId,
	}
}

func AssetRefFromGroupIndex(groupIndex uint16) *AssetRef {
	return &AssetRef{
		Type:       AssetRefByGroup,
		GroupIndex: groupIndex,
	}
}

func (a AssetId) ToString() string {
	var buf [34]byte
	copy(buf[:32], a.TxHash[:])
	// Big endian encoding for index
	buf[32] = byte(a.Index >> 8)
	buf[33] = byte(a.Index)
	return hex.EncodeToString(buf[:])
}

func AssetIdFromString(s string) (*AssetId, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(buf) != 34 {
		return nil, fmt.Errorf("invalid asset id length: %d", len(buf))
	}

	var assetId AssetId
	copy(assetId.TxHash[:], buf[:32])
	// Big endian decoding for index
	assetId.Index = uint16(buf[32])<<8 | uint16(buf[33])
	return &assetId, nil
}

type AssetGroup struct {
	AssetId      *AssetId
	Immutable    bool
	Outputs      []AssetOutput // 8 + 33
	ControlAsset *AssetRef
	Inputs       []AssetInput
	Metadata     []Metadata
}

type AssetPacket struct {
	Assets  []AssetGroup
	Version byte
}

type SubDustPacket struct {
	Key *btcec.PublicKey
}

type OpReturnPacket struct {
	Asset   *AssetPacket
	SubDust *SubDustPacket
}

var ArkadeMagic []byte = []byte{0x41, 0x52, 0x4B} // "ARK"

const (
	MarkerSubDustKey   byte = 0x01
	MarkerAssetPayload byte = 0x00
)

type Metadata struct {
	Key   string
	Value string
}

type AssetOutput struct {
	Type       AssetType
	Vout       uint32   // For Local
	Commitment [32]byte // For Teleport
	Amount     uint64
}

type AssetType uint8

const (
	AssetTypeLocal    AssetType = 0x01
	AssetTypeTeleport AssetType = 0x02
)

type TeleportWitness struct {
	Script []byte
	Nonce  [32]byte
}

func CalculateTeleportHash(script []byte, nonce [32]byte) [32]byte {
	var buf bytes.Buffer
	buf.Write(script)
	buf.Write(nonce[:])
	return sha256.Sum256(buf.Bytes())
}

type AssetInput struct {
	Type       AssetType
	Vin        uint32          // For Local
	Commitment [32]byte        // For Teleport
	Witness    TeleportWitness // For Teleport
	Amount     uint64
}

func (g *AssetPacket) EncodeAssetPacket(amount int64, subDust *SubDustPacket) (wire.TxOut, error) {
	return EncodeOpReturnPacket(amount, &OpReturnPacket{
		Asset:   g,
		SubDust: subDust,
	})
}

func EncodeOpReturnPacket(amount int64, packet *OpReturnPacket) (wire.TxOut, error) {
	if packet == nil || (packet.Asset == nil && (packet.SubDust == nil || packet.SubDust.Key == nil)) {
		return wire.TxOut{}, errors.New("empty op_return packet")
	}

	var scratch [8]byte
	var tlvData bytes.Buffer
	if _, err := tlvData.Write(ArkadeMagic); err != nil {
		return wire.TxOut{}, err
	}
	if packet.SubDust != nil && packet.SubDust.Key != nil {
		if err := tlvData.WriteByte(MarkerSubDustKey); err != nil {
			return wire.TxOut{}, err
		}
		subDustKey := schnorr.SerializePubKey(packet.SubDust.Key)
		if err := tlv.WriteVarInt(&tlvData, uint64(len(subDustKey)), &scratch); err != nil {
			return wire.TxOut{}, err
		}
		if _, err := tlvData.Write(subDustKey); err != nil {
			return wire.TxOut{}, err
		}
	}
	if packet.Asset != nil {
		encodedAssets, err := encodeAssetPacket(packet.Asset.Assets)
		if err != nil {
			return wire.TxOut{}, err
		}

		version := packet.Asset.Version
		if version == 0 {
			version = AssetVersion
		}

		assetData := append([]byte{version}, encodedAssets...)

		if err := tlvData.WriteByte(MarkerAssetPayload); err != nil {
			return wire.TxOut{}, err
		}
		if err := tlv.WriteVarInt(&tlvData, uint64(len(assetData)), &scratch); err != nil {
			return wire.TxOut{}, err
		}
		if _, err := tlvData.Write(assetData); err != nil {
			return wire.TxOut{}, err
		}
	}

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	builder.AddFullData(tlvData.Bytes())
	opReturnPubkey, err := builder.Script()
	if err != nil {
		return wire.TxOut{}, err
	}

	return wire.TxOut{
		Value:    amount,
		PkScript: opReturnPubkey,
	}, nil
}

func DecodeAssetPacket(opReturnData []byte) (*AssetPacket, error) {
	packet, err := DecodeOpReturnPacket(opReturnData)
	if err != nil {
		return nil, err
	}
	if packet.Asset == nil {
		return nil, errors.New("missing asset payload")
	}
	return packet.Asset, nil
}

func DecodeSubDustPacket(opReturnData []byte) (*SubDustPacket, error) {
	packet, err := DecodeOpReturnPacket(opReturnData)
	if err != nil {
		return nil, err
	}
	return packet.SubDust, nil
}

func DecodeOpReturnPacket(opReturnData []byte) (*OpReturnPacket, error) {
	if len(opReturnData) == 0 || opReturnData[0] != txscript.OP_RETURN {
		return nil, errors.New("OP_RETURN not present")
	}

	assetPayload, subDustKey, err := parsePacketOpReturn(opReturnData)
	if err != nil {
		return nil, err
	}

	packet := &OpReturnPacket{}
	if len(assetPayload) > 0 {
		if len(assetPayload) < 1 {
			return nil, errors.New("invalid asset op_return payload")
		}

		version := assetPayload[0]
		payload := assetPayload[1:]

		assetPacket, err := decodeAssetPacket(payload, version)
		if err != nil {
			return nil, err
		}
		packet.Asset = assetPacket
	}

	if len(subDustKey) > 0 {
		key, err := schnorr.ParsePubKey(subDustKey)
		if err != nil {
			return nil, err
		}
		packet.SubDust = &SubDustPacket{Key: key}
	}

	if packet.Asset == nil && packet.SubDust == nil {
		return nil, errors.New("missing op_return payload")
	}

	return packet, nil
}

func IsAssetPacket(opReturnData []byte) bool {
	payload, _, err := parsePacketOpReturn(opReturnData)
	return err == nil && len(payload) > 0
}

func (a *AssetGroup) EncodeTlv() ([]byte, error) {
	var tlvRecords []tlv.Record

	if a.AssetId != nil {
		tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
			tlvTypeAssetID,
			a.AssetId,
			AssetIdSize(a.AssetId),
			EAssetId, nil))
	}

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
		tlvTypeImmutable,
		&a.Immutable))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeOutput,
		&a.Outputs,
		AssetOutputListSize(a.Outputs),
		EAssetOutputList, nil))

	if a.ControlAsset != nil {
		tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
			tlvTypeControlAssetId,
			a.ControlAsset,
			AssetRefSize(a.ControlAsset),
			EAssetRef, nil))
	}

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeInput,
		&a.Inputs,
		AssetInputListSize(a.Inputs),
		EAssetInputList, nil))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeMetadata, &a.Metadata, MetadataListSize(a.Metadata), EMetadataList, nil))

	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = tlvStream.Encode(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (a *AssetGroup) DecodeTlv(data []byte) error {
	tlvStream, err := tlv.NewStream(
		tlv.MakeDynamicRecord(
			tlvTypeAssetID,
			&a.AssetId,
			AssetIdSize(nil),
			nil,
			DAssetIdPtr,
		),

		tlv.MakePrimitiveRecord(
			tlvTypeImmutable,
			&a.Immutable,
		),

		tlv.MakeDynamicRecord(
			tlvTypeOutput,
			&a.Outputs,
			AssetOutputListSize(a.Outputs),
			nil,
			DAssetOutputList,
		),
		tlv.MakeDynamicRecord(
			tlvTypeControlAssetId,
			&a.ControlAsset,
			AssetRefSize(nil),
			nil,
			DAssetRefPtr,
		),
		tlv.MakeDynamicRecord(
			tlvTypeInput,
			&a.Inputs,
			AssetInputListSize(a.Inputs),
			nil,
			DAssetInputList,
		),
		tlv.MakeDynamicRecord(
			tlvTypeMetadata,
			&a.Metadata,
			MetadataListSize(a.Metadata),
			nil,
			DMetadataList,
		),
	)
	if err != nil {
		return err
	}

	buf := bytes.NewReader(data)
	return tlvStream.Decode(buf)
}

func DeriveAssetGroupFromTx(arkTx string) (*AssetPacket, error) {
	decodedArkTx, err := psbt.NewFromRawBytes(strings.NewReader(arkTx), true)
	if err != nil {
		return nil, fmt.Errorf("error decoding Ark Tx: %s", err)
	}

	for _, output := range decodedArkTx.UnsignedTx.TxOut {
		if IsAssetPacket(output.PkScript) {
			assetGroup, err := DecodeAssetPacket(output.PkScript)
			if err != nil {
				return nil, fmt.Errorf("error decoding asset Opreturn: %s", err)
			}
			return assetGroup, nil
		}
	}

	return nil, errors.New("no asset opreturn found in transaction")

}

func encodeAssetPacket(assets []AssetGroup) ([]byte, error) {
	var scratch [8]byte
	var buf bytes.Buffer

	totalCount := uint64(len(assets))

	if err := tlv.WriteVarInt(&buf, totalCount, &scratch); err != nil {
		return nil, err
	}

	for _, asset := range assets {
		encodedAsset, err := asset.EncodeTlv()
		if err != nil {
			return nil, err
		}

		if err := tlv.WriteVarInt(&buf, uint64(len(encodedAsset)), &scratch); err != nil {
			return nil, err
		}

		if _, err := buf.Write(encodedAsset); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// parsePacketOpReturn extracts the asset payload and optional sub-dust pubkey from an OP_RETURN script.
// (OP_RETURN <type><length><value> <type><length><value> ...).
func parsePacketOpReturn(opReturnData []byte) ([]byte, []byte, error) {
	if len(opReturnData) == 0 || opReturnData[0] != txscript.OP_RETURN {
		return nil, nil, errors.New("OP_RETURN not present")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, opReturnData)
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_RETURN {
		if err := tokenizer.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("invalid OP_RETURN script")
	}

	var payload []byte

	for tokenizer.Next() {
		data := tokenizer.Data()
		if data == nil {
			return nil, nil, errors.New("invalid OP_RETURN data push")
		}

		payload = append(payload, data...)
	}

	if err := tokenizer.Err(); err != nil {
		return nil, nil, err
	}

	if len(payload) == 0 {
		return nil, nil, errors.New("missing OP_RETURN payload")
	}

	if len(payload) < len(ArkadeMagic) || !bytes.HasPrefix(payload, ArkadeMagic) {
		return nil, nil, errors.New("invalid op_return payload magic")
	}

	payload = payload[len(ArkadeMagic):]

	var subDustKey []byte
	var assetPayload []byte
	reader := bytes.NewReader(payload)
	var scratch [8]byte

	for reader.Len() > 0 {
		typ, err := reader.ReadByte()
		if err != nil {
			return nil, nil, err
		}

		length, err := tlv.ReadVarInt(reader, &scratch)
		if err != nil {
			return nil, nil, err
		}
		if uint64(reader.Len()) < length {
			return nil, nil, errors.New("invalid TLV length for OP_RETURN payload")
		}

		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, nil, err
		}

		switch typ {
		case MarkerSubDustKey:
			if subDustKey == nil {
				subDustKey = value
			}
		case MarkerAssetPayload:
			if assetPayload == nil {
				assetPayload = value
			}
		}
	}

	if len(assetPayload) == 0 && len(subDustKey) == 0 {
		return nil, nil, errors.New("missing op_return payload")
	}

	return assetPayload, subDustKey, nil
}

func normalizeAssetSlices(a *AssetGroup) {
	if len(a.Inputs) == 0 {
		a.Inputs = nil
	}
	if len(a.Outputs) == 0 {
		a.Outputs = nil
	}
	if len(a.Metadata) == 0 {
		a.Metadata = nil
	}
}

func decodeAssetPacket(payload []byte, version byte) (*AssetPacket, error) {
	reader := bytes.NewReader(payload)
	var scratch [8]byte

	assetCount, err := tlv.ReadVarInt(reader, &scratch)
	if err != nil {
		return nil, fmt.Errorf("invalid asset group count: %w", err)
	}

	if assetCount == 0 {
		return nil, errors.New("empty asset group")
	}

	assets := make([]AssetGroup, 0, int(assetCount))
	for i := uint64(0); i < assetCount; i++ {
		length, err := tlv.ReadVarInt(reader, &scratch)
		if err != nil {
			return nil, fmt.Errorf("failed to read asset length: %w", err)
		}

		if length == 0 || length > uint64(reader.Len()) {
			return nil, errors.New("asset length exceeds payload")
		}

		assetData := make([]byte, length)
		if _, err := io.ReadFull(reader, assetData); err != nil {
			return nil, fmt.Errorf("failed to read asset payload: %w", err)
		}

		var decoded AssetGroup
		if err := decoded.DecodeTlv(assetData); err != nil {
			return nil, fmt.Errorf("failed to decode asset: %w", err)
		}

		assets = append(assets, decoded)
	}

	for i := range assets {
		normalizeAssetSlices(&assets[i])
	}

	if reader.Len() != 0 {
		return nil, errors.New("unexpected trailing bytes in asset group payload")
	}

	group := &AssetPacket{
		Assets:  assets,
		Version: version,
	}

	return group, nil
}
