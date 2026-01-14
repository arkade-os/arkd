package extension

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
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

func (g *AssetPacket) EncodeAssetPacket() (wire.TxOut, error) {
	opReturnPacket := &OpReturnPacket{
		Asset: g,
	}
	return opReturnPacket.EncodeOpReturnPacket()
}

func DecodeAssetPacket(txOut wire.TxOut) (*AssetPacket, error) {
	packet, err := DecodeOpReturnPacket(txOut)
	if err != nil {
		return nil, err
	}
	if packet.Asset == nil {
		return nil, errors.New("missing asset payload")
	}
	return packet.Asset, nil
}

func ContainsAssetPacket(opReturnData []byte) bool {
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
		if ContainsAssetPacket(output.PkScript) {
			assetPacket, err := DecodeAssetPacket(*output)
			if err != nil {
				return nil, fmt.Errorf("error decoding asset Opreturn: %s", err)
			}
			return assetPacket, nil
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
