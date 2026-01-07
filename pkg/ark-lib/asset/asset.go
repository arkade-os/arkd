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
	TxId  [32]byte
	Index uint16
}

func (a AssetId) ToString() string {
	var buf [34]byte
	copy(buf[:32], a.TxId[:])
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
	copy(assetId.TxId[:], buf[:32])
	// Big endian decoding for index
	assetId.Index = uint16(buf[32])<<8 | uint16(buf[33])
	return &assetId, nil
}

type AssetGroup struct {
	AssetId        AssetId
	Immutable      bool
	Outputs        []AssetOutput // 8 + 33
	ControlAssetId *AssetId
	Inputs         []AssetInput
	Metadata       []Metadata

	// OP_RETURN
	Version byte
	Magic   []byte
}

type AssetPacket struct {
	ControlAssets []AssetGroup
	NormalAssets  []AssetGroup
	SubDustKey    *btcec.PublicKey
}

var AssetMagic []byte = []byte{0x41, 0x52, 0x4B} // "ARK"

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

func (g *AssetPacket) EncodeAssetPacket(amount int64) (wire.TxOut, error) {
	encodedAssets, err := encodeAssetPacket(g.ControlAssets, g.NormalAssets)
	if err != nil {
		return wire.TxOut{}, err
	}

	version := AssetVersion
	// Use version from first normal asset if available, else default
	if len(g.NormalAssets) > 0 && g.NormalAssets[0].Version != 0 {
		version = g.NormalAssets[0].Version
	}

	assetData := append(append([]byte{}, AssetMagic...), version)
	assetData = append(assetData, encodedAssets...)

	var scratch [8]byte
	var tlvData bytes.Buffer
	if g.SubDustKey != nil {
		if err := tlvData.WriteByte(MarkerSubDustKey); err != nil {
			return wire.TxOut{}, err
		}
		subDustKey := schnorr.SerializePubKey(g.SubDustKey)
		if err := tlv.WriteVarInt(&tlvData, uint64(len(subDustKey)), &scratch); err != nil {
			return wire.TxOut{}, err
		}
		if _, err := tlvData.Write(subDustKey); err != nil {
			return wire.TxOut{}, err
		}
	}
	if err := tlvData.WriteByte(MarkerAssetPayload); err != nil {
		return wire.TxOut{}, err
	}
	if err := tlv.WriteVarInt(&tlvData, uint64(len(assetData)), &scratch); err != nil {
		return wire.TxOut{}, err
	}
	if _, err := tlvData.Write(assetData); err != nil {
		return wire.TxOut{}, err
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
	if len(opReturnData) == 0 || opReturnData[0] != txscript.OP_RETURN {
		return nil, errors.New("OP_RETURN not present")
	}

	assetPayload, subDustKey, err := parsePacketOpReturn(opReturnData)
	if err != nil {
		return nil, err
	}

	if len(assetPayload) < len(AssetMagic)+1 || !bytes.HasPrefix(assetPayload, AssetMagic) {
		return nil, errors.New("invalid asset op_return payload")
	}

	version := assetPayload[len(AssetMagic)]
	payload := assetPayload[len(AssetMagic)+1:]

	packet, err := decodeAssetPacket(payload, version)
	if err != nil {
		return nil, err
	}

	if len(subDustKey) > 0 {
		key, keyErr := schnorr.ParsePubKey(subDustKey)
		if keyErr == nil {
			packet.SubDustKey = key
		}
	}

	return packet, nil
}

func IsAssetPacket(opReturnData []byte) bool {
	payload, _, err := parsePacketOpReturn(opReturnData)
	if err == nil && len(payload) >= len(AssetMagic)+1 {
		return bytes.HasPrefix(payload, AssetMagic)
	}
	return false
}

func (a *AssetGroup) EncodeTlv() ([]byte, error) {
	var tlvRecords []tlv.Record

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeAssetID,
		&a.AssetId,
		AssetIdSize(&a.AssetId),
		EAssetId, nil))

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
		tlvTypeImmutable,
		&a.Immutable))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeOutput,
		&a.Outputs,
		AssetOutputListSize(a.Outputs),
		EAssetOutputList, nil))

	if a.ControlAssetId != nil {
		tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
			tlvTypeControlAssetId,
			a.ControlAssetId,
			AssetIdSize(a.ControlAssetId),
			EAssetId, nil))
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
			DAssetId,
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
			&a.ControlAssetId,
			AssetIdSize(nil),
			nil,
			DAssetIdPtr,
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

func VerifyAssetOutputs(outs []*wire.TxOut, assetOutputs []AssetOutput) error {

	processedOutputs := 0

	for _, assetOut := range assetOutputs {
		switch assetOut.Type {
		case AssetTypeLocal:
			for index := range outs {
				if index == int(assetOut.Vout) {
					processedOutputs++
					break
				}
			}
		case AssetTypeTeleport:
			processedOutputs++
		default:
			return fmt.Errorf("unknown asset output type %d", assetOut.Type)
		}
	}

	if processedOutputs != len(assetOutputs) {
		errors := fmt.Errorf("not all asset outputs verified: processed %d of %d",
			processedOutputs, len(assetOutputs))
		return errors
	}

	return nil
}

func VerifyAssetInputs(ins []*wire.TxIn, assetInputs []AssetInput) error {
	processedInputs := 0

	for _, assetIn := range assetInputs {
		switch assetIn.Type {
		case AssetTypeLocal:
			if int(assetIn.Vin) >= len(ins) {
				return fmt.Errorf("asset input index out of range: %d", assetIn.Vin)
			}
			processedInputs++
		case AssetTypeTeleport:
			processedInputs++
		default:
			return fmt.Errorf("unknown asset input type %d", assetIn.Type)
		}
	}

	if processedInputs != len(assetInputs) {
		errors := fmt.Errorf("not all asset inputs verified: processed %d of %d",
			processedInputs, len(assetInputs))
		return errors
	}

	return nil
}

func VerifyAssetOutputInTx(arkTx string, vout uint32) error {
	decodedArkTx, err := psbt.NewFromRawBytes(strings.NewReader(arkTx), true)
	if err != nil {
		return fmt.Errorf("error decoding Ark Tx: %s", err)
	}

	var assetGroup *AssetPacket
	var assetGroupIndex int

	for i, output := range decodedArkTx.UnsignedTx.TxOut {
		if IsAssetPacket(output.PkScript) {
			assetGp, err := DecodeAssetPacket(output.PkScript)
			if err != nil {
				return fmt.Errorf("error decoding asset Opreturn: %s", err)
			}
			assetGroup = assetGp
			assetGroupIndex = i
			break
		}
	}

	// verify asset input in present in assetGroup.Inputs
	totalAssetOuts := make([]AssetOutput, 0)
	for _, asset := range assetGroup.NormalAssets {
		totalAssetOuts = append(totalAssetOuts, asset.Outputs...)
	}

	for _, asset := range assetGroup.ControlAssets {
		totalAssetOuts = append(totalAssetOuts, asset.Outputs...)
	}

	assetOutFound := false
	for _, assetOut := range totalAssetOuts {
		if assetOut.Vout == vout {
			assetOutFound = true
			break
		}
	}

	if !assetOutFound {
		return fmt.Errorf("asset output %d not found", vout)
	}

	// verify sealPresent
	sealPresent := false
	for i, _ := range decodedArkTx.UnsignedTx.TxOut {
		if i == assetGroupIndex {
			return fmt.Errorf("output not present")
		}

		if i == int(vout) {
			sealPresent = true
			break
		}
	}

	if !sealPresent {
		return fmt.Errorf("seal not present")
	}

	return nil
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

func encodeAssetPacket(controlAssets, normalAssets []AssetGroup) ([]byte, error) {
	var scratch [8]byte
	var buf bytes.Buffer

	totalCount := uint64(len(controlAssets) + len(normalAssets))
	controlCount := uint64(len(controlAssets))

	if err := tlv.WriteVarInt(&buf, totalCount, &scratch); err != nil {
		return nil, err
	}

	if err := tlv.WriteVarInt(&buf, controlCount, &scratch); err != nil {
		return nil, err
	}

	allAssets := append(controlAssets, normalAssets...)

	for _, asset := range allAssets {
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

// parseAssetOpReturn extracts the asset payload and optional sub-dust pubkey from an OP_RETURN script.
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

	if len(assetPayload) == 0 {
		return nil, subDustKey, errors.New("missing asset payload")
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

	controlCount, err := tlv.ReadVarInt(reader, &scratch)
	if err != nil {
		return nil, fmt.Errorf("invalid control asset count: %w", err)
	}

	if controlCount > assetCount {
		return nil, fmt.Errorf("control asset count %d exceeds total asset count %d", controlCount, assetCount)
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
		decoded.Magic = AssetMagic
		decoded.Version = version
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
		ControlAssets: assets[:controlCount],
		NormalAssets:  assets[controlCount:],
	}

	return group, nil
}
