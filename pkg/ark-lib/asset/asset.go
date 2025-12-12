package asset

import (
	"bytes"
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

type Asset struct {
	AssetId        [32]byte
	Immutable      bool
	Outputs        []AssetOutput // 8 + 33
	ControlAssetId [32]byte
	Inputs         []AssetInput
	Metadata       []Metadata

	// OP_RETURN
	Version byte
	Magic   byte
}

type AssetGroup struct {
	ControlAsset *Asset
	NormalAsset  Asset
	SubDustKey   *btcec.PublicKey
}

const AssetMagic byte = 0x41 // 'A'

type Metadata struct {
	Key   string
	Value string
}

type AssetOutput struct {
	PublicKey btcec.PublicKey
	Vout      uint32
	Amount    uint64
}

type AssetInput struct {
	Txhash []byte
	Vout   uint32
	Amount uint64
}

func (g *AssetGroup) EncodeOpret(batchTxId []byte) (wire.TxOut, error) {
	assets := make([]Asset, 0, 2)
	if g.ControlAsset != nil {
		assets = append(assets, *g.ControlAsset)
	}
	assets = append(assets, g.NormalAsset)

	encodedAssets, err := encodeAssetGroupPayload(assets)
	if err != nil {
		return wire.TxOut{}, err
	}

	version := g.NormalAsset.Version
	if version == 0 {
		version = AssetVersion
	}

	assetData := []byte{AssetMagic, version}
	assetData = append(assetData, batchTxId...)
	assetData = append(assetData, encodedAssets...)

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	if g.SubDustKey != nil {
		builder.AddData(schnorr.SerializePubKey(g.SubDustKey))
	}
	builder.AddData(assetData)

	opReturnPubkey, err := builder.Script()
	if err != nil {
		return wire.TxOut{}, err
	}

	return wire.TxOut{
		Value:    0,
		PkScript: opReturnPubkey,
	}, nil
}

func encodeAssetGroupPayload(assets []Asset) ([]byte, error) {
	var scratch [8]byte
	var buf bytes.Buffer

	if err := tlv.WriteVarInt(&buf, uint64(len(assets)), &scratch); err != nil {
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

// parseAssetOpReturn extracts the asset payload and optional sub-dust pubkey
// from an OP_RETURN script. It expects scripts built with pushdata elements
// (OP_RETURN <subdust_pubkey?> <asset_payload>).
func parseAssetOpReturn(opReturnData []byte) ([]byte, []byte, error) {
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

	var dataPushes [][]byte

	for tokenizer.Next() {
		data := tokenizer.Data()
		if data == nil {
			return nil, nil, errors.New("unexpected opcode in OP_RETURN")
		}

		pushCopy := make([]byte, len(data))
		copy(pushCopy, data)
		dataPushes = append(dataPushes, pushCopy)
	}

	if err := tokenizer.Err(); err != nil {
		return nil, nil, err
	}

	if len(dataPushes) == 0 {
		return nil, nil, errors.New("missing OP_RETURN payload")
	}

	assetPayload := dataPushes[len(dataPushes)-1]
	var subDustKey []byte

	if len(dataPushes) >= 2 && len(dataPushes[0]) == schnorr.PubKeyBytesLen {
		subDustKey = dataPushes[0]
	}

	return assetPayload, subDustKey, nil
}

func normalizeAssetSlices(a *Asset) {
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

func decodeAssetGroupPayload(payload []byte, version byte) (*AssetGroup, error) {
	reader := bytes.NewReader(payload)
	var scratch [8]byte

	assetCount, err := tlv.ReadVarInt(reader, &scratch)
	if err != nil || assetCount == 0 {
		return nil, fmt.Errorf("invalid asset group count: %w", err)
	}

	assets := make([]Asset, 0, int(assetCount))
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

		var decoded Asset
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

	group := &AssetGroup{}
	switch len(assets) {
	case 0:
		return nil, errors.New("empty asset group")
	case 1:
		group.NormalAsset = assets[0]
	default:
		group.ControlAsset = &assets[0]
		group.NormalAsset = assets[len(assets)-1]
	}

	return group, nil
}

func DecodeAssetGroupFromOpret(opReturnData []byte) (*AssetGroup, []byte, error) {
	if len(opReturnData) == 0 || opReturnData[0] != txscript.OP_RETURN {
		return nil, nil, errors.New("OP_RETURN not present")
	}

	assetPayload, subDustKey, err := parseAssetOpReturn(opReturnData)
	if err == nil && len(assetPayload) >= 34 && assetPayload[0] == AssetMagic {
		version := assetPayload[1]
		batchTxId := assetPayload[2 : 2+32]

		setSubDustKey := func(g *AssetGroup) {
			if len(subDustKey) == 0 {
				return
			}
			key, keyErr := schnorr.ParsePubKey(subDustKey)
			if keyErr == nil {
				g.SubDustKey = key
			}
		}

		group, decodeErr := decodeAssetGroupPayload(assetPayload[2+32:], version)
		if decodeErr == nil {
			setSubDustKey(group)
			return group, batchTxId, nil
		}

		var single Asset
		single.Magic = AssetMagic
		single.Version = version
		if err := single.DecodeTlv(assetPayload[2+32:]); err == nil {
			normalizeAssetSlices(&single)
			group := &AssetGroup{NormalAsset: single}
			setSubDustKey(group)
			return group, batchTxId, nil
		}
	}

	// Fallback to legacy single-asset layout where asset payload starts
	// immediately after OP_RETURN.
	if len(opReturnData) < 3+32 || opReturnData[1] != AssetMagic {
		return nil, nil, errors.New("invalid asset op_return payload")
	}

	version := opReturnData[2]
	batchTxId := opReturnData[3 : 3+32]

	group, err := decodeAssetGroupPayload(opReturnData[3+32:], version)
	if err == nil {
		return group, batchTxId, nil
	}

	// Fallback to legacy single-asset layout.
	var asset Asset
	asset.Magic = AssetMagic
	asset.Version = version

	if err := asset.DecodeTlv(opReturnData[3+32:]); err != nil {
		return nil, nil, fmt.Errorf("failed to decode asset data: %w", err)
	}

	normalizeAssetSlices(&asset)
	return &AssetGroup{NormalAsset: asset}, batchTxId, nil

}

func IsAssetGroup(opReturnData []byte) bool {
	payload, _, err := parseAssetOpReturn(opReturnData)
	if err == nil && len(payload) > 0 {
		return payload[0] == AssetMagic
	}

	// Legacy layout: OP_RETURN <AssetMagic> <Version> ...
	return len(opReturnData) > 1 &&
		opReturnData[0] == txscript.OP_RETURN &&
		opReturnData[1] == AssetMagic
}

func (a *Asset) EncodeTlv() ([]byte, error) {
	var tlvRecords []tlv.Record

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
		tlvTypeAssetID,
		&a.AssetId,
	))

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
		tlvTypeImmutable,
		&a.Immutable))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeOutput,
		&a.Outputs,
		AssetOutputListSize(len(a.Outputs)),
		EAssetOutputList, nil))

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
		tlvTypeControlAssetId,
		&a.ControlAssetId))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeInput,
		&a.Inputs,
		AssetInputListSize(len(a.Inputs)),
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

func (a *Asset) DecodeTlv(data []byte) error {
	tlvStream, err := tlv.NewStream(
		tlv.MakePrimitiveRecord(
			tlvTypeAssetID,
			&a.AssetId,
		),

		tlv.MakePrimitiveRecord(
			tlvTypeImmutable,
			&a.Immutable,
		),

		tlv.MakeDynamicRecord(
			tlvTypeOutput,
			&a.Outputs,
			AssetOutputListSize(len(a.Outputs)),
			nil,
			DAssetOutputList,
		),
		tlv.MakePrimitiveRecord(
			tlvTypeControlAssetId,
			&a.ControlAssetId,
		),
		tlv.MakeDynamicRecord(
			tlvTypeInput,
			&a.Inputs,
			AssetInputListSize(len(a.Inputs)),
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

func verifyAssetOutputs(outs []*wire.TxOut, assetOutputs []AssetOutput) error {

	processedOutputs := 0

	for _, assetOut := range assetOutputs {

		for i, out := range outs {
			// Asset Output comes after Seal Outputs
			if IsAssetGroup(out.PkScript) {
				break
			}

			pkScript, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				return err
			}
			if pkScript.IsEqual(&assetOut.PublicKey) && uint32(i) == assetOut.Vout {
				processedOutputs++
			}
		}
	}

	if processedOutputs != len(assetOutputs) {
		// also error out processedOutputs and len(assetOutputs) for easier debugging
		errors := fmt.Errorf("not all asset outputs found in transaction outputs: processed %d of %d",
			processedOutputs, len(assetOutputs))
		return errors
	}

	return nil
}

func verifyAssetInputs(ins []*wire.TxIn, assetInputs []AssetInput) error {
	processedInputs := 0

	for _, assetIn := range assetInputs {
		for _, in := range ins {
			if bytes.Equal(in.PreviousOutPoint.Hash[:], assetIn.Txhash) && in.PreviousOutPoint.Index == assetIn.Vout {
				processedInputs++
			}
		}
	}

	if processedInputs != len(assetInputs) {
		return errors.New("not all asset inputs found in transaction inputs")
	}

	return nil
}

func ValidateAssetInputOutputs(ins []*wire.TxIn, outs []*wire.TxOut, asset Asset) error {
	if err := verifyAssetInputs(ins, asset.Inputs); err != nil {
		return fmt.Errorf("asset input verification failed: %w", err)
	}

	if err := verifyAssetOutputs(outs, asset.Outputs); err != nil {
		return fmt.Errorf("asset output verification failed: %w", err)
	}

	return nil
}

func IsAssetCreation(asset Asset) bool {
	return len(asset.Inputs) == 0
}

func DeriveAssetGroupFromTx(arkTx string) (*AssetGroup, error) {
	decodedArkTx, err := psbt.NewFromRawBytes(strings.NewReader(arkTx), true)
	if err != nil {
		return nil, fmt.Errorf("error decoding Ark Tx: %s", err)
	}

	for _, output := range decodedArkTx.UnsignedTx.TxOut {
		if IsAssetGroup(output.PkScript) {
			assetGroup, _, err := DecodeAssetGroupFromOpret(output.PkScript)
			if err != nil {
				return nil, fmt.Errorf("error decoding asset Opreturn: %s", err)
			}
			return assetGroup, nil
		}
	}

	return nil, errors.New("no asset opreturn found in transaction")

}
