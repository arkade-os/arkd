package asset

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
)

type Asset struct {
	AssetId       [32]byte
	Outputs       []AssetOutput // 8 + 33
	ControlPubkey *btcec.PublicKey
	Inputs        []AssetInput
	Immutable     bool
	Metadata      []Metadata

	// OP_RETURN
	genesisTxId []byte
	version     []byte
	magic       byte
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
	Txid   []byte
	Vout   uint32
	Amount uint64
}

func (a *Asset) EncodeOpret(batchTxId []byte) (wire.TxOut, error) {
	encodedTlv, err := a.encodeTlv()
	if err != nil {
		return wire.TxOut{}, err
	}
	assetData := append([]byte{AssetMagic}, a.version...)
	assetData = append(assetData, a.genesisTxId...)
	assetData = append(assetData, batchTxId...)
	assetData = append(assetData, encodedTlv...)

	opReturnPubkey := append([]byte{txscript.OP_RETURN}, assetData...)

	return wire.TxOut{
		Value:    0,
		PkScript: opReturnPubkey,
	}, nil

}

func DecodeAssetFromOpret(opReturnData []byte) (*Asset, []byte, error) {
	asset := &Asset{}

	// Verify OP_RETURN prefix
	if opReturnData[0] != txscript.OP_RETURN {
		return nil, nil, errors.New("OP_RETURN not present")
	}

	// Extract and set magic, version, genesisTxId
	asset.magic = opReturnData[1]

	if asset.magic != AssetMagic {
		return nil, nil, errors.New("invalid asset magic")
	}

	asset.version = opReturnData[2:3]
	asset.genesisTxId = opReturnData[3 : 3+32]
	batchTxId := opReturnData[3+32 : 3+32+32]

	err := asset.decodeTlv(opReturnData[1+2+32+32:])
	if err != nil {
		return nil, nil, err
	}

	return asset, batchTxId, nil

}

func IsAsset(opReturnData []byte) bool {
	if len(opReturnData) < 1 {
		return false
	}
	return opReturnData[0] == txscript.OP_RETURN && len(opReturnData) > 1 && opReturnData[1] == AssetMagic
}

func (a *Asset) encodeTlv() ([]byte, error) {
	var tlvRecords []tlv.Record

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
		tlvTypeAssetID,
		&a.AssetId,
	))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeOutput,
		&a.Outputs,
		AssetOutputListSize(len(a.Outputs)),
		EAssetOutputList, nil))

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
		tlvTypeControlPubkey,
		&a.ControlPubkey))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeInput,
		&a.Inputs,
		AssetInputListSize(len(a.Inputs)),
		EAssetInputList, nil))

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeMetadata, &a.Metadata, MetadataListSize(a.Metadata), EMetadataList, nil))

	tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(tlvTypeImmutable, &a.Immutable))

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

func (a *Asset) decodeTlv(data []byte) error {
	tlvStream, err := tlv.NewStream(
		tlv.MakePrimitiveRecord(
			tlvTypeAssetID,
			&a.AssetId,
		),
		tlv.MakeDynamicRecord(
			tlvTypeOutput,
			&a.Outputs,
			AssetOutputListSize(len(a.Outputs)),
			nil,
			DAssetOutputList,
		),
		tlv.MakePrimitiveRecord(
			tlvTypeControlPubkey,
			&a.ControlPubkey,
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
		tlv.MakePrimitiveRecord(
			tlvTypeImmutable,
			&a.Immutable,
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

	for _, out := range outs {
		// Asset Output comes after Seal Outputs
		if IsAsset(out.PkScript) {
			break
		}
		for _, assetOut := range assetOutputs {
			pkScript, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				return err
			}
			if pkScript.IsEqual(&assetOut.PublicKey) {
				processedOutputs++
			}
		}
	}

	if processedOutputs != len(assetOutputs) {
		return errors.New("not all asset outputs found in transaction outputs")
	}

	return nil
}

func VerifyAssetInputs(ins []*wire.TxIn, assetInputs []AssetInput) error {
	processedInputs := 0

	for _, assetIn := range assetInputs {
		for _, in := range ins {
			if bytes.Equal(in.PreviousOutPoint.Hash[:], assetIn.Txid) && in.PreviousOutPoint.Index == assetIn.Vout {
				processedInputs++
			}
		}
	}

	if processedInputs != len(assetInputs) {
		return errors.New("not all asset inputs found in transaction inputs")
	}

	return nil
}

