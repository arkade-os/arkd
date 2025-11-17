package asset

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/tlv"
)

type Asset struct {
	AssetId        [32]byte
	Outputs        []AssetOutput // 8 + 33
	ControlOutputs []AssetOutput
	Inputs         []AssetInput
	Immutable      bool
	Metadata       []Metadata
}

type Metadata struct {
	Key   string
	Value string
}

type AssetOutput struct {
	PublicKey btcec.PublicKey
	Amount    uint64
}

type AssetInput struct {
	Txid []byte
	Vout uint32
}

func (a *Asset) Encode() ([]byte, error) {
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

	tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
		tlvTypeControlOutput,
		&a.ControlOutputs,
		AssetOutputListSize(len(a.ControlOutputs)),
		EAssetOutputList, nil))

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

func (a *Asset) Decode(data []byte) error {
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
		tlv.MakeDynamicRecord(
			tlvTypeControlOutput,
			&a.ControlOutputs,
			AssetOutputListSize(len(a.ControlOutputs)),
			nil,
			DAssetOutputList,
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
