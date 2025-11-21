package asset

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestEncodeOpretAndDecodeAsset(t *testing.T) {
	t.Parallel()

	var assetID [32]byte
	copy(assetID[:], bytes.Repeat([]byte{0x3c}, 32))

	controlKey := deterministicPubKey(t, 7)

	genesisTxID := deterministicTxid(0xee)
	batchTxID := deterministicTxid(0xdd)

	asset := Asset{
		AssetId:       assetID,
		Outputs:       []AssetOutput{{PublicKey: deterministicPubKey(t, 8), Amount: 50, Vout: 0}},
		ControlPubkey: &controlKey,
		Inputs:        []AssetInput{{Txid: deterministicTxid(0x0a), Vout: 2, Amount: 80}},
		Immutable:     true,
		Metadata:      []Metadata{{Key: "note", Value: "opret"}},
		version:       []byte{0x01},
		genesisTxId:   genesisTxID,
		magic:         AssetMagic,
	}

	txOut, err := asset.EncodeOpret(batchTxID)
	require.NoError(t, err)
	require.True(t, IsAsset(txOut.PkScript))

	decoded, decodedBatchTxID, err := DecodeAssetFromOpret(txOut.PkScript)
	require.NoError(t, err)
	require.Equal(t, batchTxID, decodedBatchTxID)
	require.Equal(t, asset, *decoded)
}

func TestAssetEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	var assetID [32]byte
	copy(assetID[:], bytes.Repeat([]byte{0x2a}, 32))

	controlKey := deterministicPubKey(t, 3)

	asset := Asset{
		AssetId: assetID,
		Outputs: []AssetOutput{
			{
				PublicKey: deterministicPubKey(t, 1),
				Amount:    11,
				Vout:      0,
			},
			{
				PublicKey: deterministicPubKey(t, 2),
				Amount:    22,
				Vout:      1,
			},
		},
		ControlPubkey: &controlKey,
		Inputs: []AssetInput{
			{
				Txid: deterministicTxid(0xaa),
				Vout: 7,
			},
			{
				Txid: deterministicTxid(0xbb),
				Vout: 9,
			},
		},
		Immutable: true,
		Metadata: []Metadata{
			{Key: "purpose", Value: "roundtrip"},
			{Key: "owner", Value: "arkade"},
		},
	}

	encoded, err := asset.encodeTlv()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	var decoded Asset
	require.NoError(t, decoded.decodeTlv(encoded))
	require.Equal(t, asset, decoded)
}

func TestAssetOutputListEncodeDecode(t *testing.T) {
	t.Parallel()

	outputs := []AssetOutput{
		{
			PublicKey: deterministicPubKey(t, 4),
			Vout:      0,
			Amount:    100,
		},
		{
			PublicKey: deterministicPubKey(t, 5),
			Vout:      1,
			Amount:    200,
		},
	}

	var scratch [8]byte
	var buf bytes.Buffer
	require.NoError(t, EAssetOutputList(&buf, &outputs, &scratch))

	var decoded []AssetOutput
	reader := bytes.NewReader(buf.Bytes())
	require.NoError(t, DAssetOutputList(reader, &decoded, &scratch, uint64(buf.Len())))
	require.Equal(t, outputs, decoded)
}

func TestAssetInputListEncodeDecode(t *testing.T) {
	t.Parallel()

	inputs := []AssetInput{
		{
			Txid:   deterministicTxid(0x01),
			Amount: 80,
			Vout:   1,
		},
		{
			Txid:   deterministicTxid(0x02),
			Amount: 20,
			Vout:   2,
		},
	}

	var scratch [8]byte
	var buf bytes.Buffer
	require.NoError(t, EAssetInputList(&buf, &inputs, &scratch))

	var decoded []AssetInput
	reader := bytes.NewReader(buf.Bytes())
	require.NoError(t, DAssetInputList(reader, &decoded, &scratch, uint64(buf.Len())))
	require.Equal(t, inputs, decoded)
}

func deterministicPubKey(t *testing.T, seed byte) btcec.PublicKey {
	t.Helper()

	keyBytes := bytes.Repeat([]byte{seed}, 32)
	priv, pub := btcec.PrivKeyFromBytes(keyBytes)
	require.NotNil(t, priv)
	require.NotNil(t, pub)

	return *pub
}

func deterministicTxid(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, 32)
}
