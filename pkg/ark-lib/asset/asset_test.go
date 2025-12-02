package asset

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestAssetEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	var assetID [32]byte
	copy(assetID[:], bytes.Repeat([]byte{0x2a}, 32))

	var controlAssetId [32]byte
	copy(controlAssetId[:], bytes.Repeat([]byte{0x3c}, 32))

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
		ControlAssetId: controlAssetId,
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
		Metadata: []Metadata{
			{Key: "purpose", Value: "roundtrip"},
			{Key: "owner", Value: "arkade"},
		},
	}

	encoded, err := asset.EncodeTlv()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	var decoded Asset
	require.NoError(t, decoded.DecodeTlv(encoded))
	require.Equal(t, asset, decoded)
}

func TestAssetGroupEncodeDecode(t *testing.T) {
	t.Parallel()

	var controlAssetId [32]byte
	copy(controlAssetId[:], bytes.Repeat([]byte{0x3c}, 32))

	controlAsset := Asset{
		AssetId:        deterministicBytesArray(0x11),
		Outputs:        []AssetOutput{{PublicKey: deterministicPubKey(t, 9), Amount: 1, Vout: 0}},
		ControlAssetId: controlAssetId,
		Metadata:       []Metadata{{Key: "kind", Value: "control"}},
		Version:        AssetVersion,
		Magic:          AssetMagic,
	}

	normalAsset := Asset{
		AssetId:        deterministicBytesArray(0x12),
		Outputs:        []AssetOutput{{PublicKey: deterministicPubKey(t, 10), Amount: 10, Vout: 1}},
		ControlAssetId: controlAssetId,
		Inputs:         []AssetInput{{Txid: deterministicTxid(0xcc), Vout: 1, Amount: 5}},
		Metadata:       []Metadata{{Key: "kind", Value: "normal"}},
		Version:        AssetVersion,
		Magic:          AssetMagic,
	}

	group := AssetGroup{
		ControlAsset: &controlAsset,
		NormalAsset:  normalAsset,
	}

	batchTxID := deterministicTxid(0xee)
	txOut, err := group.EncodeOpret(batchTxID)
	require.NoError(t, err)

	decodedGroup, decodedBatchTxID, err := DecodeAssetGroupFromOpret(txOut.PkScript)
	require.NoError(t, err)
	require.Equal(t, batchTxID, decodedBatchTxID)
	require.NotNil(t, decodedGroup.ControlAsset)
	require.Equal(t, controlAsset, *decodedGroup.ControlAsset)
	require.Equal(t, normalAsset, decodedGroup.NormalAsset)
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

func deterministicBytesArray(seed byte) [32]byte {
	var arr [32]byte
	copy(arr[:], deterministicTxid(seed))
	return arr
}
