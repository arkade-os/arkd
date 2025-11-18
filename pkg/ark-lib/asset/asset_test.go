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

	asset := Asset{
		AssetId: assetID,
		Outputs: []AssetOutput{
			{
				PublicKey: deterministicPubKey(t, 1),
				Amount:    11,
			},
			{
				PublicKey: deterministicPubKey(t, 2),
				Amount:    22,
			},
		},
		ControlOutputs: []AssetOutput{
			{
				PublicKey: deterministicPubKey(t, 3),
				Amount:    33,
			},
		},
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
	require.NoError(t, decoded.Decode(encoded))
	require.Equal(t, asset, decoded)
}

func TestAssetOutputListEncodeDecode(t *testing.T) {
	t.Parallel()

	outputs := []AssetOutput{
		{
			PublicKey: deterministicPubKey(t, 4),
			Amount:    100,
		},
		{
			PublicKey: deterministicPubKey(t, 5),
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
			Txid: deterministicTxid(0x01),
			Vout: 1,
		},
		{
			Txid: deterministicTxid(0x02),
			Vout: 2,
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
