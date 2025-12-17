package asset

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func TestAssetEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	asset := Asset{
		AssetId: AssetId{
			TxId:  deterministicBytesArray(0x2a),
			Index: 0,
		},
		Outputs: []AssetOutput{
			{
				Type:   AssetOutputTypeLocal,
				Amount: 11,
				Vout:   0,
			},
			{
				Type:       AssetOutputTypeTeleport,
				Commitment: deterministicBytesArray(0xcc),
				Amount:     22,
			},
		},
		ControlAssetId: &AssetId{
			TxId:  deterministicBytesArray(0x3c),
			Index: 1,
		},
		Inputs: []AssetInput{
			{
				Type:   AssetInputTypeLocal,
				Vin:    7,
				Amount: 20,
			},
			{
				Type:       AssetInputTypeTeleport,
				Commitment: deterministicBytesArray(0xbb),
				Witness: TeleportWitness{
					Script: []byte{0x00, 0x01, 0x02, 0x03},
					Nonce:  deterministicBytesArray(0x99),
				},
				Amount: 40,
			},
		},
		Metadata: []Metadata{
			{Key: "purpose", Value: "roundtrip"},
			{Key: "owner", Value: "arkade"},
		},
		Immutable: true,
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

	controlAsset := Asset{
		AssetId:        deterministicAssetId(0x11),
		Outputs:        []AssetOutput{{Type: AssetOutputTypeTeleport, Commitment: deterministicBytesArray(0xdd), Amount: 1}},
		ControlAssetId: deterministicAssetIdPtr(0x3c),
		Metadata:       []Metadata{{Key: "kind", Value: "control"}},
		Version:        AssetVersion,
		Magic:          AssetMagic,
	}

	normalAsset := Asset{
		AssetId:        deterministicAssetId(0x12),
		Outputs:        []AssetOutput{{Type: AssetOutputTypeLocal, Amount: 10, Vout: 1}},
		ControlAssetId: deterministicAssetIdPtr(0x3c),
		Inputs:         []AssetInput{{Type: AssetInputTypeLocal, Vin: 1, Amount: 5}},
		Metadata:       []Metadata{{Key: "kind", Value: "normal"}},
		Version:        AssetVersion,
		Magic:          AssetMagic,
	}

	group := AssetGroup{
		ControlAssets: []Asset{controlAsset},
		NormalAssets:  []Asset{normalAsset},
	}

	txOut, err := group.EncodeOpret(0)
	require.NoError(t, err)

	decodedGroup, err := DecodeAssetGroupFromOpret(txOut.PkScript)
	require.NoError(t, err)
	require.Equal(t, group, *decodedGroup)
}

func TestAssetIdStringConversion(t *testing.T) {
	txid := deterministicBytesArray(0x01)
	index := uint32(12345)
	assetId := AssetId{TxId: txid, Index: index}

	s := assetId.ToString()
	decoded, err := AssetIdFromString(s)
	require.NoError(t, err)
	require.Equal(t, &assetId, decoded)

	// Test invalid hex
	_, err = AssetIdFromString("invalid")
	require.Error(t, err)

	// Test invalid length
	_, err = AssetIdFromString(hex.EncodeToString(make([]byte, 35)))
	require.Error(t, err)
}

func TestAssetGroupEncodeDecodeWithSubDustKey(t *testing.T) {
	t.Parallel()

	subDustKey := deterministicPubKey(t, 0x55)
	normalAsset := Asset{
		AssetId:        deterministicAssetId(0x12),
		Outputs:        []AssetOutput{{Type: AssetOutputTypeLocal, Amount: 10, Vout: 1}},
		ControlAssetId: deterministicAssetIdPtr(0xaa),
		Version:        AssetVersion,
		Magic:          AssetMagic,
	}

	group := AssetGroup{
		ControlAssets: nil,
		NormalAssets:  []Asset{normalAsset},
		SubDustKey:    &subDustKey,
	}

	txOut, err := group.EncodeOpret(0)
	require.NoError(t, err)
	require.True(t, IsAssetGroup(txOut.PkScript))

	tokenizer := txscript.MakeScriptTokenizer(0, txOut.PkScript)
	require.True(t, tokenizer.Next())
	require.Equal(t, txscript.OP_RETURN, int(tokenizer.Opcode()))
	require.True(t, tokenizer.Next())
	require.Equal(t, []byte{MarkerSubDustKey}, tokenizer.Data())
	require.True(t, tokenizer.Next())
	require.Equal(t, schnorr.SerializePubKey(&subDustKey), tokenizer.Data())

	decodedGroup, err := DecodeAssetGroupFromOpret(txOut.PkScript)
	require.NoError(t, err)
	require.NotNil(t, decodedGroup.SubDustKey)
	require.True(t, subDustKey.IsEqual(decodedGroup.SubDustKey))
	require.Len(t, decodedGroup.NormalAssets, 1)
	require.Equal(t, normalAsset, decodedGroup.NormalAssets[0])
}

func TestAssetOutputListEncodeDecode(t *testing.T) {
	t.Parallel()

	outputs := []AssetOutput{
		{
			Type:   AssetOutputTypeLocal,
			Vout:   0,
			Amount: 100,
		},
		{
			Type:       AssetOutputTypeTeleport,
			Commitment: deterministicBytesArray(0xEE),
			Amount:     200,
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
			Type:   AssetInputTypeLocal,
			Amount: 80,
			Vin:    1,
		},
		{
			Type:       AssetInputTypeTeleport,
			Amount:     20,
			Commitment: deterministicBytesArray(0x02),
			Witness: TeleportWitness{
				Script: []byte{0xde, 0xad, 0xbe, 0xef},
				Nonce:  deterministicBytesArray(0x88),
			},
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

func deterministicTxhash(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, 32)
}

func deterministicBytesArray(seed byte) [32]byte {
	var arr [32]byte
	copy(arr[:], deterministicTxhash(seed))
	return arr
}

func deterministicAssetId(seed byte) AssetId {
	return AssetId{
		TxId:  deterministicBytesArray(seed),
		Index: 0,
	}
}

func deterministicAssetIdPtr(seed byte) *AssetId {
	a := deterministicAssetId(seed)
	return &a
}
