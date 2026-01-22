package asset

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestExtensionPacketEncodeDecode(t *testing.T) {
	packet := AssetPacket{
		Assets: []AssetGroup{controlAsset, normalAsset},
	}

	extPacket := &ExtensionPacket{Asset: &packet}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)

	decodedExt, err := DecodeToExtensionPacket(txOut)
	require.NoError(t, err)
	require.NotNil(t, decodedExt.Asset)
	require.Equal(t, packet, *decodedExt.Asset)
}

func TestExtensionPacket_WithSubDustAndAsset_Roundtrip(t *testing.T) {
	t.Parallel()
	// create a deterministic pubkey
	pub := deterministicPubKey(t, 0x42)
	sd := &SubDustPacket{Key: &pub, Amount: 123}

	packet := AssetPacket{Assets: []AssetGroup{controlAsset}}
	extPacket := &ExtensionPacket{Asset: &packet, SubDust: sd}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)

	decodedExt, err := DecodeToExtensionPacket(txOut)
	require.NoError(t, err)
	require.NotNil(t, decodedExt.Asset)
	require.NotNil(t, decodedExt.SubDust)
	require.Equal(t, packet, *decodedExt.Asset)
	require.Equal(t, sd.Amount, decodedExt.SubDust.Amount)
	require.Equal(t, schnorr.SerializePubKey(&pub), schnorr.SerializePubKey(decodedExt.SubDust.Key))
}

func TestExtensionPacket_SubDustOnly_Roundtrip(t *testing.T) {
	t.Parallel()
	pub := deterministicPubKey(t, 0x42)
	sd := &SubDustPacket{Key: &pub, Amount: 999}
	extPacket := &ExtensionPacket{SubDust: sd}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)

	decodedExt, err := DecodeToExtensionPacket(txOut)
	require.NoError(t, err)
	require.Nil(t, decodedExt.Asset)
	require.NotNil(t, decodedExt.SubDust)
	require.Equal(t, sd.Amount, decodedExt.SubDust.Amount)
	require.Equal(t, schnorr.SerializePubKey(&pub), schnorr.SerializePubKey(decodedExt.SubDust.Key))
}

// test subdust triggering subdust key missing error
func TestExtensionPacket_SubDustMissingKey(t *testing.T) {
	t.Parallel()
	sd := &SubDustPacket{Key: nil, Amount: 100}
	extPacket := &ExtensionPacket{SubDust: sd, Asset: &AssetPacket{Assets: []AssetGroup{controlAsset}}}
	_, err := extPacket.Encode()
	require.Error(t, err)
	require.Contains(t, err.Error(), "subdust key missing")
}

func TestDecodeToExtensionPacket_InvalidOpReturn(t *testing.T) {
	t.Parallel()
	// missing OP_RETURN
	txOut := wire.TxOut{Value: 0, PkScript: []byte{0x01, 0x02}}
	ep, err := DecodeToExtensionPacket(txOut)
	require.Error(t, err)
	require.Contains(t, err.Error(), "OP_RETURN not present")
	require.Nil(t, ep)
}

func TestDecodeToExtensionPacket_CorruptedPayload(t *testing.T) {
	t.Parallel()
	// build a valid packet then corrupt PkScript
	pub := deterministicPubKey(t, 0x42)
	sd := &SubDustPacket{Key: &pub, Amount: 5}
	packet := AssetPacket{Assets: []AssetGroup{controlAsset}}
	extPacket := &ExtensionPacket{Asset: &packet, SubDust: sd}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)
	require.Greater(t, len(txOut.PkScript), 2)
	// truncate pkScript to corrupt and trigger tokenizer error
	tr := wire.TxOut{Value: txOut.Value, PkScript: txOut.PkScript[:len(txOut.PkScript)-2]}
	ep, err := DecodeToExtensionPacket(tr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "opcode OP_PUSHDATA1 pushes 168 bytes, but script only has 166 remaining")
	require.Nil(t, ep)
}
