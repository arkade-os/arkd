package asset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

type jsonTxOutFixture struct {
	Name          string `json:"name"`
	PkScriptHex   string `json:"pk_script_hex"`
	Value         int64  `json:"value"`
	ExpectedError string `json:"expected_error,omitempty"`
	IsAssetPacket bool   `json:"is_asset_packet,omitempty"`
}

type jsonTxOutsFixtures struct {
	Valid   []jsonTxOutFixture `json:"valid"`
	Invalid []jsonTxOutFixture `json:"invalid"`
}

type jsonMsgTxFixture struct {
	Name          string             `json:"name"`
	Description   string             `json:"description,omitempty"`
	TxOuts        []jsonTxOutFixture `json:"tx_outs"`
	ExpectedError string             `json:"expected_error,omitempty"`
	ExpectedIndex int                `json:"expected_index,omitempty"`
}

type jsonMsgTxsFixtures struct {
	Valid   []jsonMsgTxFixture `json:"valid"`
	Invalid []jsonMsgTxFixture `json:"invalid"`
}

type jsonDecodeAssetPacketCase struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	BuildType     string `json:"build_type"`
	ExpectedError string `json:"expected_error,omitempty"`
}

type jsonDecodeAssetPacketFixtures struct {
	Valid   []jsonDecodeAssetPacketCase `json:"valid"`
	Invalid []jsonDecodeAssetPacketCase `json:"invalid"`
}

type jsonDeriveAssetPacketDecodeFixtures struct {
	Valid   []jsonDecodeAssetPacketCase `json:"valid"`
	Invalid []jsonDecodeAssetPacketCase `json:"invalid"`
}

type assetPacketFixturesJSON struct {
	TxOuts                  jsonTxOutsFixtures                  `json:"tx_outs"`
	MsgTxs                  jsonMsgTxsFixtures                  `json:"msg_txs"`
	DecodeToAssetPacket     jsonDecodeAssetPacketFixtures       `json:"decode_to_asset_packet"`
	DeriveAssetPacketDecode jsonDeriveAssetPacketDecodeFixtures `json:"derive_asset_packet_decode"`
}

var assetPacketFixtures assetPacketFixturesJSON

func init() {
	file, err := os.ReadFile("testdata/asset_packet_fixtures.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(file, &assetPacketFixtures); err != nil {
		panic(err)
	}
}

func getTxOutErrorFixture(name string) *jsonTxOutFixture {
	for _, f := range assetPacketFixtures.TxOuts.Invalid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getMsgTxErrorFixture(name string) *jsonMsgTxFixture {
	for _, f := range assetPacketFixtures.MsgTxs.Invalid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getMsgTxValidFixture(name string) *jsonMsgTxFixture {
	for _, f := range assetPacketFixtures.MsgTxs.Valid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToTxOut(f *jsonTxOutFixture) (wire.TxOut, error) {
	var pkScript []byte
	if f.PkScriptHex != "" {
		var err error
		pkScript, err = hex.DecodeString(f.PkScriptHex)
		if err != nil {
			return wire.TxOut{}, err
		}
	}
	return wire.TxOut{
		Value:    f.Value,
		PkScript: pkScript,
	}, nil
}

func fixtureToMsgTx(f *jsonMsgTxFixture, validAssetPacketTxOut *wire.TxOut) (wire.MsgTx, error) {
	msgTx := wire.MsgTx{
		TxOut: make([]*wire.TxOut, 0, len(f.TxOuts)),
	}
	for _, txOutFixture := range f.TxOuts {
		if txOutFixture.IsAssetPacket && validAssetPacketTxOut != nil {
			msgTx.TxOut = append(msgTx.TxOut, validAssetPacketTxOut)
		} else if txOutFixture.PkScriptHex == "bad_magic" {
			// Special case: OP_RETURN with Arkade magic but invalid payload
			badMagicScript := append([]byte{0x6a}, ArkadeMagic...)
			msgTx.TxOut = append(msgTx.TxOut, &wire.TxOut{
				Value:    txOutFixture.Value,
				PkScript: badMagicScript,
			})
		} else {
			txOut, err := fixtureToTxOut(&txOutFixture)
			if err != nil {
				return wire.MsgTx{}, err
			}
			msgTx.TxOut = append(msgTx.TxOut, &txOut)
		}
	}
	return msgTx, nil
}

func TestEncodeDecodeAssetPacket(t *testing.T) {
	packet := &AssetPacket{
		Assets: []AssetGroup{controlAsset, normalAsset},
	}
	txOut, err := packet.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, txOut)

	decodedPacket, err := DecodeOutputToAssetPacket(txOut)
	require.NoError(t, err)

	// check original and decoded packet fields are equal
	require.Equal(t, packet.Version, decodedPacket.Version)
	require.True(t, assetGroupsEqual(packet.Assets, decodedPacket.Assets))

	// fail to encode empty asset packet
	emptyPacket := &AssetPacket{
		Assets: []AssetGroup{},
	}

	wireTx, err := emptyPacket.Encode()
	require.Error(t, err)
	require.Equal(t, "cannot encode empty asset group", err.Error())
	require.Equal(t, int64(0), wireTx.Value)
	require.Equal(t, 0, len(wireTx.PkScript))

	// empty TxOut decode failure
	emptyFixture := getTxOutErrorFixture("empty")
	require.NotNil(t, emptyFixture)
	emptyTxOut, err := fixtureToTxOut(emptyFixture)
	require.NoError(t, err)
	pkt, err := DecodeOutputToAssetPacket(emptyTxOut)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, emptyFixture.ExpectedError, err.Error())

	// asset packet with no opreturn prefix
	missingOpReturnFixture := getTxOutErrorFixture("missing_op_return")
	require.NotNil(t, missingOpReturnFixture)
	missingOpReturnTx, err := fixtureToTxOut(missingOpReturnFixture)
	require.NoError(t, err)
	pkt, err = DecodeOutputToAssetPacket(missingOpReturnTx)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, missingOpReturnFixture.ExpectedError, err.Error())
}

func TestDeriveAssetPacketFromTx(t *testing.T) {
	// empty tx
	emptyFixture := getMsgTxErrorFixture("empty")
	require.NotNil(t, emptyFixture)
	emptyTx, err := fixtureToMsgTx(emptyFixture, nil)
	require.NoError(t, err)
	packet, idx, err := DeriveAssetPacketFromTx(emptyTx)
	require.Error(t, err)
	require.Equal(t, emptyFixture.ExpectedError, err.Error())
	require.Nil(t, packet)
	require.Equal(t, 0, idx)

	// tx with no asset packets
	noAssetFixture := getMsgTxErrorFixture("no_asset_packets")
	require.NotNil(t, noAssetFixture)
	noAssetTx, err := fixtureToMsgTx(noAssetFixture, nil)
	require.NoError(t, err)
	packet, idx, err = DeriveAssetPacketFromTx(noAssetTx)
	require.Error(t, err)
	require.Equal(t, noAssetFixture.ExpectedError, err.Error())
	require.Nil(t, packet)
	require.Equal(t, 0, idx)

	// tx with non-asset OP_RETURN
	nonAssetOpReturnFixture := getMsgTxErrorFixture("with_non_asset_op_return")
	require.NotNil(t, nonAssetOpReturnFixture)
	nonAssetOpReturnTx, err := fixtureToMsgTx(nonAssetOpReturnFixture, nil)
	require.NoError(t, err)
	packet, idx, err = DeriveAssetPacketFromTx(nonAssetOpReturnTx)
	require.Error(t, err)
	require.Equal(t, nonAssetOpReturnFixture.ExpectedError, err.Error())
	require.Nil(t, packet)
	require.Equal(t, 0, idx)

	// create valid asset packet for mixed tx test
	validPacket := &AssetPacket{
		Assets: []AssetGroup{controlAsset, normalAsset},
	}
	validTxOut, err := validPacket.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, validTxOut)

	// tx with valid asset packet at specific index
	mixedFixture := getMsgTxValidFixture("mixed_with_valid_at_index_1")
	require.NotNil(t, mixedFixture)
	mixedTx, err := fixtureToMsgTx(mixedFixture, &validTxOut)
	require.NoError(t, err)
	packet, idx, err = DeriveAssetPacketFromTx(mixedTx)
	require.NoError(t, err)
	require.NotNil(t, packet)
	require.Equal(t, mixedFixture.ExpectedIndex, idx)
	require.True(t, assetGroupsEqual(packet.Assets, []AssetGroup{controlAsset, normalAsset}))
}

func TestDecodeOutputToAssetPacket_MissingAssetPayload(t *testing.T) {
	t.Parallel()
	// Create a TxOut with only subdust payload (no asset)
	pubFixture := getExtPubKeyFixture("corrupted_payload_0x42")
	require.NotNil(t, pubFixture)
	keyPtr, err := fixtureToExtPubKey(pubFixture)
	require.NoError(t, err)
	key := *keyPtr
	extPacket := &ExtensionPacket{
		Asset:   nil,
		SubDust: &SubDustPacket{Key: &key, Amount: 100},
	}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)

	// Try to decode as AssetPacket - should fail
	pkt, err := DecodeOutputToAssetPacket(txOut)
	require.Error(t, err)
	require.Equal(t, "missing asset payload", err.Error())
	require.Nil(t, pkt)
}

func TestDecodeToAssetPacket_EmptyAssetGroup(t *testing.T) {
	t.Parallel()
	// Payload with asset count = 0, tests decodeToAssetPacket's "empty asset group" error path
	var payload bytes.Buffer
	var scratch [8]byte
	_ = tlv.WriteVarInt(&payload, 0, &scratch) // count = 0

	// Wrap in extension packet format
	var tlvData bytes.Buffer
	tlvData.Write(ArkadeMagic)
	tlvData.WriteByte(MarkerAssetPayload)
	_ = tlv.WriteVarInt(&tlvData, uint64(payload.Len()), &scratch)
	tlvData.Write(payload.Bytes())

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	builder.AddFullData(tlvData.Bytes())
	pkScript, err := builder.Script()
	require.NoError(t, err)

	txOut := wire.TxOut{Value: 0, PkScript: pkScript}
	pkt, err := DecodeOutputToAssetPacket(txOut)
	require.Error(t, err)
	require.Equal(t, "empty asset group", err.Error())
	require.Nil(t, pkt)
}

func TestDecodeToAssetPacket_TrailingBytes(t *testing.T) {
	t.Parallel()
	// Create a valid asset packet, then add trailing bytes
	packet := &AssetPacket{
		Assets: []AssetGroup{controlAsset},
	}
	txOut, err := packet.Encode()
	require.NoError(t, err)

	// Decode the pkScript to get the payload, add trailing bytes, re-encode
	// Parse the OP_RETURN script to extract payload
	tokenizer := txscript.MakeScriptTokenizer(0, txOut.PkScript)
	require.True(t, tokenizer.Next()) // OP_RETURN
	require.True(t, tokenizer.Next()) // data push
	originalPayload := tokenizer.Data()
	require.True(t, bytes.HasPrefix(originalPayload, ArkadeMagic))

	// Find the asset payload within the TLV structure and add trailing bytes to it
	// The structure is: ArkadeMagic + type(1) + length(varint) + value
	// We need to modify the value to have trailing bytes.
	// Simpler to encode asset groups with trailing bytes.
	encodedAssets, err := encodeAssetGroups(packet.Assets)
	require.NoError(t, err)

	// Add trailing bytes to the encoded assets
	encodedAssetsWithTrailing := append(encodedAssets, 0xff, 0xfe, 0xfd)

	// Build new payload
	var tlvData bytes.Buffer
	var scratch [8]byte
	tlvData.Write(ArkadeMagic)
	tlvData.WriteByte(MarkerAssetPayload)
	_ = tlv.WriteVarInt(&tlvData, uint64(len(encodedAssetsWithTrailing)), &scratch)
	tlvData.Write(encodedAssetsWithTrailing)

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	builder.AddFullData(tlvData.Bytes())
	pkScript, err := builder.Script()
	require.NoError(t, err)

	modifiedTxOut := wire.TxOut{Value: 0, PkScript: pkScript}
	pkt, err := DecodeOutputToAssetPacket(modifiedTxOut)
	require.Error(t, err)
	require.Equal(t, "unexpected trailing bytes in asset group payload", err.Error())
	require.Nil(t, pkt)
}

func buildAssetPacketTestScript(buildType string) ([]byte, error) {
	var scratch [8]byte
	var tlvData bytes.Buffer
	tlvData.Write(ArkadeMagic)

	switch buildType {
	case "invalid_group_count_varint":
		// Asset payload marker + truncated varint (0xff requires more bytes)
		tlvData.WriteByte(MarkerAssetPayload)
		_ = tlv.WriteVarInt(&tlvData, 1, &scratch) // length = 1
		tlvData.WriteByte(0xff)                    // incomplete varint
	case "corrupted_asset_group":
		// Valid count but corrupted asset group data
		tlvData.WriteByte(MarkerAssetPayload)
		var assetPayload bytes.Buffer
		_ = tlv.WriteVarInt(&assetPayload, 1, &scratch) // count = 1
		assetPayload.Write([]byte{0xff, 0xff, 0xff})    // garbage data
		_ = tlv.WriteVarInt(&tlvData, uint64(assetPayload.Len()), &scratch)
		tlvData.Write(assetPayload.Bytes())
	case "contains_but_invalid":
		// Creates a packet that passes ContainsAssetPacket but fails decode
		// Use a valid-looking structure but with invalid asset data
		tlvData.WriteByte(MarkerAssetPayload)
		var assetPayload bytes.Buffer
		_ = tlv.WriteVarInt(&assetPayload, 1, &scratch)    // count = 1
		assetPayload.WriteByte(0x00)                        // presence byte
		_ = tlv.WriteVarInt(&assetPayload, 1, &scratch)    // input count = 1
		assetPayload.WriteByte(0x99)                        // unknown input type
		_ = tlv.WriteVarInt(&tlvData, uint64(assetPayload.Len()), &scratch)
		tlvData.Write(assetPayload.Bytes())
	default:
		return nil, nil
	}

	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
	builder.AddFullData(tlvData.Bytes())
	return builder.Script()
}

func TestDecodeToAssetPacket_InvalidGroupCount(t *testing.T) {
	t.Parallel()

	for _, tc := range assetPacketFixtures.DecodeToAssetPacket.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			pkScript, err := buildAssetPacketTestScript(tc.BuildType)
			require.NoError(t, err)

			txOut := wire.TxOut{Value: 0, PkScript: pkScript}
			pkt, err := DecodeOutputToAssetPacket(txOut)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.ExpectedError)
			require.Nil(t, pkt)
		})
	}
}

func TestDeriveAssetPacketFromTx_DecodeError(t *testing.T) {
	t.Parallel()

	for _, tc := range assetPacketFixtures.DeriveAssetPacketDecode.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			pkScript, err := buildAssetPacketTestScript(tc.BuildType)
			require.NoError(t, err)

			msgTx := wire.MsgTx{
				TxOut: []*wire.TxOut{
					{Value: 0, PkScript: pkScript},
				},
			}

			pkt, idx, err := DeriveAssetPacketFromTx(msgTx)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.ExpectedError)
			require.Nil(t, pkt)
			require.Equal(t, 0, idx)
		})
	}
}
