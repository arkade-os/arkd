package asset

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/wire"
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
	ErrorCases []jsonTxOutFixture `json:"error_cases"`
}

type jsonMsgTxFixture struct {
	Name          string             `json:"name"`
	Description   string             `json:"description,omitempty"`
	TxOuts        []jsonTxOutFixture `json:"tx_outs"`
	ExpectedError string             `json:"expected_error,omitempty"`
	ExpectedIndex int                `json:"expected_index,omitempty"`
}

type jsonMsgTxsFixtures struct {
	ErrorCases []jsonMsgTxFixture `json:"error_cases"`
	ValidCases []jsonMsgTxFixture `json:"valid_cases"`
}

type assetPacketFixturesJSON struct {
	TxOuts  jsonTxOutsFixtures `json:"tx_outs"`
	MsgTxs  jsonMsgTxsFixtures `json:"msg_txs"`
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
	for _, f := range assetPacketFixtures.TxOuts.ErrorCases {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getMsgTxErrorFixture(name string) *jsonMsgTxFixture {
	for _, f := range assetPacketFixtures.MsgTxs.ErrorCases {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getMsgTxValidFixture(name string) *jsonMsgTxFixture {
	for _, f := range assetPacketFixtures.MsgTxs.ValidCases {
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
	require.Equal(t, len(packet.Assets), len(decodedPacket.Assets))
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
