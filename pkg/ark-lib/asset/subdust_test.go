package asset

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type jsonSubDustPacketFixture struct {
	Name          string `json:"name"`
	KeySeed       *byte  `json:"key_seed"`
	Amount        uint64 `json:"amount"`
	ExpectedError string `json:"expected_error,omitempty"`
}

type jsonSubDustPacketsFixtures struct {
	Valid   []jsonSubDustPacketFixture `json:"valid"`
	Invalid []jsonSubDustPacketFixture `json:"invalid"`
}

type jsonSubDustTxOutFixture struct {
	Name          string `json:"name"`
	PkScriptHex   string `json:"pk_script_hex"`
	Value         int64  `json:"value"`
	ExpectedError string `json:"expected_error"`
}

type jsonSubDustTxOutsFixtures struct {
	ErrorCases []jsonSubDustTxOutFixture `json:"error_cases"`
}

type subdustFixturesJSON struct {
	SubDustPackets jsonSubDustPacketsFixtures `json:"subdust_packets"`
	TxOuts         jsonSubDustTxOutsFixtures  `json:"tx_outs"`
}

var subdustFixtures subdustFixturesJSON

func init() {
	file, err := os.ReadFile("testdata/subdust_fixtures.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(file, &subdustFixtures); err != nil {
		panic(err)
	}
}

func getValidSubDustPacketFixture(name string) *jsonSubDustPacketFixture {
	for _, f := range subdustFixtures.SubDustPackets.Valid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getInvalidSubDustPacketFixture(name string) *jsonSubDustPacketFixture {
	for _, f := range subdustFixtures.SubDustPackets.Invalid {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getSubDustTxOutErrorFixture(name string) *jsonSubDustTxOutFixture {
	for _, f := range subdustFixtures.TxOuts.ErrorCases {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToSubDustTxOut(f *jsonSubDustTxOutFixture) (wire.TxOut, error) {
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

func TestEncodeDecodeSubDustPacket(t *testing.T) {
	// Test valid packet
	validFixture := getValidSubDustPacketFixture("default")
	require.NotNil(t, validFixture)

	key := deterministicPubKey(t, *validFixture.KeySeed)
	packet := &SubDustPacket{
		Key:    &key,
		Amount: validFixture.Amount,
	}
	txOut, err := packet.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, txOut)

	decodedPacket, err := DecodeToSubDustPacket(txOut)
	require.NoError(t, err)
	require.NotNil(t, decodedPacket)

	// check original and decoded packet fields are equal
	require.Equal(t, packet.Amount, decodedPacket.Amount)
	require.True(t, key.IsEqual(decodedPacket.Key))

	// empty TxOut decode failure
	emptyFixture := getSubDustTxOutErrorFixture("empty")
	require.NotNil(t, emptyFixture)
	emptyTxOut, err := fixtureToSubDustTxOut(emptyFixture)
	require.NoError(t, err)
	pkt, err := DecodeToSubDustPacket(emptyTxOut)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, emptyFixture.ExpectedError, err.Error())

	// TxOut with no opreturn prefix
	missingOpReturnFixture := getSubDustTxOutErrorFixture("missing_op_return")
	require.NotNil(t, missingOpReturnFixture)
	missingOpReturnTx, err := fixtureToSubDustTxOut(missingOpReturnFixture)
	require.NoError(t, err)
	pkt, err = DecodeToSubDustPacket(missingOpReturnTx)
	require.Error(t, err)
	require.Nil(t, pkt)
	require.Equal(t, missingOpReturnFixture.ExpectedError, err.Error())

	// fail to encode empty subdust packet
	invalidFixture := getInvalidSubDustPacketFixture("empty")
	require.NotNil(t, invalidFixture)
	emptyPacket := &SubDustPacket{Key: nil, Amount: invalidFixture.Amount}
	txOut, err = emptyPacket.Encode()
	require.Error(t, err)
	require.Equal(t, invalidFixture.ExpectedError, err.Error())
	require.Equal(t, int64(0), txOut.Value)
	require.Equal(t, 0, len(txOut.PkScript))
}

func TestDecodeToSubDustPacket_MissingSubDustPayload(t *testing.T) {
	t.Parallel()
	// Create a TxOut with only asset payload (no subdust)
	packet := &AssetPacket{
		Assets: []AssetGroup{controlAsset},
	}
	extPacket := &ExtensionPacket{Asset: packet, SubDust: nil}
	txOut, err := extPacket.Encode()
	require.NoError(t, err)

	// Try to decode as SubDustPacket - should fail
	pkt, err := DecodeToSubDustPacket(txOut)
	require.Error(t, err)
	require.Equal(t, "missing subdust payload", err.Error())
	require.Nil(t, pkt)
}
