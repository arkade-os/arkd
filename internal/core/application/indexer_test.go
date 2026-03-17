package application

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func newTestIndexer(privkey *btcec.PrivateKey) *indexerService {
	return &indexerService{
		privkey:      privkey,
		signerPubkey: schnorr.SerializePubKey(privkey.PubKey()),
		authTokenTTL: defaultAuthTokenTTL,
	}
}

type fixtures struct {
	AuthTokenTests    authTokenTestFixtures `json:"auth_token_tests"`
	InvalidTokenTests []invalidTokenTest    `json:"invalid_token_tests"`
}

type authTokenTestFixtures struct {
	PrivateKeyHex string              `json:"private_key_hex"`
	PublicKeyHex  string              `json:"public_key_hex"`
	TestCases     []authTokenTestCase `json:"test_cases"`
}

type authTokenTestCase struct {
	Name           string          `json:"name"`
	Outpoint       outpointFixture `json:"outpoint"`
	ShouldValidate bool            `json:"should_validate"`
}

type outpointFixture struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type invalidTokenTest struct {
	Name           string `json:"name"`
	Token          string `json:"token"`
	ShouldValidate bool   `json:"should_validate"`
}

func privkeyFromHex(privKeyHex string) (*btcec.PrivateKey, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, err
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	return privKey, nil
}

func loadFixtures(t *testing.T) *fixtures {
	data, err := os.ReadFile("testdata/indexer_fixtures.json")
	require.NoError(t, err)

	var f fixtures
	err = json.Unmarshal(data, &f)
	require.NoError(t, err)

	return &f
}

func TestCreateAndValidateAuthToken(t *testing.T) {
	f := loadFixtures(t)

	privkey, err := privkeyFromHex(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	indexer := newTestIndexer(privkey)

	for _, tc := range f.AuthTokenTests.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			outpoint := Outpoint{
				Txid: tc.Outpoint.Txid,
				VOut: tc.Outpoint.Vout,
			}

			token, err := indexer.createAuthToken(outpoint)
			require.NoError(t, err)
			require.NotEmpty(t, token)

			_, valid, err := indexer.validateAuthToken(token)
			require.NoError(t, err)
			require.Equal(t, tc.ShouldValidate, valid, "token validation mismatch")
		})
	}
}

func TestValidateAuthToken_Invalid(t *testing.T) {
	f := loadFixtures(t)

	privkey, err := privkeyFromHex(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	indexer := newTestIndexer(privkey)

	for _, tc := range f.InvalidTokenTests {
		t.Run(tc.Name, func(t *testing.T) {
			_, valid, err := indexer.validateAuthToken(tc.Token)
			require.NoError(t, err)
			require.Equal(t, tc.ShouldValidate, valid)
		})
	}
}

func TestValidateAuthToken_WrongSigner(t *testing.T) {
	f := loadFixtures(t)

	privkey1, err := privkeyFromHex(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	privkey2, err := privkeyFromHex(
		"0000000000000000000000000000000000000000000000000000000000000002",
	)
	require.NoError(t, err)

	indexer1 := newTestIndexer(privkey1)

	// Create indexer with privkey1 for signing but privkey2's pubkey for validation
	indexer2 := &indexerService{
		privkey:      privkey1,
		signerPubkey: schnorr.SerializePubKey(privkey2.PubKey()),
		authTokenTTL: defaultAuthTokenTTL,
	}

	outpoint := Outpoint{
		Txid: "0000000000000000000000000000000000000000000000000000000000000001",
		VOut: 0,
	}

	token, err := indexer1.createAuthToken(outpoint)
	require.NoError(t, err)

	// Validate with correct pubkey - should pass
	_, valid, err := indexer1.validateAuthToken(token)
	require.NoError(t, err)
	require.True(t, valid, "token should be valid with correct signer")

	// Validate with wrong pubkey - should fail
	_, valid, err = indexer2.validateAuthToken(token)
	require.NoError(t, err)
	require.False(t, valid, "token should be invalid with wrong signer pubkey")
}

func TestAuthTokenDeterminism(t *testing.T) {
	f := loadFixtures(t)

	privkey, err := privkeyFromHex(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	indexer := newTestIndexer(privkey)

	outpoint := Outpoint{
		Txid: "0000000000000000000000000000000000000000000000000000000000000001",
		VOut: 0,
	}

	token1, err := indexer.createAuthToken(outpoint)
	require.NoError(t, err)

	token2, err := indexer.createAuthToken(outpoint)
	require.NoError(t, err)

	_, valid1, err := indexer.validateAuthToken(token1)
	require.NoError(t, err)
	require.True(t, valid1)

	_, valid2, err := indexer.validateAuthToken(token2)
	require.NoError(t, err)
	require.True(t, valid2)
}

func TestAuthTokenExpiry(t *testing.T) {
	f := loadFixtures(t)

	privkey, err := privkeyFromHex(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	indexer := newTestIndexer(privkey)

	outpoint := Outpoint{
		Txid: "0000000000000000000000000000000000000000000000000000000000000001",
		VOut: 0,
	}

	expiredTime := time.Now().Add(-(defaultAuthTokenTTL + time.Minute))
	token, err := indexer.createAuthTokenWithTimestamp(outpoint, expiredTime)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, valid, err := indexer.validateAuthToken(token)
	require.NoError(t, err)
	require.False(t, valid, "expired token should not be valid")

	freshToken, err := indexer.createAuthToken(outpoint)
	require.NoError(t, err)

	_, valid, err = indexer.validateAuthToken(freshToken)
	require.NoError(t, err)
	require.True(t, valid, "fresh token should be valid")
}

func TestAuthTokenOutpointExtraction(t *testing.T) {
	f := loadFixtures(t)

	privkey, err := privkeyFromHex(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	indexer := newTestIndexer(privkey)

	for _, tc := range f.AuthTokenTests.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			outpoint := Outpoint{
				Txid: tc.Outpoint.Txid,
				VOut: tc.Outpoint.Vout,
			}

			token, err := indexer.createAuthToken(outpoint)
			require.NoError(t, err)

			extractedOutpoint, valid, err := indexer.validateAuthToken(token)
			require.NoError(t, err)
			require.True(t, valid)

			require.Equal(t, outpoint.Txid, extractedOutpoint.Txid, "txid mismatch")
			require.Equal(t, outpoint.VOut, extractedOutpoint.VOut, "vout mismatch")
		})
	}
}
