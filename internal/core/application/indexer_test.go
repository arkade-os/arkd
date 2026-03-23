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
	AuthToken authTokenFixtures `json:"auth_token"`
}

type authTokenFixtures struct {
	PrivateKeyHex string             `json:"private_key_hex"`
	PublicKeyHex  string             `json:"public_key_hex"`
	Valid         []validTokenTest   `json:"valid"`
	Invalid       []invalidTokenTest `json:"invalid"`
}

type validTokenTest struct {
	Name          string          `json:"name"`
	Outpoint      outpointFixture `json:"outpoint"`
	ExpectedToken string          `json:"expected_token"`
}

type outpointFixture struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type invalidTokenTest struct {
	Name  string `json:"name"`
	Token string `json:"token"`
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

// fixedTimestamp is used for deterministic token generation in tests.
// Uses 2100-01-01 00:00:00 UTC to ensure tokens never expire during tests.
var fixedTimestamp = time.Unix(4102444800, 0)

func TestAuthToken(t *testing.T) {
	f := loadFixtures(t)

	privkey, err := privkeyFromHex(f.AuthToken.PrivateKeyHex)
	require.NoError(t, err)

	indexer := newTestIndexer(privkey)

	t.Run("valid", func(t *testing.T) {
		for _, tc := range f.AuthToken.Valid {
			t.Run(tc.Name, func(t *testing.T) {
				outpoint := Outpoint{
					Txid: tc.Outpoint.Txid,
					VOut: tc.Outpoint.Vout,
				}

				token, err := indexer.createAuthTokenWithTimestamp(outpoint, fixedTimestamp)
				require.NoError(t, err)
				require.Equal(t, tc.ExpectedToken, token)

				_, valid, err := indexer.validateAuthToken(token)
				require.NoError(t, err)
				require.True(t, valid, "token validation mismatch")
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range f.AuthToken.Invalid {
			t.Run(tc.Name, func(t *testing.T) {
				_, valid, err := indexer.validateAuthToken(tc.Token)
				require.NoError(t, err)
				require.False(t, valid)
			})
		}
	})
}

func TestValidateAuthToken_WrongSigner(t *testing.T) {
	privkey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkey2, err := btcec.NewPrivateKey()
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
	privkey, err := btcec.NewPrivateKey()
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
	privkey, err := btcec.NewPrivateKey()
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
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	indexer := newTestIndexer(privkey)

	outpoint := Outpoint{
		Txid: "0000000000000000000000000000000000000000000000000000000000000001",
		VOut: 0,
	}

	token, err := indexer.createAuthToken(outpoint)
	require.NoError(t, err)

	extractedOutpoint, valid, err := indexer.validateAuthToken(token)
	require.NoError(t, err)
	require.True(t, valid)

	require.Equal(t, outpoint.Txid, extractedOutpoint.Txid, "txid mismatch")
	require.Equal(t, outpoint.VOut, extractedOutpoint.VOut, "vout mismatch")
}
