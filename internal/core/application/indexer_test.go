package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

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

// mockSignerService implements ports.SignerService for testing
type mockSignerService struct {
	privateKey *btcec.PrivateKey
	publicKey  *btcec.PublicKey
}

func newMockSignerService(privKeyHex string) (*mockSignerService, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, err
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
	return &mockSignerService{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

func (m *mockSignerService) IsReady(ctx context.Context) (bool, error) {
	return true, nil
}

func (m *mockSignerService) GetPubkey(ctx context.Context) (*btcec.PublicKey, error) {
	return m.publicKey, nil
}

func (m *mockSignerService) SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error) {
	return "", nil
}

func (m *mockSignerService) SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error) {
	return "", nil
}

// mocks what is called inside createAuthToken - we just need to return a valid signature for the message
// but this code mimics SignMessage in pkg/arkd-wallet/core/application/wallet/service.go
func (m *mockSignerService) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
	msgHash := chainhash.HashB(message)
	sig, err := schnorr.Sign(m.privateKey, msgHash)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
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
	ctx := context.Background()

	// Create mock signer
	mockSigner, err := newMockSignerService(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	// Create indexer service
	indexer := &indexerService{
		signer:       mockSigner,
		signerPubkey: schnorr.SerializePubKey(mockSigner.publicKey),
	}

	for _, tc := range f.AuthTokenTests.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			outpoint := Outpoint{
				Txid: tc.Outpoint.Txid,
				VOut: tc.Outpoint.Vout,
			}

			// Create auth token
			token, err := indexer.createAuthToken(ctx, outpoint)
			require.NoError(t, err)
			require.NotEmpty(t, token)

			// Validate the token we just created
			valid, err := indexer.validateAuthToken(token)
			require.NoError(t, err)
			require.Equal(t, tc.ShouldValidate, valid, "token validation mismatch")
		})
	}
}

func TestValidateAuthToken_Invalid(t *testing.T) {
	f := loadFixtures(t)

	// Create mock signer
	mockSigner, err := newMockSignerService(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	// Create indexer service
	indexer := &indexerService{
		signer:       mockSigner,
		signerPubkey: schnorr.SerializePubKey(mockSigner.publicKey),
	}

	for _, tc := range f.InvalidTokenTests {
		t.Run(tc.Name, func(t *testing.T) {
			valid, err := indexer.validateAuthToken(tc.Token)
			require.NoError(t, err)
			require.Equal(t, tc.ShouldValidate, valid)
		})
	}
}

func TestValidateAuthToken_WrongSigner(t *testing.T) {
	f := loadFixtures(t)
	ctx := context.Background()

	// Create first signer
	mockSigner1, err := newMockSignerService(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	// Create second signer with different key
	mockSigner2, err := newMockSignerService("0000000000000000000000000000000000000000000000000000000000000002")
	require.NoError(t, err)

	// Create indexer with signer1
	indexer1 := &indexerService{
		signer:       mockSigner1,
		signerPubkey: schnorr.SerializePubKey(mockSigner1.publicKey),
	}

	// Create indexer with signer2's pubkey (simulates wrong signer)
	indexer2 := &indexerService{
		signer:       mockSigner1,
		signerPubkey: schnorr.SerializePubKey(mockSigner2.publicKey),
	}

	outpoint := Outpoint{
		Txid: "0000000000000000000000000000000000000000000000000000000000000001",
		VOut: 0,
	}

	// Create token with signer1
	token, err := indexer1.createAuthToken(ctx, outpoint)
	require.NoError(t, err)

	// Validate with signer1's pubkey - should pass
	valid, err := indexer1.validateAuthToken(token)
	require.NoError(t, err)
	require.True(t, valid, "token should be valid with correct signer")

	// Validate with signer2's pubkey - should fail
	valid, err = indexer2.validateAuthToken(token)
	require.NoError(t, err)
	require.False(t, valid, "token should be invalid with wrong signer pubkey")
}

func TestAuthTokenDeterminism(t *testing.T) {
	f := loadFixtures(t)
	ctx := context.Background()

	// Create mock signer
	mockSigner, err := newMockSignerService(f.AuthTokenTests.PrivateKeyHex)
	require.NoError(t, err)

	// Create indexer service
	indexer := &indexerService{
		signer:       mockSigner,
		signerPubkey: schnorr.SerializePubKey(mockSigner.publicKey),
	}

	outpoint := Outpoint{
		Txid: "0000000000000000000000000000000000000000000000000000000000000001",
		VOut: 0,
	}

	// Create multiple tokens for the same outpoint
	token1, err := indexer.createAuthToken(ctx, outpoint)
	require.NoError(t, err)

	token2, err := indexer.createAuthToken(ctx, outpoint)
	require.NoError(t, err)

	// Both tokens should be valid
	valid1, err := indexer.validateAuthToken(token1)
	require.NoError(t, err)
	require.True(t, valid1)

	valid2, err := indexer.validateAuthToken(token2)
	require.NoError(t, err)
	require.True(t, valid2)
}
