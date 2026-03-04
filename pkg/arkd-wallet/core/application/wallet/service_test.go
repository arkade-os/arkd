package wallet

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

type serviceFixtures struct {
	SignMessageTests signMessageTestFixtures `json:"sign_message_tests"`
}

type signMessageTestFixtures struct {
	TestKeys  []testKey           `json:"test_keys"`
	TestCases []signMessageTestCase `json:"test_cases"`
}

type testKey struct {
	Name          string `json:"name"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
}

type signMessageTestCase struct {
	Name       string `json:"name"`
	MessageHex string `json:"message_hex"`
	KeyName    string `json:"key_name"`
}

func loadServiceFixtures(t *testing.T) *serviceFixtures {
	data, err := os.ReadFile("fixtures/service_fixtures.json")
	require.NoError(t, err)

	var f serviceFixtures
	err = json.Unmarshal(data, &f)
	require.NoError(t, err)

	return &f
}

func getTestKey(t *testing.T, fixtures *serviceFixtures, keyName string) *btcec.PrivateKey {
	for _, k := range fixtures.SignMessageTests.TestKeys {
		if k.Name == keyName {
			privKeyBytes, err := hex.DecodeString(k.PrivateKeyHex)
			require.NoError(t, err)
			privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
			return privKey
		}
	}
	t.Fatalf("test key not found: %s", keyName)
	return nil
}

func TestSignMessage(t *testing.T) {
	fixtures := loadServiceFixtures(t)
	ctx := context.Background()

	for _, tc := range fixtures.SignMessageTests.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Get the private key for this test case
			privKey := getTestKey(t, fixtures, tc.KeyName)

			// Create wallet with signer key
			w := &wallet{
				WalletOptions: WalletOptions{
					SignerKey: privKey,
				},
			}

			// Decode message
			message, err := hex.DecodeString(tc.MessageHex)
			require.NoError(t, err)

			// Sign the message
			signature, err := w.SignMessage(ctx, message)
			require.NoError(t, err)
			require.NotNil(t, signature)

			// Schnorr signatures are always 64 bytes
			require.Len(t, signature, 64, "schnorr signature should be 64 bytes")

			// Verify the signature is valid
			msgHash := chainhash.HashB(message)
			sig, err := schnorr.ParseSignature(signature)
			require.NoError(t, err)

			pubKey := privKey.PubKey()
			valid := sig.Verify(msgHash, pubKey)
			require.True(t, valid, "signature should be valid")
		})
	}
}

func TestSignMessage_NoSignerKey(t *testing.T) {
	ctx := context.Background()

	// Create wallet without signer key
	w := &wallet{
		WalletOptions: WalletOptions{
			SignerKey: nil,
		},
	}

	message := []byte("test message")
	signature, err := w.SignMessage(ctx, message)

	require.Error(t, err)
	require.Nil(t, signature)
	require.Contains(t, err.Error(), "signer key not loaded")
}

func TestSignMessage_DifferentKeysProduceDifferentSignatures(t *testing.T) {
	fixtures := loadServiceFixtures(t)
	ctx := context.Background()

	// Get two different keys
	privKey1 := getTestKey(t, fixtures, "key_1")
	privKey2 := getTestKey(t, fixtures, "key_2")

	w1 := &wallet{WalletOptions: WalletOptions{SignerKey: privKey1}}
	w2 := &wallet{WalletOptions: WalletOptions{SignerKey: privKey2}}

	message := []byte("same message")

	sig1, err := w1.SignMessage(ctx, message)
	require.NoError(t, err)

	sig2, err := w2.SignMessage(ctx, message)
	require.NoError(t, err)

	// Signatures should be different (different keys)
	require.NotEqual(t, sig1, sig2, "different keys should produce different signatures")

	// But both should be valid for their respective keys
	msgHash := chainhash.HashB(message)

	parsedSig1, err := schnorr.ParseSignature(sig1)
	require.NoError(t, err)
	require.True(t, parsedSig1.Verify(msgHash, privKey1.PubKey()))

	parsedSig2, err := schnorr.ParseSignature(sig2)
	require.NoError(t, err)
	require.True(t, parsedSig2.Verify(msgHash, privKey2.PubKey()))

	// Cross-verification should fail
	require.False(t, parsedSig1.Verify(msgHash, privKey2.PubKey()), "sig1 should not verify with key2")
	require.False(t, parsedSig2.Verify(msgHash, privKey1.PubKey()), "sig2 should not verify with key1")
}

func TestSignMessage_DifferentMessagesProduceDifferentSignatures(t *testing.T) {
	fixtures := loadServiceFixtures(t)
	ctx := context.Background()

	privKey := getTestKey(t, fixtures, "key_1")
	w := &wallet{WalletOptions: WalletOptions{SignerKey: privKey}}

	message1 := []byte("message one")
	message2 := []byte("message two")

	sig1, err := w.SignMessage(ctx, message1)
	require.NoError(t, err)

	sig2, err := w.SignMessage(ctx, message2)
	require.NoError(t, err)

	// Signatures should be different (different messages)
	require.NotEqual(t, sig1, sig2, "different messages should produce different signatures")

	// Each signature should only verify with its corresponding message
	pubKey := privKey.PubKey()

	parsedSig1, err := schnorr.ParseSignature(sig1)
	require.NoError(t, err)
	require.True(t, parsedSig1.Verify(chainhash.HashB(message1), pubKey))
	require.False(t, parsedSig1.Verify(chainhash.HashB(message2), pubKey))

	parsedSig2, err := schnorr.ParseSignature(sig2)
	require.NoError(t, err)
	require.True(t, parsedSig2.Verify(chainhash.HashB(message2), pubKey))
	require.False(t, parsedSig2.Verify(chainhash.HashB(message1), pubKey))
}

func TestSignMessage_ConsistentWithSchnorrVerify(t *testing.T) {
	fixtures := loadServiceFixtures(t)
	ctx := context.Background()

	privKey := getTestKey(t, fixtures, "key_1")
	w := &wallet{WalletOptions: WalletOptions{SignerKey: privKey}}

	// Test with the 36-byte auth token message format
	// This matches what indexer.go uses for auth tokens
	txid := make([]byte, 32)
	txid[31] = 0x01 // txid = ...0001
	vout := []byte{0x00, 0x00, 0x00, 0x2a} // vout = 42 (big endian)
	message := append(txid, vout...)

	signature, err := w.SignMessage(ctx, message)
	require.NoError(t, err)

	// Verify using the same method as validateAuthToken in indexer.go
	msgHash := chainhash.HashB(message)
	sig, err := schnorr.ParseSignature(signature)
	require.NoError(t, err)

	// Use schnorr pubkey serialization (x-coordinate only) like indexer does
	pubKeyBytes := schnorr.SerializePubKey(privKey.PubKey())
	pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)

	valid := sig.Verify(msgHash, pubKey)
	require.True(t, valid, "signature should verify with schnorr pubkey format")
}
