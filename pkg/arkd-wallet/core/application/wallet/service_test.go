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

type signMessageFixtures struct {
	TestKeys []testKey              `json:"test_keys"`
	Valid    []signMessageTestCase  `json:"valid"`
	Invalid  []signMessageInvalidCase `json:"invalid"`
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

type signMessageInvalidCase struct {
	Name          string `json:"name"`
	MessageHex    string `json:"message_hex"`
	KeyName       string `json:"key_name"`
	ExpectedError string `json:"expected_error"`
}

func loadSignMessageFixtures(t *testing.T) *signMessageFixtures {
	t.Helper()
	data, err := os.ReadFile("testdata/signmessage_fixtures.json")
	require.NoError(t, err)

	var f signMessageFixtures
	err = json.Unmarshal(data, &f)
	require.NoError(t, err)

	return &f
}

func getTestKey(t *testing.T, fixtures *signMessageFixtures, keyName string) *btcec.PrivateKey {
	t.Helper()
	for _, k := range fixtures.TestKeys {
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
	fixtures := loadSignMessageFixtures(t)
	ctx := context.Background()

	t.Run("valid", func(t *testing.T) {
		for _, tc := range fixtures.Valid {
			t.Run(tc.Name, func(t *testing.T) {
				privKey := getTestKey(t, fixtures, tc.KeyName)

				w := &wallet{
					WalletOptions: WalletOptions{
						SignerKey: privKey,
					},
				}

				message, err := hex.DecodeString(tc.MessageHex)
				require.NoError(t, err)

				signature, err := w.SignMessage(ctx, message)
				require.NoError(t, err)
				require.NotNil(t, signature)

				require.Len(t, signature, 64, "schnorr signature should be 64 bytes")

				msgHash := chainhash.HashB(message)
				sig, err := schnorr.ParseSignature(signature)
				require.NoError(t, err)

				pubKey := privKey.PubKey()
				valid := sig.Verify(msgHash, pubKey)
				require.True(t, valid, "signature should be valid")
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, tc := range fixtures.Invalid {
			t.Run(tc.Name, func(t *testing.T) {
				w := &wallet{
					WalletOptions: WalletOptions{
						SignerKey: nil,
					},
				}

				message, err := hex.DecodeString(tc.MessageHex)
				require.NoError(t, err)

				signature, err := w.SignMessage(ctx, message)
				require.Error(t, err)
				require.Nil(t, signature)
				require.Contains(t, err.Error(), tc.ExpectedError)
			})
		}
	})
}
