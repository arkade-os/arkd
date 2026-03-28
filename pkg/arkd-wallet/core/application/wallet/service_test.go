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
	Valid   []signMessageTestCase    `json:"valid"`
	Invalid []signMessageInvalidCase `json:"invalid"`
}

type signMessageTestCase struct {
	Name          string `json:"name"`
	MessageHex    string `json:"message_hex"`
	PrivateKeyHex string `json:"private_key_hex"`
}

type signMessageInvalidCase struct {
	Name          string `json:"name"`
	MessageHex    string `json:"message_hex"`
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

func TestSignMessage(t *testing.T) {
	fixtures := loadSignMessageFixtures(t)
	ctx := context.Background()

	t.Run("valid", func(t *testing.T) {
		for _, tc := range fixtures.Valid {
			t.Run(tc.Name, func(t *testing.T) {
				privKeyBytes, err := hex.DecodeString(tc.PrivateKeyHex)
				require.NoError(t, err)
				privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

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
