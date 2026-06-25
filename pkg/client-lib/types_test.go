package clientlib

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestServerParamsAllSigners(t *testing.T) {
	current, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	deprecated, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	cfg := ServerParams{
		SignerPubKey: current.PubKey(),
		DeprecatedSigners: []DeprecatedSigner{
			{PubKey: deprecated.PubKey()},
			{PubKey: current.PubKey()},
		},
	}

	signers := cfg.AllSigners()

	currentKey := hex.EncodeToString(schnorr.SerializePubKey(current.PubKey()))
	deprecatedKey := hex.EncodeToString(schnorr.SerializePubKey(deprecated.PubKey()))

	require.Len(t, signers, 2)
	require.True(t, signers[currentKey].IsEqual(current.PubKey()))
	require.True(t, signers[deprecatedKey].IsEqual(deprecated.PubKey()))
}
