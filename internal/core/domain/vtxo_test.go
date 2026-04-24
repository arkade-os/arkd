package domain_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

const validVtxoPubkey = "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"

func TestOutpoint(t *testing.T) {
	t.Run("FromString", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			original := domain.Outpoint{
				Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				VOut: 42,
			}
			var parsed domain.Outpoint
			err := parsed.FromString(original.String())
			require.NoError(t, err)
			require.Equal(t, original, parsed)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				name string
				s    string
			}{
				{"empty", ""},
				{"no separator", "abcdef"},
				{"too many separators", "abcdef:1:2"},
				{"non numeric vout", "abcdef:xyz"},
				{"negative vout", "abcdef:-1"},
			}
			for _, f := range fixtures {
				t.Run(f.name, func(t *testing.T) {
					var op domain.Outpoint
					err := op.FromString(f.s)
					require.Error(t, err)
				})
			}
		})
	})
}

func TestVtxo_IsNote(t *testing.T) {
	fixtures := []struct {
		name   string
		vtxo   domain.Vtxo
		isNote bool
	}{
		{
			name:   "should be true",
			vtxo:   domain.Vtxo{},
			isNote: true,
		},
		{
			name: "should be false",
			vtxo: domain.Vtxo{
				CommitmentTxids:    []string{"txid1"},
				RootCommitmentTxid: "rootid",
			},
			isNote: false,
		},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			require.Equal(t, f.isNote, f.vtxo.IsNote())
		})
	}
}

func TestVtxo_IsSettled(t *testing.T) {
	fixtures := []struct {
		name      string
		vtxo      domain.Vtxo
		isSettled bool
	}{
		{
			name:      "should be true",
			vtxo:      domain.Vtxo{SettledBy: "commitment-txid"},
			isSettled: true,
		},
		{
			name:      "should be false",
			vtxo:      domain.Vtxo{},
			isSettled: false,
		},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			require.Equal(t, f.isSettled, f.vtxo.IsSettled())
		})
	}
}

func TestVtxo_IsExpired(t *testing.T) {
	fixtures := []struct {
		name      string
		vtxo      domain.Vtxo
		isExpired bool
	}{
		{
			name:      "should be true",
			vtxo:      domain.Vtxo{ExpiresAt: time.Now().Add(-time.Hour).Unix()},
			isExpired: true,
		},
		{
			name:      "should be false",
			vtxo:      domain.Vtxo{ExpiresAt: time.Now().Add(time.Hour).Unix()},
			isExpired: false,
		},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			require.Equal(t, f.isExpired, f.vtxo.IsExpired())
		})
	}
}

func TestVtxo_RequiresForfeit(t *testing.T) {
	futureExpiry := time.Now().Add(time.Hour).Unix()
	pastExpiry := time.Now().Add(-time.Hour).Unix()

	fixtures := []struct {
		name            string
		vtxo            domain.Vtxo
		requiresForfeit bool
	}{
		{
			name: "should be true",
			vtxo: domain.Vtxo{
				CommitmentTxids: []string{"txid1"},
				ExpiresAt:       futureExpiry,
			},
			requiresForfeit: true,
		},
		{
			name: "should be false (swept)",
			vtxo: domain.Vtxo{
				CommitmentTxids: []string{"txid1"},
				ExpiresAt:       futureExpiry,
				Swept:           true,
			},
			requiresForfeit: false,
		},
		{
			name: "should be false (expired)",
			vtxo: domain.Vtxo{
				CommitmentTxids: []string{"txid1"},
				ExpiresAt:       pastExpiry,
			},
			requiresForfeit: false,
		},
		{
			name: "should be false (note)",
			vtxo: domain.Vtxo{
				ExpiresAt: futureExpiry,
			},
			requiresForfeit: false,
		},
		{
			name: "should be false (unrolled)",
			vtxo: domain.Vtxo{
				CommitmentTxids: []string{"txid1"},
				ExpiresAt:       futureExpiry,
				Unrolled:        true,
			},
			requiresForfeit: false,
		},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			require.Equal(t, f.requiresForfeit, f.vtxo.RequiresForfeit())
		})
	}
}

func TestVtxo_TapKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		v := domain.Vtxo{PubKey: validVtxoPubkey}
		key, err := v.TapKey()
		require.NoError(t, err)
		require.NotNil(t, key)

		expected, err := hex.DecodeString(validVtxoPubkey)
		require.NoError(t, err)
		parsed, err := schnorr.ParsePubKey(expected)
		require.NoError(t, err)
		require.True(t, key.IsEqual(parsed))
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name string
			vtxo domain.Vtxo
		}{
			{"invalid hex", domain.Vtxo{PubKey: "not-hex"}},
			{"invalid pubkey length", domain.Vtxo{PubKey: "abcd"}},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				_, err := f.vtxo.TapKey()
				require.Error(t, err)
			})
		}
	})
}

func TestVtxo_OutputScript(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		v := domain.Vtxo{PubKey: validVtxoPubkey}
		pkScript, err := v.OutputScript()
		require.NoError(t, err)
		require.NotEmpty(t, pkScript)
		// P2TR script: OP_1 <32-byte x-only pubkey> = 34 bytes total
		require.Len(t, pkScript, 34)
		require.Equal(t, byte(0x51), pkScript[0]) // OP_1
		require.Equal(t, byte(0x20), pkScript[1]) // push 32 bytes
	})

	t.Run("invalid", func(t *testing.T) {
		v := domain.Vtxo{PubKey: "not-hex"}
		_, err := v.OutputScript()
		require.Error(t, err)
	})
}
