package ports_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestSettingsDigest verifies that Settings.Digest() changes when (and only when)
// a field that feeds the digest computation changes. Fields that are not part of
// the digest must leave it untouched.
func TestSettingsDigest(t *testing.T) {
	delay := func(v uint32) arklib.RelativeLocktime {
		lt, _ := arklib.ParseRelativeLocktime(v)
		return lt
	}

	_, signerPubkey := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x11}, 32))
	_, forfeitPubkey := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x22}, 32))
	_, otherPubkey := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x33}, 32))

	// baseSettings returns a fresh, fully-populated settings value. Each case
	// mutates its own copy so cases never interfere with one another.
	baseSettings := func() ports.Settings {
		return ports.Settings{
			Settings: domain.Settings{
				// Fields that feed the digest.
				SessionDuration:           30 * time.Second,
				PublicUnilateralExitDelay: delay(512),
				BoardingExitDelay:         delay(1024),
				UtxoMinAmount:             1000,
				UtxoMaxAmount:             100000,
				VtxoMinAmount:             500,
				VtxoMaxAmount:             50000,
				MaxTxWeight:               400000,
				MaxOpReturnOutputs:        3,
				BatchFees:                 domain.BatchFees{OnchainInputFee: "0.0"},
				// Fields the digest ignores (set to non-zero so mutations are real changes).
				UnilateralExitDelay:           delay(512),
				CheckpointExitDelay:           delay(256),
				VtxoTreeExpiry:                delay(2048),
				BanThreshold:                  1,
				BanDuration:                   time.Minute,
				UnrolledVtxoMinExpiryMargin:   time.Minute,
				RoundMinParticipantsCount:     1,
				RoundMaxParticipantsCount:     10,
				SettlementMinExpiryGap:        time.Minute,
				VtxoNoCsvValidationCutoffDate: time.Unix(1_700_000_000, 0),
				AssetTxMaxWeightRatio:         0.5,
				NoteUriPrefix:                 "ark",
				BuildVersionHeader:            "v1.0.0",
				BuildVersionHeaderRequired:    true,
				DigestHeaderRequired:          true,
				UpdatedAt:                     time.Unix(1_700_000_000, 0),
			},
			Network:             arklib.Bitcoin,
			DustAmount:          354,
			SignerPubkey:        signerPubkey,
			ForfeitPubkey:       forfeitPubkey,
			ForfeitAddress:      "forfeit-address",
			CheckpointTapscript: []byte{0x01, 0x02, 0x03},
		}
	}

	tests := []struct {
		name          string
		mutate        func(s *ports.Settings)
		digestChanges bool
	}{
		// Fields the digest is computed from: changing any of them must change the digest.
		{"signer pubkey", func(s *ports.Settings) { s.SignerPubkey = otherPubkey }, true},
		{"forfeit pubkey", func(s *ports.Settings) { s.ForfeitPubkey = otherPubkey }, true},
		{"public unilateral exit delay", func(s *ports.Settings) { s.PublicUnilateralExitDelay = delay(1536) }, true},
		{"boarding exit delay", func(s *ports.Settings) { s.BoardingExitDelay = delay(1536) }, true},
		{"session duration", func(s *ports.Settings) { s.SessionDuration = 60 * time.Second }, true},
		{"network", func(s *ports.Settings) { s.Network = arklib.BitcoinTestNet }, true},
		{"dust amount", func(s *ports.Settings) { s.DustAmount = 999 }, true},
		{"forfeit address", func(s *ports.Settings) { s.ForfeitAddress = "other-address" }, true},
		{"utxo min amount", func(s *ports.Settings) { s.UtxoMinAmount = 2000 }, true},
		{"utxo max amount", func(s *ports.Settings) { s.UtxoMaxAmount = 200000 }, true},
		{"vtxo min amount", func(s *ports.Settings) { s.VtxoMinAmount = 600 }, true},
		{"vtxo max amount", func(s *ports.Settings) { s.VtxoMaxAmount = 60000 }, true},
		{"checkpoint tapscript", func(s *ports.Settings) { s.CheckpointTapscript = []byte{0x09} }, true},
		{"batch fees", func(s *ports.Settings) { s.BatchFees = domain.BatchFees{OnchainInputFee: "0.1"} }, true},
		{"max tx weight", func(s *ports.Settings) { s.MaxTxWeight = 500000 }, true},
		{"max op return outputs", func(s *ports.Settings) { s.MaxOpReturnOutputs = 5 }, true},

		// Fields the digest ignores: changing any of them must leave the digest unchanged.
		// Note: the digest uses PublicUnilateralExitDelay, NOT the internal UnilateralExitDelay.
		{"unilateral exit delay", func(s *ports.Settings) { s.UnilateralExitDelay = delay(1536) }, false},
		{"checkpoint exit delay", func(s *ports.Settings) { s.CheckpointExitDelay = delay(1536) }, false},
		{"vtxo tree expiry", func(s *ports.Settings) { s.VtxoTreeExpiry = delay(4096) }, false},
		{"ban threshold", func(s *ports.Settings) { s.BanThreshold = 999 }, false},
		{"ban duration", func(s *ports.Settings) { s.BanDuration = time.Hour }, false},
		{"unrolled vtxo min expiry margin", func(s *ports.Settings) { s.UnrolledVtxoMinExpiryMargin = time.Hour }, false},
		{"round min participants count", func(s *ports.Settings) { s.RoundMinParticipantsCount = 5 }, false},
		{"round max participants count", func(s *ports.Settings) { s.RoundMaxParticipantsCount = 500 }, false},
		{"settlement min expiry gap", func(s *ports.Settings) { s.SettlementMinExpiryGap = time.Hour }, false},
		{"vtxo no csv validation cutoff date", func(s *ports.Settings) { s.VtxoNoCsvValidationCutoffDate = time.Unix(1_800_000_000, 0) }, false},
		{"asset tx max weight ratio", func(s *ports.Settings) { s.AssetTxMaxWeightRatio = 0.9 }, false},
		{"note uri prefix", func(s *ports.Settings) { s.NoteUriPrefix = "other" }, false},
		{"scheduled session", func(s *ports.Settings) { s.ScheduledSession = &domain.ScheduledSession{Period: time.Hour} }, false},
		{"updated at", func(s *ports.Settings) { s.UpdatedAt = time.Unix(1_800_000_000, 0) }, false},
		{"build version header", func(s *ports.Settings) { s.BuildVersionHeader = "v2.0.0" }, false},
		{"build version header required", func(s *ports.Settings) { s.BuildVersionHeaderRequired = false }, false},
		{"digest header required", func(s *ports.Settings) { s.DigestHeaderRequired = false }, false},
	}

	baseDigest, err := baseSettings().Digest()
	require.NoError(t, err)
	require.NotEmpty(t, baseDigest)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := baseSettings()
			tt.mutate(&mutated)

			got, err := mutated.Digest()
			require.NoError(t, err)
			require.NotEmpty(t, got)

			if tt.digestChanges {
				require.NotEqual(
					t, baseDigest, got, "digest should change when %q changes", tt.name,
				)
			} else {
				require.Equal(
					t, baseDigest, got, "digest should not change when %q changes", tt.name,
				)
			}
		})
	}
}
