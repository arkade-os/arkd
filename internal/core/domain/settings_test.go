package domain

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validSettings() Settings {
	return Settings{
		BanThreshold:              3,
		BanDuration:               300,
		VtxoTreeExpiry:            604672,
		UnilateralExitDelay:       86400,
		PublicUnilateralExitDelay: 86400,
		CheckpointExitDelay:       86400,
		BoardingExitDelay:         7776000,
		RoundMinParticipantsCount: 1,
		RoundMaxParticipantsCount: 128,
		VtxoMinAmount:             -1,
		VtxoMaxAmount:             -1,
		UtxoMinAmount:             -1,
		UtxoMaxAmount:             -1,
		MaxTxWeight:               40000,
	}
}

func TestSettings_Validate(t *testing.T) {
	t.Run("valid settings pass", func(t *testing.T) {
		require.NoError(t, validSettings().Validate())
	})

	t.Run("ban threshold must be at least 1", func(t *testing.T) {
		s := validSettings()
		s.BanThreshold = 0
		err := s.Validate()
		require.Error(t, err)
		var validationErr *ErrInvalidSettings
		require.ErrorAs(t, err, &validationErr)
		assert.Contains(t, validationErr.Reason, "ban threshold")
	})

	t.Run("amount lower bound", func(t *testing.T) {
		tests := []struct {
			name  string
			field string
			set   func(*Settings, int64)
		}{
			{"vtxo min", "vtxo min amount", func(s *Settings, v int64) { s.VtxoMinAmount = v }},
			{"vtxo max", "vtxo max amount", func(s *Settings, v int64) { s.VtxoMaxAmount = v }},
			{"utxo min", "utxo min amount", func(s *Settings, v int64) { s.UtxoMinAmount = v }},
			{"utxo max", "utxo max amount", func(s *Settings, v int64) { s.UtxoMaxAmount = v }},
		}
		for _, tt := range tests {
			t.Run(tt.name+" rejects -2", func(t *testing.T) {
				s := validSettings()
				tt.set(&s, -2)
				err := s.Validate()
				require.Error(t, err)
				var validationErr *ErrInvalidSettings
				require.ErrorAs(t, err, &validationErr)
				assert.Contains(t, validationErr.Reason, tt.field)
			})

			t.Run(tt.name+" accepts -1", func(t *testing.T) {
				s := validSettings()
				tt.set(&s, -1)
				require.NoError(t, s.Validate())
			})
		}
	})

	t.Run("amount upper bound", func(t *testing.T) {
		tests := []struct {
			name  string
			field string
			set   func(*Settings, int64)
		}{
			{"vtxo min", "vtxo min amount", func(s *Settings, v int64) { s.VtxoMinAmount = v }},
			{"vtxo max", "vtxo max amount", func(s *Settings, v int64) { s.VtxoMaxAmount = v }},
			{"utxo min", "utxo min amount", func(s *Settings, v int64) { s.UtxoMinAmount = v }},
			{"utxo max", "utxo max amount", func(s *Settings, v int64) { s.UtxoMaxAmount = v }},
		}
		for _, tt := range tests {
			t.Run(tt.name+" rejects above max satoshis", func(t *testing.T) {
				s := validSettings()
				tt.set(&s, MaxSatoshis+1)
				err := s.Validate()
				require.Error(t, err)
				var validationErr *ErrInvalidSettings
				require.ErrorAs(t, err, &validationErr)
				assert.Contains(t, validationErr.Reason, tt.field)
			})

			t.Run(tt.name+" accepts max satoshis", func(t *testing.T) {
				s := validSettings()
				tt.set(&s, MaxSatoshis)
				require.NoError(t, s.Validate())
			})
		}
	})

	t.Run("uint32 overflow", func(t *testing.T) {
		tests := []struct {
			name string
			set  func(*Settings)
		}{
			{"unilateral exit delay", func(s *Settings) {
				s.UnilateralExitDelay = math.MaxUint32 + 1
				s.PublicUnilateralExitDelay = math.MaxUint32 + 1
			}},
			{"boarding exit delay", func(s *Settings) {
				s.BoardingExitDelay = math.MaxUint32 + 1
			}},
			{"vtxo tree expiry", func(s *Settings) {
				s.VtxoTreeExpiry = math.MaxUint32 + 1
			}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s := validSettings()
				tt.set(&s)
				err := s.Validate()
				require.Error(t, err)
				var validationErr *ErrInvalidSettings
				require.ErrorAs(t, err, &validationErr)
				assert.Contains(t, validationErr.Reason, "exceeds maximum uint32")
			})
		}
	})

	t.Run("min exceeds max", func(t *testing.T) {
		t.Run("vtxo", func(t *testing.T) {
			s := validSettings()
			s.VtxoMinAmount = 1000
			s.VtxoMaxAmount = 500
			err := s.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "vtxo min amount must be <= vtxo max amount")
		})

		t.Run("utxo", func(t *testing.T) {
			s := validSettings()
			s.UtxoMinAmount = 1000
			s.UtxoMaxAmount = 500
			err := s.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "utxo min amount must be <= utxo max amount")
		})

		t.Run("skipped when sentinel", func(t *testing.T) {
			s := validSettings()
			s.VtxoMinAmount = 1000
			s.VtxoMaxAmount = -1
			require.NoError(t, s.Validate())
		})
	})
}
