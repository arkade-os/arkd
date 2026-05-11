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

	t.Run("checkpoint exit delay must be > 0", func(t *testing.T) {
		s := validSettings()
		s.CheckpointExitDelay = 0
		err := s.Validate()
		require.Error(t, err)
		var validationErr *ErrInvalidSettings
		require.ErrorAs(t, err, &validationErr)
		assert.Contains(t, validationErr.Reason, "checkpoint exit delay")
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
			{"checkpoint exit delay", func(s *Settings) {
				s.CheckpointExitDelay = math.MaxUint32 + 1
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

	t.Run("merge with update_fields updates only listed fields", func(t *testing.T) {
		current := validSettings()
		partial := Settings{BanThreshold: 10}
		merged, err := partial.Merge(current, []string{"ban_threshold"})
		require.NoError(t, err)

		assert.Equal(t, int64(10), merged.BanThreshold)
		assert.Equal(t, current.BanDuration, merged.BanDuration)
		assert.Equal(t, current.UnilateralExitDelay, merged.UnilateralExitDelay)
		assert.Equal(t, current.BoardingExitDelay, merged.BoardingExitDelay)
		assert.Equal(t, current.VtxoTreeExpiry, merged.VtxoTreeExpiry)
		assert.Equal(t, current.MaxTxWeight, merged.MaxTxWeight)
		require.NoError(t, merged.Validate())
	})

	t.Run("merge with update_fields allows setting field to zero", func(t *testing.T) {
		current := validSettings()
		current.SettlementMinExpiryGap = 3600
		update := Settings{SettlementMinExpiryGap: 0}
		merged, err := update.Merge(current, []string{"settlement_min_expiry_gap"})
		require.NoError(t, err)

		assert.Equal(t, int64(0), merged.SettlementMinExpiryGap)
		// Other fields unchanged.
		assert.Equal(t, current.BanThreshold, merged.BanThreshold)
	})

	t.Run("merge with empty update_fields replaces all fields", func(t *testing.T) {
		current := validSettings()
		full := validSettings()
		full.BanThreshold = 99
		merged, err := full.Merge(current, nil)
		require.NoError(t, err)

		assert.Equal(t, int64(99), merged.BanThreshold)
		assert.Equal(t, full.BanDuration, merged.BanDuration)
	})

	t.Run("merge rejects unknown update_fields", func(t *testing.T) {
		current := validSettings()
		_, err := current.Merge(current, []string{"ban_threshol"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown update field: "ban_threshol"`)
	})

	t.Run("merge rejects duplicate update_fields", func(t *testing.T) {
		current := validSettings()
		_, err := current.Merge(current, []string{"ban_threshold", "ban_threshold"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `duplicate update field: "ban_threshold"`)
	})

	t.Run("validUpdateFields matches Settings struct", func(t *testing.T) {
		expected := map[string]struct{}{
			"ban_threshold":                      {},
			"ban_duration":                       {},
			"unilateral_exit_delay":              {},
			"public_unilateral_exit_delay":       {},
			"checkpoint_exit_delay":              {},
			"boarding_exit_delay":                {},
			"vtxo_tree_expiry":                   {},
			"round_min_participants_count":       {},
			"round_max_participants_count":       {},
			"vtxo_min_amount":                    {},
			"vtxo_max_amount":                    {},
			"utxo_min_amount":                    {},
			"utxo_max_amount":                    {},
			"settlement_min_expiry_gap":          {},
			"vtxo_no_csv_validation_cutoff_date": {},
			"max_tx_weight":                      {},
		}
		assert.Equal(t, expected, validUpdateFields)
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
