package handlers

import (
	"math"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUpdateSettingsRejectsNegativeUnsignedFields(t *testing.T) {
	handler := &adminHandler{}

	// Negative values are stored as uint64 and would invert the comparisons that
	// use them, banning or rejecting everyone.
	t.Run("ban threshold", func(t *testing.T) {
		threshold := int64(-1)
		_, err := handler.UpdateSettings(t.Context(), &arkv1.UpdateSettingsRequest{
			Settings: &arkv1.Settings{BanThreshold: &threshold},
		})
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.Contains(t, st.Message(), "invalid ban threshold")
	})

	t.Run("max op return outputs", func(t *testing.T) {
		maxOpReturnOutputs := int64(-1)
		_, err := handler.UpdateSettings(t.Context(), &arkv1.UpdateSettingsRequest{
			Settings: &arkv1.Settings{MaxOpReturnOutputs: &maxOpReturnOutputs},
		})
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.Contains(t, st.Message(), "invalid max op return outputs")
	})

	// Narrowing a locktime to uint32 inverts its meaning instead: -1 becomes a
	// ~136 years delay, which passes Settings.Validate and locks funds up.
	t.Run("locktimes", func(t *testing.T) {
		for _, tt := range []struct {
			name  string
			apply func(*arkv1.Settings, *int64)
		}{
			{"unilateral exit delay", func(s *arkv1.Settings, v *int64) { s.UnilateralExitDelay = v }},
			{"public unilateral exit delay", func(s *arkv1.Settings, v *int64) {
				s.PublicUnilateralExitDelay = v
			}},
			{"checkpoint exit delay", func(s *arkv1.Settings, v *int64) { s.CheckpointExitDelay = v }},
			{"boarding exit delay", func(s *arkv1.Settings, v *int64) { s.BoardingExitDelay = v }},
			{"vtxo tree expiry", func(s *arkv1.Settings, v *int64) { s.VtxoTreeExpiry = v }},
		} {
			t.Run(tt.name, func(t *testing.T) {
				for _, delay := range []int64{-1, math.MaxUint32 + 1} {
					settings := &arkv1.Settings{}
					tt.apply(settings, &delay)

					_, err := handler.UpdateSettings(t.Context(), &arkv1.UpdateSettingsRequest{
						Settings: settings,
					})
					require.Error(t, err)

					st, ok := status.FromError(err)
					require.True(t, ok)
					require.Equal(t, codes.InvalidArgument, st.Code())
					require.Contains(t, st.Message(), "invalid locktime")
				}
			})
		}
	})
}

func TestRevokeTokensRequiresFilter(t *testing.T) {
	handler := &adminHandler{}

	_, err := handler.RevokeTokens(t.Context(), &arkv1.RevokeTokensRequest{})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "at least one filter")
}

func TestParseSettingsRateLimit(t *testing.T) {
	t.Run("maps set rate-limit fields", func(t *testing.T) {
		enabled := true
		velocity := 0.5
		cooldown := int64(1800)

		update, err := parseSettings(&arkv1.Settings{
			RateLimitEnabled:         &enabled,
			RateLimitMaxVelocity:     &velocity,
			RateLimitMaxCooldownSecs: &cooldown,
		})
		require.NoError(t, err)
		require.NotNil(t, update.RateLimitEnabled)
		require.True(t, *update.RateLimitEnabled)
		require.NotNil(t, update.RateLimitMaxVelocity)
		require.Equal(t, 0.5, *update.RateLimitMaxVelocity)
		require.NotNil(t, update.RateLimitMaxCooldownSecs)
		require.Equal(t, int64(1800), *update.RateLimitMaxCooldownSecs)
	})

	t.Run("leaves unset rate-limit fields nil", func(t *testing.T) {
		update, err := parseSettings(&arkv1.Settings{})
		require.NoError(t, err)
		require.Nil(t, update.RateLimitEnabled)
		require.Nil(t, update.RateLimitMaxVelocity)
		require.Nil(t, update.RateLimitMaxCooldownSecs)
	})
}
