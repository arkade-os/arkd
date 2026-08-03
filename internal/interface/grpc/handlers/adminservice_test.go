package handlers

import (
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
