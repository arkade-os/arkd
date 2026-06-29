package interceptors

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestSanitizeMetadata(t *testing.T) {
	t.Run("selects metadata of interest", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"x-build-version", "1.2.3",
			"x-sdk-version", "0.9.0",
			"x-digest", "abc123",
			"authorization", "secret",
		))

		got, ok := sanitizeMetadata(ctx)

		require.True(t, ok)
		require.JSONEq(t, `{
			"x-build-version": "1.2.3",
			"x-sdk-version": "0.9.0",
			"x-digest": "abc123"
		}`, got)
	})

	t.Run("preserves multiple values", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"x-sdk-version", "0.9.0",
			"x-sdk-version", "0.9.1",
		))

		got, ok := sanitizeMetadata(ctx)

		require.True(t, ok)
		require.JSONEq(t, `{
			"x-sdk-version": ["0.9.0", "0.9.1"]
		}`, got)
	})

	t.Run("returns false without incoming metadata", func(t *testing.T) {
		got, ok := sanitizeMetadata(context.Background())

		require.False(t, ok)
		require.Empty(t, got)
	})

	t.Run("returns false without metadata of interest", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"authorization", "secret",
			"x-request-id", "request-id",
		))

		got, ok := sanitizeMetadata(ctx)

		require.False(t, ok)
		require.Empty(t, got)
	})

	t.Run("replaces oversized values", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"x-digest", strings.Repeat("a", maxMetadataValueSizeBytes+1),
		))

		got, ok := sanitizeMetadata(ctx)

		require.True(t, ok)
		require.JSONEq(t, `{
			"x-digest": "`+invalidMetadataValue+`"
		}`, got)
	})
}
