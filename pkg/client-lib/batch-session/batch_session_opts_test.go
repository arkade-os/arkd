package batchsession

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/stretchr/testify/require"
)

func TestWithEventsCh(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		t.Run("applied twice", func(t *testing.T) {
			opts := newOptions()
			ch := make(chan any, 1)
			require.NoError(t, WithEventsCh(ch).apply(opts))

			err := WithEventsCh(ch).apply(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "events channel already set")
		})
	})
}

func TestWithExtraSigner(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		t.Run("no signer sessions", func(t *testing.T) {
			opts := newOptions()
			err := WithExtraSigner([]tree.SignerSession{}...).apply(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no signer sessions provided")
		})
	})
}

func TestWithRetries(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		t.Run("applied twice", func(t *testing.T) {
			opts := newOptions()
			require.NoError(t, WithRetries(1).apply(opts))

			err := WithRetries(1).apply(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "retry num already set")
		})

		t.Run("zero or negative", func(t *testing.T) {
			opts := newOptions()
			err := WithRetries(0).apply(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "retry num must be in range [1, 3]")
		})

		t.Run("above max", func(t *testing.T) {
			opts := newOptions()
			err := WithRetries(4).apply(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "retry num must be in range [1, 3]")
		})
	})
}
