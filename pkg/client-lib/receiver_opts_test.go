package arksdk

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

func TestWithReceiver(t *testing.T) {
	const addr = "tark1qfaketestaddressgoesherenoadditionalvalidationhere"

	t.Run("invalid", func(t *testing.T) {
		t.Run("rejects empty addr - sendOptions", func(t *testing.T) {
			opts := newDefaultSendOptions()
			err := WithReceiver("").applySend(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "missing")
			require.Empty(t, opts.receiver)
		})

		t.Run("rejects empty addr - batchSessionOptions", func(t *testing.T) {
			opts := newDefaultSettleOptions()
			err := WithReceiver("").applyBatch(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "missing")
			require.Empty(t, opts.receiver)
		})

		t.Run("rejects empty addr - unrollOptions", func(t *testing.T) {
			opts := newDefaultUnrollOptions()
			err := WithReceiver("").applyUnroll(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "missing")
			require.Empty(t, opts.receiver)
		})

		t.Run("rejects double-set - sendOptions", func(t *testing.T) {
			opts := newDefaultSendOptions()
			require.NoError(t, WithReceiver(addr).applySend(opts))
			err := WithReceiver(addr).applySend(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "already set")
		})

		t.Run("rejects double-set - batchSessionOptions", func(t *testing.T) {
			opts := newDefaultSettleOptions()
			require.NoError(t, WithReceiver(addr).applyBatch(opts))
			err := WithReceiver(addr).applyBatch(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "already set")
		})

		t.Run("rejects double-set - unrollOptions", func(t *testing.T) {
			opts := newDefaultUnrollOptions()
			require.NoError(t, WithReceiver(addr).applyUnroll(opts))
			err := WithReceiver(addr).applyUnroll(opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "already set")
		})
	})

	t.Run("valid", func(t *testing.T) {
		t.Run("stores addr - sendOptions", func(t *testing.T) {
			opts := newDefaultSendOptions()
			require.NoError(t, WithReceiver(addr).applySend(opts))
			require.Equal(t, addr, opts.receiver)
		})

		t.Run("stores addr - batchSessionOptions", func(t *testing.T) {
			opts := newDefaultSettleOptions()
			require.NoError(t, WithReceiver(addr).applyBatch(opts))
			require.Equal(t, addr, opts.receiver)
		})

		t.Run("stores addr - unrollOptions", func(t *testing.T) {
			opts := newDefaultUnrollOptions()
			require.NoError(t, WithReceiver(addr).applyUnroll(opts))
			require.Equal(t, addr, opts.receiver)
		})

		t.Run("usable as SendOption", func(t *testing.T) {
			var _ SendOption = WithReceiver(addr)
		})

		t.Run("usable as BatchSessionOption", func(t *testing.T) {
			var _ BatchSessionOption = WithReceiver(addr)
		})

		t.Run("usable as UnrollOption", func(t *testing.T) {
			var _ UnrollOption = WithReceiver(addr)
		})
	})
}

func TestValidateOffchainAddress(t *testing.T) {
	t.Run("rejects empty", func(t *testing.T) {
		err := validateOffchainAddress("")
		require.Error(t, err)
	})
	t.Run("rejects malformed", func(t *testing.T) {
		err := validateOffchainAddress("not-an-address")
		require.Error(t, err)
	})
	t.Run("rejects onchain bitcoin address", func(t *testing.T) {
		// regtest p2tr-style — should fail offchain decoding (HRP not in allowed set)
		err := validateOffchainAddress(
			"bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2skvg4",
		)
		require.Error(t, err)
	})
}

func TestValidateOnchainAddress(t *testing.T) {
	t.Run("rejects empty", func(t *testing.T) {
		err := validateOnchainAddress("", arklib.BitcoinRegTest)
		require.Error(t, err)
	})
	t.Run("rejects malformed", func(t *testing.T) {
		err := validateOnchainAddress("not-an-address", arklib.BitcoinRegTest)
		require.Error(t, err)
	})
}

func TestValidateOffchainOrOnchainAddress(t *testing.T) {
	t.Run("rejects empty", func(t *testing.T) {
		err := validateOffchainOrOnchainAddress("", arklib.BitcoinRegTest)
		require.Error(t, err)
	})
	t.Run("rejects malformed", func(t *testing.T) {
		err := validateOffchainOrOnchainAddress("not-an-address", arklib.BitcoinRegTest)
		require.Error(t, err)
	})
}
