package handlers

import (
	"context"
	"errors"
	"testing"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/stretchr/testify/require"
)

// TestIsTransactionConfirmedNotFound pins the flag that separates a transaction
// the backend has never seen from one it has and sees unconfirmed. Both answer
// confirmed = false, so without the flag a caller cannot tell an evicted or
// replaced transaction from one still waiting, and anything acting on that
// difference would either never act or act wrongly.
func TestIsTransactionConfirmedNotFound(t *testing.T) {
	const txid = "4ba63c204f39841e3a7c98e458586307cf6d33bbed9a9a520c827ab043f32701"

	t.Run("a transaction the backend does not have is flagged not found", func(t *testing.T) {
		h := &walletHandler{scanner: &confirmScanner{err: application.ErrTransactionNotFound}}

		resp, err := h.IsTransactionConfirmed(
			context.Background(), &arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
		)

		require.NoError(t, err, "a missing transaction is an ordinary answer, not a failure")
		require.False(t, resp.GetConfirmed())
		require.True(t, resp.GetNotFound())
	})

	// The case the flag exists to distinguish: known to the backend, just not
	// mined yet. Flagging this one would let a caller treat a live transaction
	// as gone.
	t.Run("an unconfirmed transaction is not flagged not found", func(t *testing.T) {
		h := &walletHandler{scanner: &confirmScanner{}}

		resp, err := h.IsTransactionConfirmed(
			context.Background(), &arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
		)

		require.NoError(t, err)
		require.False(t, resp.GetConfirmed())
		require.False(t, resp.GetNotFound())
	})

	t.Run("a confirmed transaction is not flagged not found", func(t *testing.T) {
		h := &walletHandler{scanner: &confirmScanner{
			confirmed: true, blockHeight: 964276, blockTime: 1700000000,
		}}

		resp, err := h.IsTransactionConfirmed(
			context.Background(), &arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
		)

		require.NoError(t, err)
		require.True(t, resp.GetConfirmed())
		require.False(t, resp.GetNotFound())
		require.EqualValues(t, 964276, resp.GetBlocknumber())
	})

	// Any other failure stays a failure. Reporting it as not found would tell
	// the caller the transaction is gone when the backend simply could not say.
	// The signal the retraction actually depends on: a replaced transaction is
	// still known and still answers "not confirmed", so only this names it.
	t.Run("a replaced transaction reports its replacement", func(t *testing.T) {
		const replacement = "4dc2f8e63b9dc3825f69c8295a48a9b87ba4c663f42ea7b49fa335746d626246"
		h := &walletHandler{scanner: &confirmScanner{replacedBy: replacement}}

		resp, err := h.IsTransactionConfirmed(
			context.Background(), &arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
		)

		require.NoError(t, err)
		require.False(t, resp.GetConfirmed())
		require.False(t, resp.GetNotFound())
		require.Equal(t, replacement, resp.GetReplacedBy())
	})

	// A backend that cannot answer must not be read as "not replaced", so the
	// field stays empty and the caller sees no signal rather than a false one.
	t.Run("a failed replacement lookup leaves the field empty", func(t *testing.T) {
		h := &walletHandler{scanner: &confirmScanner{replacedErr: errors.New("backend down")}}

		resp, err := h.IsTransactionConfirmed(
			context.Background(), &arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
		)

		require.NoError(t, err)
		require.Empty(t, resp.GetReplacedBy())
	})

	t.Run("another failure is returned as an error", func(t *testing.T) {
		h := &walletHandler{scanner: &confirmScanner{err: errors.New("backend down")}}

		_, err := h.IsTransactionConfirmed(
			context.Background(), &arkwalletv1.IsTransactionConfirmedRequest{Txid: txid},
		)

		require.Error(t, err)
	})
}

// --- fixtures ---

// confirmScanner answers IsTransactionConfirmed with a fixed result. The
// embedded interface is nil, so any other method panics rather than silently
// returning a zero value.
type confirmScanner struct {
	application.BlockchainScanner
	confirmed   bool
	blockHeight int64
	blockTime   int64
	replacedBy  string
	err         error
	replacedErr error
}

func (s *confirmScanner) TransactionReplacedBy(_ context.Context, _ string) (string, error) {
	return s.replacedBy, s.replacedErr
}

func (s *confirmScanner) IsTransactionConfirmed(
	_ context.Context, _ string,
) (bool, int64, int64, error) {
	if s.err != nil {
		return false, 0, 0, s.err
	}
	return s.confirmed, s.blockHeight, s.blockTime, nil
}
