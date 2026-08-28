package nbxplorer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/stretchr/testify/require"
)

const testTxid = "4ba63c204f39841e3a7c98e458586307cf6d33bbed9a9a520c827ab043f32701"

func newTestNbxplorer(t *testing.T, handler http.HandlerFunc) *nbxplorer {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &nbxplorer{url: srv.URL, httpClient: srv.Client(), groupID: "test-group"}
}

// TestGetTransactionNotFound pins the contract the whole confirmation path
// depends on. NBXplorer answers 404 for a transaction it has not seen, which is
// an ordinary outcome rather than a fault: GetTransaction must report it as
// ErrTransactionNotFound so the gRPC handler can translate it into "not
// confirmed". When that translation is lost, the sweeper reads the resulting
// error as "cannot schedule this sweep" and silently stops sweeping batches —
// which is exactly what happened when the 404 error message stopped containing
// the substring an earlier version of this function matched on.
func TestGetTransactionNotFound(t *testing.T) {
	t.Run("reports a missing transaction as not found", func(t *testing.T) {
		n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		details, err := n.GetTransaction(context.Background(), testTxid)

		require.Nil(t, details)
		require.ErrorIs(t, err, application.ErrTransactionNotFound)
	})

	// Any other failure must stay a failure: reporting it as "not found" would
	// tell the caller the transaction is merely unconfirmed.
	t.Run("does not mistake another error for not found", func(t *testing.T) {
		n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, err := n.GetTransaction(context.Background(), testTxid)

		require.Error(t, err)
		require.NotErrorIs(t, err, application.ErrTransactionNotFound)
	})

	t.Run("returns details when the transaction exists", func(t *testing.T) {
		n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			//nolint:errcheck
			_, _ = w.Write([]byte(
				`{"transactionId":"` + testTxid + `","confirmations":3,"height":964276}`,
			))
		})

		details, err := n.GetTransaction(context.Background(), testTxid)

		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, testTxid, details.TxID)
		require.EqualValues(t, 3, details.Confirmations)
	})
}

// TestGetTxSpendsNotFound covers the other side of the same 404: a transaction
// that touches nothing the group tracks is the common case on every chain
// event, so it must yield no spends rather than an error.
func TestGetTxSpendsNotFound(t *testing.T) {
	n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	spends, err := n.GetTxSpends(context.Background(), testTxid)

	require.NoError(t, err)
	require.Empty(t, spends)
}

// TestMakeRequestNotFoundMessage guards the compatibility half of the fix. The
// sentinel is what callers should match on, but the message still has to carry
// the HTTP status, because a caller that predates the sentinel detects a missing
// resource by substring and would otherwise change behaviour silently.
func TestMakeRequestNotFoundMessage(t *testing.T) {
	n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, err := n.makeRequest(context.Background(), "GET", "/anything", nil)

	require.Error(t, err)
	require.True(t, errors.Is(err, errNotFound))
	require.Contains(t, err.Error(), "404")
}
