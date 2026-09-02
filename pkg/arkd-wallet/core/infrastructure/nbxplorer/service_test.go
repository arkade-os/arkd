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

func TestNbxplorerNotFound(t *testing.T) {
	// GetTransaction pins the contract the whole confirmation path
	// depends on. NBXplorer answers 404 for a transaction it has not seen, which is
	// an ordinary outcome rather than a fault: GetTransaction must report it as
	// ErrTransactionNotFound so the gRPC handler can translate it into "not
	// confirmed". When that translation is lost, the sweeper reads the resulting
	// error as "cannot schedule this sweep" and silently stops sweeping batches —
	// which is exactly what happened when the 404 error message stopped containing
	// the substring an earlier version of this function matched on.
	t.Run("GetTransaction", func(t *testing.T) {
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
	})

	// GetTxSpends covers the other side of the same 404: a transaction
	// that touches nothing the group tracks is the common case on every chain
	// event, so it must yield no spends rather than an error.
	t.Run("GetTxSpends yields no spends for an untracked transaction", func(t *testing.T) {
		n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		spends, err := n.GetTxSpends(context.Background(), testTxid)

		require.NoError(t, err)
		require.Empty(t, spends)
	})

	// makeRequest guards the compatibility half of the fix. The
	// sentinel is what callers should match on, but the message still has to carry
	// the HTTP status, because a caller that predates the sentinel detects a missing
	// resource by substring and would otherwise change behaviour silently.
	t.Run("makeRequest keeps the status in the not-found message", func(t *testing.T) {
		n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		_, err := n.makeRequest(context.Background(), "GET", "/anything", nil)

		require.Error(t, err)
		require.True(t, errors.Is(err, errNotFound))
		require.Contains(t, err.Error(), "404")
	})

	// GetTxSpends documents the deliberate asymmetry between the two
	// failure modes. A 404 means the transaction touches nothing tracked and is
	// reported as "no spends"; any other status is a real failure and must surface
	// as one, because treating it as "no spends" would let a transient server error
	// look identical to a transaction that genuinely spent nothing. The caller in
	// the notification loop logs it and still delivers the UTXO half of the event.
	t.Run("GetTxSpends surfaces a server error", func(t *testing.T) {
		n := newTestNbxplorer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		spends, err := n.GetTxSpends(context.Background(), testTxid)

		require.Error(t, err)
		require.NotErrorIs(t, err, application.ErrTransactionNotFound)
		require.Empty(t, spends)
	})
}

// TestParseOutpoint uses the exact encoding NBXplorer 2.6.7 returned on a live
// regtest instance. Responses serialise an outpoint as 36 bytes of hex — the
// hash in internal (reversed) byte order followed by a little-endian index —
// not the "<txid>-<index>" form the rescan *request* accepts. Confusing the two
// fails silently in the worst way: every spent outpoint is skipped, the unspent
// set is never reduced, and a caller using it to retract spends undoes each
// mempool spend one tick after recording it.
func TestParseOutpoint(t *testing.T) {
	// Observed live: funding tx 19631d10...a4bc vout 0 appeared in
	// unconfirmed.spentOutpoints as the value below once its spend hit the
	// mempool.
	const (
		wireEncoded = "bca470cd7c7cfb8f48abbd4e153bf088efd57daa4ed92b98d71714d0101d631900000000"
		wantTxid    = "19631d10d01417d7982bd94eaa7dd5ef88f03b154ebdab488ffb7c7ccd70a4bc"
	)

	t.Run("wire encoding from a response", func(t *testing.T) {
		out, err := parseOutpoint(wireEncoded)

		require.NoError(t, err)
		require.Equal(t, wantTxid, out.Hash.String())
		require.EqualValues(t, 0, out.Index)
	})

	t.Run("non-zero index is little endian", func(t *testing.T) {
		out, err := parseOutpoint(wireEncoded[:64] + "02000000")

		require.NoError(t, err)
		require.Equal(t, wantTxid, out.Hash.String())
		require.EqualValues(t, 2, out.Index)
	})

	// The dashed form is what rescanUTXOs sends; still accepted so a caller
	// passing the request encoding keeps working.
	t.Run("dashed request encoding", func(t *testing.T) {
		out, err := parseOutpoint(wantTxid + "-3")

		require.NoError(t, err)
		require.Equal(t, wantTxid, out.Hash.String())
		require.EqualValues(t, 3, out.Index)
	})

	t.Run("rejects malformed input", func(t *testing.T) {
		for _, s := range []string{"", "zzzz", wireEncoded[:60], wantTxid} {
			_, err := parseOutpoint(s)
			require.Error(t, err, "expected %q to be rejected", s)
		}
	})
}

// --- fixtures ---

const testTxid = "4ba63c204f39841e3a7c98e458586307cf6d33bbed9a9a520c827ab043f32701"

func newTestNbxplorer(t *testing.T, handler http.HandlerFunc) *nbxplorer {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &nbxplorer{url: srv.URL, httpClient: srv.Client(), groupID: "test-group"}
}
