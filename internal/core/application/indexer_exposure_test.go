package application

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// mockRoundRepo implements only GetTxsWithTxids; other methods panic if called.
type mockRoundRepo struct {
	domain.RoundRepository
	txs map[string]string // txid -> raw tx
}

func (m *mockRoundRepo) GetTxsWithTxids(
	_ context.Context, txids []string,
) ([]string, error) {
	result := make([]string, 0, len(txids))
	for _, txid := range txids {
		if tx, ok := m.txs[txid]; ok {
			result = append(result, tx)
		}
	}
	return result, nil
}

type mockRepoManager struct {
	ports.RepoManager
	rounds *mockRoundRepo
}

func (m *mockRepoManager) Rounds() domain.RoundRepository { return m.rounds }

func newTestIndexerWithExposure(
	privkey *btcec.PrivateKey, exposure string, repo ports.RepoManager,
) *indexerService {
	return &indexerService{
		repoManager:  repo,
		privkey:      privkey,
		authPubkey: schnorr.SerializePubKey(privkey.PubKey()),
		txExposure:   exposure,
		authTokenTTL: defaultAuthTokenTTL,
	}
}

var testTxids = []string{
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

// TestGetVirtualTxs_PublicExposure verifies that in public mode, GetVirtualTxs
// returns transaction data regardless of whether an auth token is provided.
func TestGetVirtualTxs_PublicExposure(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	repo := &mockRepoManager{
		rounds: &mockRoundRepo{txs: map[string]string{
			testTxids[0]: "fakeTxData",
		}},
	}
	indexer := newTestIndexerWithExposure(privkey, "public", repo)

	t.Run("no token returns txs", func(t *testing.T) {
		resp, err := indexer.GetVirtualTxs(context.Background(), "", testTxids, nil)
		require.NoError(t, err)
		require.Len(t, resp.Txs, 1)
	})

	t.Run("with token still returns txs", func(t *testing.T) {
		resp, err := indexer.GetVirtualTxs(context.Background(), "sometoken", testTxids, nil)
		require.NoError(t, err)
		require.Len(t, resp.Txs, 1)
	})
}

// TestGetVirtualTxs_PrivateExposure verifies that in private mode, GetVirtualTxs
// rejects requests without a valid auth token. An empty token must return
// "auth token is required" and a malformed token must return "invalid auth token".
// This prevents unauthenticated callers from accessing virtual transaction data.
func TestGetVirtualTxs_PrivateExposure(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	repo := &mockRepoManager{
		rounds: &mockRoundRepo{txs: map[string]string{
			testTxids[0]: "fakeTxData",
		}},
	}
	indexer := newTestIndexerWithExposure(privkey, "private", repo)

	t.Run("no token returns error", func(t *testing.T) {
		_, err := indexer.GetVirtualTxs(context.Background(), "", testTxids, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "auth token is required")
	})

	t.Run("invalid token returns error", func(t *testing.T) {
		_, err := indexer.GetVirtualTxs(context.Background(), "badtoken", testTxids, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth token")
	})
}

// TestGetVirtualTxs_WithheldExposure verifies that in withheld mode, GetVirtualTxs
// does not reject requests with missing or invalid auth tokens. Instead, it proceeds
// but strips arkd signatures from the returned PSBTs (tested here with empty results
// so stripping is a no-op). This ensures withheld mode degrades gracefully rather
// than blocking access entirely.
func TestGetVirtualTxs_WithheldExposure(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	repo := &mockRepoManager{
		rounds: &mockRoundRepo{txs: map[string]string{}},
	}
	indexer := newTestIndexerWithExposure(privkey, "withheld", repo)

	t.Run("no token does not error", func(t *testing.T) {
		resp, err := indexer.GetVirtualTxs(context.Background(), "", nil, nil)
		require.NoError(t, err)
		require.Empty(t, resp.Txs)
	})

	t.Run("invalid token does not error", func(t *testing.T) {
		resp, err := indexer.GetVirtualTxs(context.Background(), "badtoken", nil, nil)
		require.NoError(t, err)
		require.Empty(t, resp.Txs)
	})
}
