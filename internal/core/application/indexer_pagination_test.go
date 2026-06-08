package application

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestChainCursorRoundTrip(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	indexer := newTestIndexer(t, privkey, exposurePublic, nil, nil, nil)

	key := sha256.Sum256([]byte("test-cursor-key"))
	indexer.cursorHMACKey = key[:]

	op := Outpoint{Txid: testTxids[0], VOut: 0}

	t.Run("round trip", func(t *testing.T) {
		token := indexer.encodeChainCursor(42, op)
		require.NotEmpty(t, token)

		offset, err := indexer.decodeChainCursor(token, op)
		require.NoError(t, err)
		require.Equal(t, 42, offset)
	})

	t.Run("rejects cursor issued for another outpoint", func(t *testing.T) {
		token := indexer.encodeChainCursor(7, op)
		other := Outpoint{Txid: differentTxid, VOut: 0}

		_, err := indexer.decodeChainCursor(token, other)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match outpoint")
	})

	t.Run("rejects tampered signature", func(t *testing.T) {
		token := indexer.encodeChainCursor(7, op)
		raw, err := base64.RawURLEncoding.DecodeString(token)
		require.NoError(t, err)
		raw[len(raw)-1] ^= 0xff // flip a signature byte

		_, err = indexer.decodeChainCursor(base64.RawURLEncoding.EncodeToString(raw), op)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature mismatch")
	})

	t.Run("rejects invalid base64", func(t *testing.T) {
		_, err := indexer.decodeChainCursor("not base64 !!!", op)
		require.Error(t, err)
	})

	t.Run("works without an hmac key", func(t *testing.T) {
		indexer.cursorHMACKey = nil
		token := indexer.encodeChainCursor(99, op)

		offset, err := indexer.decodeChainCursor(token, op)
		require.NoError(t, err)
		require.Equal(t, 99, offset)
	})
}

func TestPaginateByOffset(t *testing.T) {
	items := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	t.Run("first page has more", func(t *testing.T) {
		page, resp, more := paginateByOffset(items, 0, 3)
		require.Equal(t, []int{0, 1, 2}, page)
		require.True(t, more)
		require.Equal(t, int32(1), resp.Current)
		require.Equal(t, int32(4), resp.Total) // ceil(10/3)
	})

	t.Run("middle page has more", func(t *testing.T) {
		page, _, more := paginateByOffset(items, 3, 3)
		require.Equal(t, []int{3, 4, 5}, page)
		require.True(t, more)
	})

	t.Run("last partial page has no more", func(t *testing.T) {
		page, _, more := paginateByOffset(items, 9, 3)
		require.Equal(t, []int{9}, page)
		require.False(t, more)
	})

	t.Run("offset past end returns empty", func(t *testing.T) {
		page, _, more := paginateByOffset(items, 20, 3)
		require.Empty(t, page)
		require.False(t, more)
	})

	t.Run("zero page size returns everything", func(t *testing.T) {
		page, _, more := paginateByOffset(items, 0, 0)
		require.Equal(t, items, page)
		require.False(t, more)
	})

	t.Run("page size larger than len returns everything", func(t *testing.T) {
		page, _, more := paginateByOffset(items, 0, 100)
		require.Equal(t, items, page)
		require.False(t, more)
	})
}

// TestGetVtxoChainPagination builds a chain, fetches it whole, then pages
// through it one tx at a time via next_page_token and asserts the reassembled
// pages are identical to the full chain.
func TestGetVtxoChainPagination(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	_, vtxoTxid, flatTree := buildTestTreeTxs(t)
	commitmentTxid := differentTxid
	vtxoOutpoint := Outpoint{Txid: vtxoTxid, VOut: 0}
	vtxoData := domain.Vtxo{
		Outpoint:           vtxoOutpoint,
		Preconfirmed:       false,
		RootCommitmentTxid: commitmentTxid,
	}

	rounds := &mockedRoundRepo{}
	vtxos := &mockedVtxoRepo{}
	vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{vtxoOutpoint}).
		Return([]domain.Vtxo{vtxoData}, nil)
	rounds.On("GetRoundVtxoTree", mock.Anything, commitmentTxid).
		Return(flatTree, nil)

	indexer := newTestIndexer(t, privkey, exposurePublic, rounds, vtxos, nil)

	// Full chain: no page and no token returns everything with no next cursor.
	full, err := indexer.GetVtxoChain(t.Context(), "", vtxoOutpoint, nil, "")
	require.NoError(t, err)
	require.Empty(t, full.NextPageToken)
	require.GreaterOrEqual(t, len(full.Chain), 2, "need a multi-tx chain to exercise paging")

	// Page through one tx at a time and reassemble.
	const pageSize = 1
	var paged []ChainTx
	token := ""
	for iter := 0; iter <= len(full.Chain)+1; iter++ {
		resp, err := indexer.GetVtxoChain(
			t.Context(), "", vtxoOutpoint, &Page{PageSize: int32(pageSize)}, token,
		)
		require.NoError(t, err)
		require.LessOrEqual(t, len(resp.Chain), pageSize)
		paged = append(paged, resp.Chain...)
		token = resp.NextPageToken
		if token == "" {
			break
		}
	}
	require.Empty(t, token, "pagination did not terminate")
	require.Equal(t, full.Chain, paged)

	rounds.AssertExpectations(t)
	vtxos.AssertExpectations(t)
}

// TestGetVtxoChainInvalidPageTokenDoesNotExtendSession proves that a request
// that fails cursor decoding does not extend the auth session: touch happens
// only after a fully successful page fetch.
func TestGetVtxoChainInvalidPageTokenDoesNotExtendSession(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	_, vtxoTxid, flatTree := buildTestTreeTxs(t)
	commitmentTxid := differentTxid
	vtxoOutpoint := Outpoint{Txid: vtxoTxid, VOut: 0}
	vtxoData := domain.Vtxo{Outpoint: vtxoOutpoint, RootCommitmentTxid: commitmentTxid}

	rounds := &mockedRoundRepo{}
	vtxos := &mockedVtxoRepo{}
	vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{vtxoOutpoint}).
		Return([]domain.Vtxo{vtxoData}, nil)
	rounds.On("GetRoundVtxoTree", mock.Anything, commitmentTxid).
		Return(flatTree, nil)

	indexer := newTestIndexer(t, privkey, exposurePrivate, rounds, vtxos, nil)

	_, allOutpoints, err := indexer.buildVtxoChain(t.Context(), vtxoOutpoint)
	require.NoError(t, err)
	token, err := indexer.createAuthToken(allOutpoints)
	require.NoError(t, err)

	hash, err := hashOutpoints(allOutpoints)
	require.NoError(t, err)
	hashStr := hex.EncodeToString(hash)

	_, before, ok := indexer.tokenCache.getOutpoints(hashStr)
	require.True(t, ok)

	// A malformed page_token must fail without extending the session.
	_, err = indexer.GetVtxoChain(t.Context(), token, vtxoOutpoint, &Page{PageSize: 1}, "garbage!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid page_token")

	_, after, ok := indexer.tokenCache.getOutpoints(hashStr)
	require.True(t, ok)
	require.Equal(t, *before, *after, "a failed request must not extend the session")
}

// TestValidateChainAuthPagination covers the keepalive behaviour: the first page
// still enforces the signed-timestamp expiry, while a continuation is accepted
// on signature alone as long as the session is still active in the token cache.
func TestValidateChainAuthPagination(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	op := Outpoint{Txid: testTxids[0], VOut: 0}
	outpoints := []Outpoint{op}

	hash, err := hashOutpoints(outpoints)
	require.NoError(t, err)
	hashStr := hex.EncodeToString(hash)

	expired := buildExpiredToken(t, privkey, outpoints)

	t.Run("first page enforces expiry", func(t *testing.T) {
		indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
		indexer.tokenCache.add(hashStr, outpoints, time.Now())

		_, err := indexer.validateChainAuth(expired, op, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expired")
	})

	t.Run("continuation accepted while session active", func(t *testing.T) {
		indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
		indexer.tokenCache.add(hashStr, outpoints, time.Now())

		_, err := indexer.validateChainAuth(expired, op, true)
		require.NoError(t, err)
	})

	t.Run("continuation rejected when session inactive", func(t *testing.T) {
		indexer := newTestIndexer(t, privkey, exposurePrivate, nil, nil, nil)
		// no cache entry added: the session is not active

		_, err := indexer.validateChainAuth(expired, op, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expired")
	})
}
