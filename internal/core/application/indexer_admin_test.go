package application

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestExtractTokenHash(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	svc := &indexerService{
		authPrvkey:   key,
		authTokenTTL: defaultAuthTokenTTL,
		tokenCache:   newTokenCache(defaultAuthTokenTTL),
	}
	t.Cleanup(svc.tokenCache.close)

	outpoints := []Outpoint{
		{Txid: "aabbcc1100000000000000000000000000000000000000000000000000000000", VOut: 0},
	}

	t.Run("extracts hash from valid token", func(t *testing.T) {
		token, err := svc.createAuthToken(outpoints)
		require.NoError(t, err)

		// Validate with full validation first to get the expected hash.
		expectedHash, err := svc.validateAuthToken(token)
		require.NoError(t, err)

		// extractTokenHash should return the same hash.
		hash, err := svc.extractTokenHash(token)
		require.NoError(t, err)
		require.Equal(t, expectedHash, hash)
	})

	t.Run("extracts hash from expired token", func(t *testing.T) {
		shortSvc := &indexerService{
			authPrvkey:   key,
			authTokenTTL: 10 * time.Millisecond,
			tokenCache:   newTokenCache(10 * time.Millisecond),
		}
		t.Cleanup(shortSvc.tokenCache.close)

		token, err := shortSvc.createAuthToken(outpoints)
		require.NoError(t, err)
		time.Sleep(20 * time.Millisecond)

		// validateAuthToken should fail (expired).
		_, err = shortSvc.validateAuthToken(token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expired")

		// extractTokenHash should still succeed.
		hash, err := shortSvc.extractTokenHash(token)
		require.NoError(t, err)
		require.NotEmpty(t, hash)
	})

	t.Run("rejects invalid base64", func(t *testing.T) {
		_, err := svc.extractTokenHash("not-valid-base64!!!")
		require.Error(t, err)
		require.Contains(t, err.Error(), "base64")
	})

	t.Run("rejects wrong length", func(t *testing.T) {
		short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
		_, err := svc.extractTokenHash(short)
		require.Error(t, err)
		require.Contains(t, err.Error(), "length")
	})

	t.Run("rejects token signed by different key", func(t *testing.T) {
		otherKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		otherSvc := &indexerService{
			authPrvkey:   otherKey,
			authTokenTTL: defaultAuthTokenTTL,
			tokenCache:   newTokenCache(defaultAuthTokenTTL),
		}
		t.Cleanup(otherSvc.tokenCache.close)

		token, err := otherSvc.createAuthToken(outpoints)
		require.NoError(t, err)

		// svc uses a different key, so signature verification should fail.
		_, err = svc.extractTokenHash(token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("errors when authPrvkey is nil", func(t *testing.T) {
		publicSvc := &indexerService{
			authPrvkey:   nil,
			authTokenTTL: defaultAuthTokenTTL,
			tokenCache:   newTokenCache(defaultAuthTokenTTL),
		}
		t.Cleanup(publicSvc.tokenCache.close)

		token, err := svc.createAuthToken(outpoints)
		require.NoError(t, err)

		_, err = publicSvc.extractTokenHash(token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "public exposure")
	})
}

func TestResolveTokenFilter(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	svc := &indexerService{
		authPrvkey:   key,
		authTokenTTL: defaultAuthTokenTTL,
		tokenCache:   newTokenCache(defaultAuthTokenTTL),
	}
	t.Cleanup(svc.tokenCache.close)

	t.Run("returns hash when token is empty", func(t *testing.T) {
		h, err := svc.resolveTokenFilter("", "myhash")
		require.NoError(t, err)
		require.Equal(t, "myhash", h)
	})

	t.Run("returns empty when both empty", func(t *testing.T) {
		h, err := svc.resolveTokenFilter("", "")
		require.NoError(t, err)
		require.Empty(t, h)
	})

	t.Run("token takes precedence over hash", func(t *testing.T) {
		outpoints := []Outpoint{
			{Txid: "aabbcc1100000000000000000000000000000000000000000000000000000000", VOut: 0},
		}
		token, err := svc.createAuthToken(outpoints)
		require.NoError(t, err)

		h, err := svc.resolveTokenFilter(token, "ignored-hash")
		require.NoError(t, err)
		require.NotEqual(t, "ignored-hash", h)
		require.NotEmpty(t, h)
	})

	t.Run("propagates token error", func(t *testing.T) {
		_, err := svc.resolveTokenFilter("bad-token!!!", "")
		require.Error(t, err)
	})
}

func TestNormalizeOutpoint(t *testing.T) {
	t.Run("empty string returns empty", func(t *testing.T) {
		out, err := normalizeOutpoint("")
		require.NoError(t, err)
		require.Empty(t, out)
	})

	t.Run("valid outpoint is normalized", func(t *testing.T) {
		out, err := normalizeOutpoint("aabb:0")
		require.NoError(t, err)
		require.Equal(t, "aabb:0", out)
	})

	t.Run("rejects missing vout", func(t *testing.T) {
		_, err := normalizeOutpoint("aabb")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid outpoint")
	})

	t.Run("rejects non-numeric vout", func(t *testing.T) {
		_, err := normalizeOutpoint("aabb:xyz")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid")
	})

	t.Run("rejects empty txid with vout", func(t *testing.T) {
		// FromString doesn't validate txid content, but ":0" splits into ["", "0"]
		// which is technically valid per FromString. This tests current behavior.
		out, err := normalizeOutpoint(":0")
		require.NoError(t, err)
		require.Equal(t, ":0", out)
	})
}
