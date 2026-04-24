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

	t.Run("valid", func(t *testing.T) {
		t.Run("valid token", func(t *testing.T) {
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

		t.Run("expired token", func(t *testing.T) {
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
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("invalid base64", func(t *testing.T) {
			_, err := svc.extractTokenHash("not-valid-base64!!!")
			require.Error(t, err)
			require.Contains(t, err.Error(), "base64")
		})

		t.Run("wrong length", func(t *testing.T) {
			short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
			_, err := svc.extractTokenHash(short)
			require.Error(t, err)
			require.Contains(t, err.Error(), "length")
		})

		t.Run("authPrvkey is nil", func(t *testing.T) {
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

	t.Run("valid", func(t *testing.T) {
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
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("propagates token error", func(t *testing.T) {
			_, err := svc.resolveTokenFilter("bad-token!!!", "")
			require.Error(t, err)
		})
	})
}

func TestNormalizeOutpoint(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("empty string returns empty", func(t *testing.T) {
			out, err := normalizeOutpoint("")
			require.NoError(t, err)
			require.Empty(t, out)
		})

		t.Run("valid outpoint is normalized", func(t *testing.T) {
			txid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			out, err := normalizeOutpoint(txid + ":0")
			require.NoError(t, err)
			require.Equal(t, txid+":0", out)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("missing vout", func(t *testing.T) {
			_, err := normalizeOutpoint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid outpoint")
		})

		t.Run("non-numeric vout", func(t *testing.T) {
			_, err := normalizeOutpoint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:xyz")
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid")
		})

		t.Run("short txid", func(t *testing.T) {
			_, err := normalizeOutpoint("aabb:0")
			require.Error(t, err)
			require.Contains(t, err.Error(), "txid length")
		})

		t.Run("non-hex txid", func(t *testing.T) {
			_, err := normalizeOutpoint("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz:0")
			require.Error(t, err)
			require.Contains(t, err.Error(), "txid hex")
		})

		t.Run("empty txid", func(t *testing.T) {
			_, err := normalizeOutpoint(":0")
			require.Error(t, err)
			require.Contains(t, err.Error(), "txid length")
		})
	})
}
