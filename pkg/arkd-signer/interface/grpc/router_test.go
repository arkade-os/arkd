package grpcservice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The signer holds the operator key and has no auth of its own, so it must not
// advertise itself to browsers. Without CORS headers a page cannot read a
// response, and a gateway JSON post is not CORS-simple so it never gets past
// preflight in the first place.
func TestRouterSendsNoCORSHeaders(t *testing.T) {
	gateway := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	h := router(nil, gateway)

	corsHeaders := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Headers",
		"Access-Control-Allow-Methods",
	}

	t.Run("preflight is refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/sign", nil)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		for _, k := range corsHeaders {
			require.Emptyf(t, rec.Header().Get(k), "preflight must not send %s", k)
		}
	})

	t.Run("gateway responses carry no CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		for _, k := range corsHeaders {
			require.Emptyf(t, rec.Header().Get(k), "response must not send %s", k)
		}
	})

	t.Run("healthz still reachable for the container healthcheck", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
	})
}
