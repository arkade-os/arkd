package grpcservice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestRouterServesOnlyGRPCAndHealthz(t *testing.T) {
	h := router(grpc.NewServer())

	t.Run("healthz for the container healthcheck", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("no rest gateway", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign-transaction", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.NotEqual(t, http.StatusOK, rec.Code)
	})
}
