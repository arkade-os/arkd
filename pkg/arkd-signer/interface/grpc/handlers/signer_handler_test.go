package handlers_test

import (
	"context"
	"encoding/hex"
	"testing"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-signer/interface/grpc/handlers"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

func TestSignerHandlerStatusAndPubkey(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	h := handlers.NewSignerHandler(application.New(priv, nil))

	status, err := h.GetStatus(context.Background(), &signerv1.GetStatusRequest{})
	require.NoError(t, err)
	require.True(t, status.GetReady())

	pub, err := h.GetPubkey(context.Background(), &signerv1.GetPubkeyRequest{})
	require.NoError(t, err)
	require.Equal(t,
		hex.EncodeToString(priv.PubKey().SerializeCompressed()),
		pub.GetPubkey(),
	)
}

// The health endpoint is what an orchestrator gates readiness on, so a signer
// that came up without a usable key has to report NOT_SERVING rather than be
// indistinguishable from a working one until the first signing request.
func TestHealthHandlerReflectsSignerReadiness(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		signer application.Signer
		want   grpchealth.HealthCheckResponse_ServingStatus
	}{
		{
			name:   "ready signer serves",
			signer: application.New(priv, nil),
			want:   grpchealth.HealthCheckResponse_SERVING,
		},
		{
			name:   "signer without a key does not serve",
			signer: application.New(nil, nil),
			want:   grpchealth.HealthCheckResponse_NOT_SERVING,
		},
		{
			name:   "missing signer does not serve",
			signer: nil,
			want:   grpchealth.HealthCheckResponse_NOT_SERVING,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := handlers.NewHealthHandler(tc.signer)

			check, err := h.Check(
				context.Background(), &grpchealth.HealthCheckRequest{},
			)
			require.NoError(t, err)
			require.Equal(t, tc.want, check.GetStatus())

			list, err := h.List(context.Background(), &grpchealth.HealthListRequest{})
			require.NoError(t, err)
			require.Equal(t, tc.want, list.GetStatuses()["arkd-signer"].GetStatus())
		})
	}
}
