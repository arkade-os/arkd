package handlers_test

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-signer/interface/grpc/handlers"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

			// Watch must report the status before it blocks, otherwise a
			// watching client learns nothing before the stream closes.
			ctx, cancel := context.WithCancel(context.Background())
			stream := &fakeWatchServer{ctx: ctx}
			done := make(chan error, 1)
			go func() { done <- h.Watch(&grpchealth.HealthCheckRequest{}, stream) }()

			require.Eventually(t, func() bool {
				return len(stream.sent()) > 0
			}, 2*time.Second, 10*time.Millisecond)
			require.Equal(t, tc.want, stream.sent()[0].GetStatus())

			cancel()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(2 * time.Second):
				t.Fatal("Watch did not return after the stream context was cancelled")
			}
		})
	}
}

// fakeWatchServer captures what Watch streams, standing in for the generated
// grpchealth.Health_WatchServer.
type fakeWatchServer struct {
	grpc.ServerStream
	ctx context.Context

	mu   sync.Mutex
	msgs []*grpchealth.HealthCheckResponse
}

func (f *fakeWatchServer) Context() context.Context { return f.ctx }

func (f *fakeWatchServer) Send(m *grpchealth.HealthCheckResponse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return nil
}

func (f *fakeWatchServer) sent() []*grpchealth.HealthCheckResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*grpchealth.HealthCheckResponse(nil), f.msgs...)
}
