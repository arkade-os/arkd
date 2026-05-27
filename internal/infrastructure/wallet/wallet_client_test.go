package walletclient

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeWalletServer counts Withdraw calls and always fails with a retryable error.
type fakeWalletServer struct {
	arkwalletv1.UnimplementedWalletServiceServer
	withdrawCalls atomic.Int32
}

func (s *fakeWalletServer) Withdraw(
	_ context.Context, _ *arkwalletv1.WithdrawRequest,
) (*arkwalletv1.WithdrawResponse, error) {
	s.withdrawCalls.Add(1)
	return nil, status.Error(codes.Unavailable, "wallet unavailable")
}

// TestWithdrawDoesNotRetry checks Withdraw runs at most once, so funds can't be sent twice.
func TestWithdrawDoesNotRetry(t *testing.T) {
	srv := &fakeWalletServer{}
	conn := newTestWalletConn(t, srv)
	w := &walletDaemonClient{client: arkwalletv1.NewWalletServiceClient(conn), conn: conn}

	_, err := w.Withdraw(context.Background(), "bcrt1qaddr", 1000, false)
	require.Error(t, err)
	require.Equal(t, int32(1), srv.withdrawCalls.Load(),
		"Withdraw must be attempted exactly once (double-spend risk)")

	// Control: without the WithMax(0) opt-out the same call IS retried, proving the interceptor is on.
	srv.withdrawCalls.Store(0)
	_, err = arkwalletv1.NewWalletServiceClient(conn).Withdraw(
		context.Background(),
		&arkwalletv1.WithdrawRequest{Address: "bcrt1qaddr", Amount: 1000},
	)
	require.Error(t, err)
	require.Equal(t, int32(5), srv.withdrawCalls.Load(),
		"control: a normal call should be retried 5 times by the interceptor")
}

// newTestWalletConn returns an in-memory client conn using the same retry interceptor as New.
func newTestWalletConn(t *testing.T, srv arkwalletv1.WalletServiceServer) *grpc.ClientConn {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	arkwalletv1.RegisterWalletServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithUnaryInterceptor(
			grpc_retry.UnaryClientInterceptor(retryCallOptions()...),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
