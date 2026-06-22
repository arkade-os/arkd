package grpcclient

import (
	stderrors "errors"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsDigestMismatch(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "plain non-status error",
			err:  stderrors.New(errors.DIGEST_MISMATCH.Name),
			want: false,
		},
		{
			name: "status with DIGEST_MISMATCH details",
			err:  statusWithDetails(t, codes.FailedPrecondition, errors.DIGEST_MISMATCH.Name),
			want: true,
		},
		{
			name: "status with different error details",
			err: statusWithDetails(
				t, codes.FailedPrecondition, errors.BUILD_VERSION_TOO_OLD.Name,
			),
			want: false,
		},
		{
			name: "status without details but name in message",
			err:  status.Error(codes.FailedPrecondition, errors.DIGEST_MISMATCH.Name),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isDigestMismatch(tt.err))
		})
	}
}

// statusWithDetails builds a gRPC status error carrying an arkv1.ErrorDetails,
// mirroring what the server's errorConverter attaches to guard errors.
func statusWithDetails(t *testing.T, code codes.Code, name string) error {
	t.Helper()
	st, err := status.New(code, name).WithDetails(&arkv1.ErrorDetails{
		Name: name,
	})
	require.NoError(t, err)
	return st.Err()
}
