package handlers

import (
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRevokeTokensRequiresFilter(t *testing.T) {
	handler := &adminHandler{}

	_, err := handler.RevokeTokens(t.Context(), &arkv1.RevokeTokensRequest{})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "at least one filter")
}
