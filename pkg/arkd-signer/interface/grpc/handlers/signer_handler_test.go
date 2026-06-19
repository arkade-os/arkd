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
