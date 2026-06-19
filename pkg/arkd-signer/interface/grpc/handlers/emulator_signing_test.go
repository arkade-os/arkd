package handlers_test

import (
	"context"
	"encoding/hex"
	"testing"

	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/arkade-os/emulator/pkg/emulator/grpchandler"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestEmulatorGetInfoReturnsOperatorPubkey verifies that emulator.New wired
// with nil finalizer (signing-only) returns the operator pubkey via GetInfo,
// and that grpchandler.New correctly wraps it.
func TestEmulatorGetInfoReturnsOperatorPubkey(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	svc, err := emulator.New(
		context.Background(),
		priv,
		nil, // no deprecated keys
		priv.PubKey(),
		nil, // nil finalizer: signing-only
		arkade.DefaultComputeLimits(),
	)
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	// Check via the Service interface directly.
	info, err := svc.GetInfo(context.Background())
	require.NoError(t, err)
	require.NotNil(t, info)

	wantPubkey := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	require.Equal(t, wantPubkey, info.SignerPublicKey)
	require.Empty(t, info.DeprecatedSignerPublicKeys)

	// Also check through the gRPC handler.
	h := grpchandler.New("", svc)
	resp, err := h.GetInfo(context.Background(), &emulatorv1.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, wantPubkey, resp.GetSignerPubkey())
}
