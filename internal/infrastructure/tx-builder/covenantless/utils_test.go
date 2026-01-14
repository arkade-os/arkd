package txbuilder

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

func TestBuildTeleportAssetLeaf(t *testing.T) {
	idBytes, err := hex.DecodeString(
		"0101010101010101010101010101010101010101010101010101010101010101",
	)
	require.NoError(t, err)

	var id [32]byte
	copy(id[:], idBytes)
	assetID := asset.AssetId{TxHash: id, Index: 0}

	hashBytes := bytes.Repeat([]byte{0x02}, 32)

	receiver := domain.Receiver{
		Amount:            500,
		AssetId:           assetID.ToString(),
		AssetTeleportHash: hex.EncodeToString(hashBytes),
	}

	leaf, err := buildTeleportAssetLeaf(receiver, nil, []string{"cosigner"})
	require.NoError(t, err)
	require.NotEmpty(t, leaf.AssetScript)
	require.Equal(t, receiver.Amount, leaf.Amount)

	packet, err := asset.DecodeAssetPacket([]byte(leaf.AssetScript))
	require.NoError(t, err)
	require.Len(t, packet.Assets, 1)
	require.NotNil(t, packet.Assets[0].AssetId)
	require.Equal(t, assetID, *packet.Assets[0].AssetId)

	outputs := packet.Assets[0].Outputs
	require.Len(t, outputs, 1)
	require.Equal(t, asset.AssetTypeTeleport, outputs[0].Type)
	require.Equal(t, receiver.Amount, outputs[0].Amount)

	var expectedCommitment [32]byte
	copy(expectedCommitment[:], hashBytes)
	require.Equal(t, expectedCommitment, outputs[0].Commitment)
}
