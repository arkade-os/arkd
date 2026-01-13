package txbuilder

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestGetAssetFromIntentsWithMultipleAssetGroups(t *testing.T) {
	asset1, opret1 := newTestAssetGroup(
		t,
		"0101010101010101010101010101010101010101010101010101010101010101",
	)
	asset2, opret2 := newTestAssetGroup(
		t,
		"0202020202020202020202020202020202020202020202020202020202020202",
	)

	intent := domain.Intent{
		AssetPacketList: [][]byte{opret1, opret2},
	}

	foundAsset, err := getAssetFromIntents([]domain.Intent{intent}, asset2.AssetId)
	require.NoError(t, err)
	require.Equal(t, asset2.AssetId, foundAsset.AssetId)
	foundAsset, err = getAssetFromIntents([]domain.Intent{intent}, asset1.AssetId)
	require.NoError(t, err)
	require.Equal(t, asset1.AssetId, foundAsset.AssetId)
}

func newTestAssetGroup(t *testing.T, idHex string) (asset.AssetGroup, []byte) {
	t.Helper()

	idBytes, err := hex.DecodeString(idHex)
	require.NoError(t, err)
	require.Len(t, idBytes, 32)

	var id [32]byte
	copy(id[:], idBytes)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	testAsset := asset.AssetGroup{
		AssetId: &asset.AssetId{
			TxHash: id,
			Index:  0,
		},
		Outputs: []asset.AssetOutput{{
			Type:   asset.AssetTypeLocal,
			Vout:   0,
			Amount: 100,
		}},
	}

	group := asset.AssetPacket{
		Assets:     []asset.AssetGroup{testAsset},
		SubDustKey: privKey.PubKey(),
		Version:    asset.AssetVersion,
	}

	opret, err := group.EncodeAssetPacket(0)
	require.NoError(t, err)

	return testAsset, opret.PkScript
}
