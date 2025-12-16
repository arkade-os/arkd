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
	asset1, opret1 := newTestAssetGroup(t, "0101010101010101010101010101010101010101010101010101010101010101")
	asset2, opret2 := newTestAssetGroup(t, "0202020202020202020202020202020202020202020202020202020202020202")

	intent := domain.Intent{
		AssetGroupList: [][]byte{opret1, opret2},
	}

	foundAsset, err := getAssetFromIntents([]domain.Intent{intent}, asset2.AssetId)
	require.NoError(t, err)
	require.Equal(t, asset2.AssetId, foundAsset.AssetId)
	foundAsset, err = getAssetFromIntents([]domain.Intent{intent}, asset1.AssetId)
	require.NoError(t, err)
	require.Equal(t, asset1.AssetId, foundAsset.AssetId)
}

func newTestAssetGroup(t *testing.T, idHex string) (asset.Asset, []byte) {
	t.Helper()

	idBytes, err := hex.DecodeString(idHex)
	require.NoError(t, err)
	require.Len(t, idBytes, 32)

	var id [32]byte
	copy(id[:], idBytes)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	testAsset := asset.Asset{
		AssetId: id,
		Outputs: []asset.AssetOutput{{
			PublicKey: *privKey.PubKey(),
			Vout:      0,
			Amount:    100,
		}},
	}

	group := asset.AssetGroup{
		NormalAssets: []asset.Asset{testAsset},
		SubDustKey:   privKey.PubKey(),
	}

	opret, err := group.EncodeOpret(0)
	require.NoError(t, err)

	return testAsset, opret.PkScript
}
