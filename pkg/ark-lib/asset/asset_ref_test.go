package asset

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssetRefFromIdAndGroupIndex(t *testing.T) {
	t.Parallel()

	// deterministic AssetId
	var tx [32]byte
	for i := 0; i < len(tx); i++ {
		tx[i] = byte(i + 1)
	}
	id := AssetId{Txid: tx, Index: 42}

	ref := AssetRefFromId(id)
	require.NotNil(t, ref)
	require.Equal(t, AssetRefByID, ref.Type)
	require.Equal(t, id.Index, ref.AssetId.Index)
	require.True(t, bytes.Equal(id.Txid[:], ref.AssetId.Txid[:]))

	gref := AssetRefFromGroupIndex(7)
	require.NotNil(t, gref)
	require.Equal(t, AssetRefByGroup, gref.Type)
	require.Equal(t, uint16(7), gref.GroupIndex)

}

func TestAssetRef_ConstructorsIndependence(t *testing.T) {
	t.Parallel()
	// ensure that modifying returned refs does not mutate originals
	id := AssetId{Txid: [32]byte{1, 2, 3}, Index: 9}
	ref := AssetRefFromId(id)
	ref.AssetId.Index = 99
	// original id unchanged
	require.Equal(t, uint16(9), id.Index)

	g := AssetRefFromGroupIndex(5)
	g.GroupIndex = 123
	// ensure original group index unchanged
	g2 := AssetRefFromGroupIndex(5)
	require.Equal(t, uint16(5), g2.GroupIndex)
}
