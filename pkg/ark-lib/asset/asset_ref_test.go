package asset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type jsonAssetIdRefFixture struct {
	Name  string `json:"name"`
	Txid  string `json:"txid"`
	Index uint16 `json:"index"`
}

type jsonGroupIndexFixture struct {
	Name  string `json:"name"`
	Index uint16 `json:"index"`
}

type assetRefFixturesJSON struct {
	AssetIds     []jsonAssetIdRefFixture `json:"asset_ids"`
	GroupIndices []jsonGroupIndexFixture `json:"group_indices"`
}

var assetRefFixtures assetRefFixturesJSON

func init() {
	file, err := os.ReadFile("testdata/asset_ref_fixtures.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(file, &assetRefFixtures); err != nil {
		panic(err)
	}
}

func getAssetIdRefFixture(name string) *jsonAssetIdRefFixture {
	for _, f := range assetRefFixtures.AssetIds {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func getGroupIndexFixture(name string) *jsonGroupIndexFixture {
	for _, f := range assetRefFixtures.GroupIndices {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func fixtureToAssetIdRef(f *jsonAssetIdRefFixture) (AssetId, error) {
	b, err := hex.DecodeString(f.Txid)
	if err != nil {
		return AssetId{}, err
	}
	var arr [32]byte
	copy(arr[:], b)
	return AssetId{Txid: arr, Index: f.Index}, nil
}

func TestAssetRefFromIdAndGroupIndex(t *testing.T) {
	t.Parallel()

	// deterministic AssetId from fixture
	idFixture := getAssetIdRefFixture("sequential_bytes")
	require.NotNil(t, idFixture)
	id, err := fixtureToAssetIdRef(idFixture)
	require.NoError(t, err)

	ref := AssetRefFromId(id)
	require.NotNil(t, ref)
	require.Equal(t, AssetRefByID, ref.Type)
	require.Equal(t, id.Index, ref.AssetId.Index)
	require.True(t, bytes.Equal(id.Txid[:], ref.AssetId.Txid[:]))

	groupFixture := getGroupIndexFixture("default")
	require.NotNil(t, groupFixture)
	gref := AssetRefFromGroupIndex(groupFixture.Index)
	require.NotNil(t, gref)
	require.Equal(t, AssetRefByGroup, gref.Type)
	require.Equal(t, groupFixture.Index, gref.GroupIndex)
}

func TestAssetRef_ConstructorsIndependence(t *testing.T) {
	t.Parallel()

	// ensure that modifying returned refs does not mutate originals
	idFixture := getAssetIdRefFixture("simple")
	require.NotNil(t, idFixture)
	id, err := fixtureToAssetIdRef(idFixture)
	require.NoError(t, err)

	ref := AssetRefFromId(id)
	ref.AssetId.Index = 99
	// original id unchanged
	require.Equal(t, idFixture.Index, id.Index)

	groupFixture := getGroupIndexFixture("independence_test")
	require.NotNil(t, groupFixture)
	g := AssetRefFromGroupIndex(groupFixture.Index)
	g.GroupIndex = 123
	// ensure original group index unchanged
	g2 := AssetRefFromGroupIndex(groupFixture.Index)
	require.Equal(t, groupFixture.Index, g2.GroupIndex)
}
