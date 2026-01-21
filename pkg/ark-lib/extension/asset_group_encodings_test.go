package extension

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeAssetGroups(t *testing.T) {
	t.Parallel()

	assetGroups := []AssetGroup{controlAsset, normalAsset}
	data, err := encodeAssetGroups(assetGroups)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	assetGroups = []AssetGroup{}
	data, err = encodeAssetGroups(assetGroups)
	require.Error(t, err)
	require.Equal(t, "cannot encode empty asset group", err.Error())
	require.Nil(t, data)
}
