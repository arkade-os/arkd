package asset_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/stretchr/testify/require"
)

// baselineGroupHex is a canonical issuance group: presence 0x00, no inputs, one
// output (type=local, vout=0, amount=1). Bytes: 00 | 00 | 01 | 01 0000 01.
const baselineGroupHex = "00000101000001"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestAssetGroupBaselineIsCanonical(t *testing.T) {
	ag, err := asset.NewAssetGroupFromBytes(mustHex(t, baselineGroupHex))
	require.NoError(t, err)
	got, err := ag.Serialize()
	require.NoError(t, err)
	require.Equal(t, baselineGroupHex, hex.EncodeToString(got))
}

func TestAssetGroupRejectsUndefinedPresenceBits(t *testing.T) {
	// Presence 0x08: a bit outside the defined mask (0x07), otherwise an
	// issuance with the same body as the baseline.
	_, err := asset.NewAssetGroupFromBytes(mustHex(t, "08000101000001"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-canonical")
}

func TestAssetGroupRejectsMetadataFlagWithEmptyList(t *testing.T) {
	// Presence 0x04 (metadata) but metadata count is 0x00 (empty list).
	// Bytes: 04 | 00(md count) | 00(inputs) | 01 01 0000 01 (one output).
	_, err := asset.NewAssetGroupFromBytes(mustHex(t, "0400000101000001"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-canonical")
}
