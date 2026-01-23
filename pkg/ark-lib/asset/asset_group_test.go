package asset

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssetGroup_Encode_ErrorUnknownInputType(t *testing.T) {
	t.Parallel()
	ag := &AssetGroup{
		Inputs: []AssetInput{{Type: AssetType(99)}},
	}
	_, err := ag.Encode()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown asset input type")
}

func TestAssetGroup_Decode_Truncated(t *testing.T) {
	t.Parallel()
	ag := &AssetGroup{
		Inputs:  []AssetInput{{Type: AssetTypeLocal, Vin: 5, Amount: 555}},
		Outputs: []AssetOutput{{Type: AssetTypeLocal, Vout: 6, Amount: 666}},
	}
	data, err := ag.Encode()
	require.NoError(t, err)
	if len(data) < 5 {
		t.Skip("encoded data too small to truncate")
	}
	// Truncate last 3 bytes to simulate incomplete data
	tr := data[:len(data)-3]
	var out AssetGroup
	err = out.Decode(bytes.NewReader(tr))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected EOF")
}

func TestAssetEncodeDecodeRoundTrip(t *testing.T) {
	ag := AssetGroup{
		AssetId: &AssetId{
			Txid:  deterministicBytesArray(0x3c),
			Index: 2,
		},
		Outputs: []AssetOutput{
			{
				Type:   AssetTypeLocal,
				Amount: 11,
				Vout:   0,
			},
			{
				Type:   AssetTypeTeleport,
				Script: deterministicTxhash(0xcc),
				Amount: 22,
			},
		},
		ControlAsset: AssetRefFromId(AssetId{
			Txid:  deterministicBytesArray(0x3c),
			Index: 1,
		}),
		Inputs: []AssetInput{
			{
				Type:   AssetTypeLocal,
				Vin:    7,
				Amount: 20,
			},
			{
				Type: AssetTypeTeleport,
				// Vin is not encoded for Teleport inputs
				Vin: 0,
				Witness: TeleportWitness{
					Script: []byte{0x00, 0x01, 0x02, 0x03},
					Txid:   deterministicBytesArray(0x55),
					Index:  123,
				},
				Amount: 40,
			},
		},
		Metadata: []Metadata{
			{Key: "purpose", Value: "roundtrip"},
			{Key: "owner", Value: "arkade"},
		},
		Immutable: true,
	}

	encoded, err := ag.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	var decoded AssetGroup

	require.NoError(t, decoded.Decode(bytes.NewReader(encoded)))
	require.Equal(t, ag, decoded)

	decoded.normalizeAssetSlices()
	ag.normalizeAssetSlices()
	require.Equal(t, ag.AssetId.Index, decoded.AssetId.Index)
	require.Equal(t, ag.Immutable, decoded.Immutable)
	require.Equal(t, ag.ControlAsset.Type, decoded.ControlAsset.Type)
	require.Equal(t, ag.Metadata, decoded.Metadata)
	require.Equal(t, ag.Inputs[0].Vin, decoded.Inputs[0].Vin)
	require.Equal(t, ag.Outputs[0].Vout, decoded.Outputs[0].Vout)

	var nilAssetGroup *AssetGroup
	_, err = nilAssetGroup.Encode()
	require.Error(t, err)
	require.Equal(t, "cannot encode nil AssetGroup", fmt.Sprint(err))
}
