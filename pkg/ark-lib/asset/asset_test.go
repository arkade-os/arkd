package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

var charset = "0123456789"
var maxUint16 = 65535

func RandTxHash() [TX_HASH_SIZE]byte {
	var txh [TX_HASH_SIZE]byte
	for i := 0; i < TX_HASH_SIZE; i++ {
		txh[i] = charset[rand.Intn(len(charset))]
	}
	return txh
}

func RandIndex() uint16 {
	return uint16(rand.Intn(maxUint16))
}

func TestAssetId_Roundtrip(t *testing.T) {
	assetId := AssetId{
		Txid:  RandTxHash(),
		Index: RandIndex(),
	}

	assetString := assetId.String()
	require.Equal(t, ASSET_ID_SIZE*2, len(assetString))

	derivedAssetId, err := NewAssetIdFromString(assetString)
	require.NoError(t, err)
	require.Equal(t, assetId.Index, derivedAssetId.Index)
	require.Equal(t, assetId.Txid, derivedAssetId.Txid)
}

func TestAssetIdFromString_InvalidLength(t *testing.T) {
	shortString := "0123"
	// hex encoding means string length is double the byte length
	shortLen := len(shortString) / 2
	assetId, err := NewAssetIdFromString(shortString)
	require.Error(t, err)
	require.Equal(t, fmt.Sprintf("invalid asset id length: %d", shortLen), err.Error())
	require.Nil(t, assetId)
}

func TestAssetIdStringConversion(t *testing.T) {
	txid := deterministicBytesArray(0x01)
	index := uint16(12345)
	assetId := AssetId{Txid: txid, Index: index}

	s := assetId.String()
	decoded, err := NewAssetIdFromString(s)
	require.NoError(t, err)
	require.Equal(t, &assetId, decoded)

	// Test invalid hex
	_, err = NewAssetIdFromString("invalid")
	require.Error(t, err)

	// Test invalid length
	_, err = NewAssetIdFromString(hex.EncodeToString(make([]byte, 35)))
	require.Error(t, err)
}

// helper function to deep equal compare []AssetGroup slices
func assetGroupsEqual(a, b []AssetGroup) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i].AssetId == nil) != (b[i].AssetId == nil) {
			return false
		}
		// check each field in the AssetId matches
		if a[i].AssetId != nil && b[i].AssetId != nil {
			if a[i].AssetId.Index != b[i].AssetId.Index {
				return false
			}
			if a[i].AssetId.Txid != b[i].AssetId.Txid {
				return false
			}
		}
		if a[i].Immutable != b[i].Immutable {
			return false
		}
		// check each field in the Outputs slice match
		if len(a[i].Outputs) != len(b[i].Outputs) {
			return false
		}
		for idx, o := range a[i].Outputs {
			if o.Type != b[i].Outputs[idx].Type ||
				o.Vout != b[i].Outputs[idx].Vout ||
				len(o.Script) != len(b[i].Outputs[idx].Script) ||
				bytes.Equal(o.Script, b[i].Outputs[idx].Script) == false ||
				o.Amount != b[i].Outputs[idx].Amount {
				return false
			}
		}
		// check each ControlAsset field matches
		if (a[i].ControlAsset == nil) != (b[i].ControlAsset == nil) {
			return false
		}
		if a[i].ControlAsset != nil && b[i].ControlAsset != nil {
			if a[i].ControlAsset.Type != b[i].ControlAsset.Type ||
				a[i].ControlAsset.GroupIndex != b[i].ControlAsset.GroupIndex ||
				a[i].ControlAsset.AssetId != b[i].ControlAsset.AssetId {
				return false
			}
		}
		// check each field in the Inputs slice match
		if len(a[i].Inputs) != len(b[i].Inputs) {
			return false
		}
		for idx, in := range a[i].Inputs {
			if in.Type != b[i].Inputs[idx].Type ||
				in.Vin != b[i].Inputs[idx].Vin ||
				// check Witness fields
				len(in.Witness.Script) != len(b[i].Inputs[idx].Witness.Script) ||
				bytes.Equal(in.Witness.Script, b[i].Inputs[idx].Witness.Script) == false ||
				len(in.Witness.Txid) != len(b[i].Inputs[idx].Witness.Txid) ||
				bytes.Equal(in.Witness.Txid[:], b[i].Inputs[idx].Witness.Txid[:]) == false ||
				in.Amount != b[i].Inputs[idx].Amount {
				return false
			}
		}
		// check each field in the Metadata slice match
		if len(a[i].Metadata) != len(b[i].Metadata) {
			return false
		}
		for idx, md := range a[i].Metadata {
			if md.Key != b[i].Metadata[idx].Key ||
				md.Value != b[i].Metadata[idx].Value {
				return false
			}
		}
	}
	return true
}
