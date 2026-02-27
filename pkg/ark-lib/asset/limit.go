package asset

import "math"

var (
	// packet overhead: OP_RETURN(1) + push_data(1) + magic_bytes + marker(1) + varuint_count(1)
	packetOverheadWU uint64 = (1 + 1 + uint64(len(ArkadeMagic)) + 1 + 1) * 4
	
	// ref group weight 
	refAssetId, _ = NewAssetId(
		"0100000000000000000000000000000000000000000000000000000000000000", 0,
	)
	// we assume that to spend an asset, we need to transfer it to a least 1 output.
	// the minimum group size is 1 input + 1 output + asset Id (not an issuance)
	refGroup = AssetGroup{
		AssetId: refAssetId,
		Inputs:  []AssetInput{{Type: AssetInputTypeLocal, Vin: 0, Amount: 1}},
		Outputs: []AssetOutput{{Type: AssetOutputTypeLocal, Vout: 0, Amount: 1}},
	}
	groupBytes, _ = refGroup.Serialize()
	// group is in OP_RETURN, so weight = bytes * 4
	refGroupWeight = uint64(len(groupBytes)) * 4 // 180 WU
)

const (
	// spendingWeightThreshold is the fraction of maxTxWeight reserved for the asset packet.
	// It is used in MaxAssetsPerVtxo to compute the maximum number of assets allowed in a single VTXO.
	spendingWeightThreshold = 0.5
)


// MaxAssetsPerVtxo computes the maximum number of asset groups (unique assets)
// that a VTXO can hold while remaining spendable within maxTxWeight.
// It serializes a worst-case reference asset group to measure per-group overhead.
func MaxAssetsPerVtxo(maxTxWeight uint64) int {
	if maxTxWeight == 0 {
		return 0
	}

	maxPacketWU := uint64(float64(maxTxWeight) * spendingWeightThreshold)
	if maxPacketWU <= packetOverheadWU {
		return 0
	}

	return int(math.Ceil(float64(maxPacketWU - packetOverheadWU) / float64(refGroupWeight)))
}
