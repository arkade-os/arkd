package domain

type AssetAnchor struct {
	AnchorPoint Outpoint
	AssetID     string
	Vtxos       []AnchorVtxo
}

type AssetMetadata struct {
	Key   string
	Value string
}

type AnchorVtxo struct {
	Vout   uint32
	Amount uint64
}

type Asset struct {
	ID        string
	Quantity  uint64
	Immutable bool
	Metadata  []AssetMetadata
}

type TeleportAsset struct {
	Hash      string
	AssetID   string
	Amount    uint64
	IsClaimed bool
}
