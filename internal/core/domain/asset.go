package domain

type AssetAnchor struct {
	Outpoint
	Assets []NormalAsset
}

type AssetMetadata struct {
	Key   string
	Value string
}

type NormalAsset struct {
	Outpoint
	Amount  uint64
	AssetID string
}

type AssetGroup struct {
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
