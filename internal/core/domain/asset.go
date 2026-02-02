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
	ID             string
	Quantity       uint64
	Immutable      bool
	ControlAssetID string
	Metadata       []AssetMetadata
}

type TeleportAsset struct {
	Script      string
	IntentID    string
	AssetID     string
	OutputIndex uint32
	Amount      uint64
	IsClaimed   bool
}
