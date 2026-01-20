package extension

type AssetRefType uint8

const (
	AssetRefByID    AssetRefType = 0x01
	AssetRefByGroup AssetRefType = 0x02
)

type AssetRef struct {
	Type       AssetRefType
	AssetId    AssetId
	GroupIndex uint16
}

func AssetRefFromId(assetId AssetId) *AssetRef {
	return &AssetRef{
		Type:    AssetRefByID,
		AssetId: assetId,
	}
}

func AssetRefFromGroupIndex(groupIndex uint16) *AssetRef {
	return &AssetRef{
		Type:       AssetRefByGroup,
		GroupIndex: groupIndex,
	}
}