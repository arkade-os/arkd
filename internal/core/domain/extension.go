package domain

type Extension interface {
	isExtension()
	Type() ExtensionType
}

type ExtensionType uint16

const (
	ExtAsset ExtensionType = 1
)

type AssetExtension struct {
	AssetID string
	Amount  uint64
}

func (AssetExtension) isExtension()        {}
func (AssetExtension) Type() ExtensionType { return ExtAsset }
