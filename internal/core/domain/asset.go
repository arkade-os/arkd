package domain

import (
	"math/big"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
)

type Asset struct {
	Id             string
	ControlAssetId string
	Metadata       []asset.Metadata
	Supply         big.Int
}
