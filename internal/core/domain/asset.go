package domain

import "github.com/arkade-os/arkd/pkg/ark-lib/asset"

type Asset struct {
	Id             string
	Immutable      bool
	ControlAssetId string
	Metadata       []asset.Metadata
}
