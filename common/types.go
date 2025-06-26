package common

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

type VtxoInput struct {
	Outpoint *wire.OutPoint
	Amount   int64
	// Tapscript is the path used to spend the vtxo
	Tapscript *waddrmgr.Tapscript
	// CheckpointTapscript is the path used to craft checkpoint output script
	// it is combined with the server's unroll script to creaft a new "checkpoint" output script
	// it can be nil, defaulting to Tapscript if not set
	CheckpointTapscript *waddrmgr.Tapscript
	RevealedTapscripts  []string
}
