package wallet

import (
	"encoding/hex"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/coinset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var coinSelector = coinset.MinNumberCoinSelector{
	MaxInputs:       20,
	MinChangeAmount: 1000,
}

// selectable implements coinset.Coin interface
type selectable struct {
	utxo ports.Utxo
}

func (u selectable) Value() btcutil.Amount {
	return btcutil.Amount(u.utxo.Value)
}

func (u selectable) ValueAge() int64 {
	return int64(u.utxo.Confirmations)
}

func (u selectable) PkScript() []byte {
	script, err := hex.DecodeString(u.utxo.Script)
	if err != nil {
		return nil
	}
	return script
}

func (u selectable) Hash() *chainhash.Hash {
	return &u.utxo.OutPoint.Hash
}

func (u selectable) Index() uint32 {
	return u.utxo.OutPoint.Index
}

func (u selectable) NumConfs() int64 {
	return int64(u.utxo.Confirmations)
}
