package wallet

import (
	"encoding/hex"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/coinset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	// maxSelectionInputs caps the number of inputs a single selection may use.
	maxSelectionInputs = 50
	// defaultMinChangeAmount is the min change a selection must leave to be
	// accepted (roughly the P2TR/P2WSH dust limit). It avoids producing dust
	// change outputs for general-purpose selections.
	defaultMinChangeAmount = 330
)

// newCoinSelector builds a coin selector that prefers the fewest inputs.
// minChangeAmount controls the minimum change a selection must leave behind:
// any selection whose total is in (target, target+minChangeAmount) is rejected.
// Pass 0 to accept any total >= target (useful when sub-dust change is folded
// into the fee instead of becoming an output).
func newCoinSelector(minChangeAmount btcutil.Amount) coinset.MinNumberCoinSelector {
	return coinset.MinNumberCoinSelector{
		MaxInputs:       maxSelectionInputs,
		MinChangeAmount: minChangeAmount,
	}
}

// coin implements coinset.Coin interface
type coin struct {
	utxo ports.Utxo
}

func (u coin) Value() btcutil.Amount {
	return btcutil.Amount(u.utxo.Value)
}

func (u coin) ValueAge() int64 {
	return int64(u.utxo.Confirmations)
}

func (u coin) PkScript() []byte {
	script, err := hex.DecodeString(u.utxo.Script)
	if err != nil {
		return nil
	}
	return script
}

func (u coin) Hash() *chainhash.Hash {
	return &u.utxo.OutPoint.Hash
}

func (u coin) Index() uint32 {
	return u.utxo.OutPoint.Index
}

func (u coin) NumConfs() int64 {
	return int64(u.utxo.Confirmations)
}
