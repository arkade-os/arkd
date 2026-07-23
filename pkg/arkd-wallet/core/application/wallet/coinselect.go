package wallet

import (
	"encoding/hex"
	"sort"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/coinset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	maxInputs = 500
	defaultMinChangeAmount = 330
	// match Bitcoin Core 100k cap.
	bnbMaxTries = 100_000
)

// newCoinSelector builds a coin selector that prefers:
// 1. changeless selection
// 2. consolidation
// 3. minimal inputs count
type coinSelector struct {
	minChangeAmount btcutil.Amount
}

func (s coinSelector) CoinSelect(
	targetValue btcutil.Amount, coins []coinset.Coin,
) (coinset.Coins, error) {
	// 1. changeless branch-and-bound: minimize fragmentation.
	if cs, ok := branchAndBound(targetValue, maxInputs, coins); ok {
		return cs, nil
	}
	// 2. consolidate: sweep smallest UTXOs first, up to consolidateMaxInputs.
	if cs, ok := consolidate(
		targetValue, s.minChangeAmount, maxInputs, coins,
	); ok {
		return cs, nil
	}
	// 3. fallback: fewest inputs, up to fallbackMaxInputs.
	return coinset.MinNumberCoinSelector{
		MaxInputs:       maxInputs,
		MinChangeAmount: s.minChangeAmount,
	}.CoinSelect(targetValue, coins)
}

// consolidate accumulates coins smallest-first until the target is covered with
// acceptable change (0 or >= minChange), using at most maxInputs.
func consolidate(
	target, minChange btcutil.Amount, maxInputs int, coins []coinset.Coin,
) (coinset.Coins, bool) {
	sorted := make([]coinset.Coin, len(coins))
	copy(sorted, coins)
	sort.Sort(bySmallestValue(sorted)) // smallest first

	cs := coinset.NewCoinSet(nil)
	var sum btcutil.Amount
	for _, c := range sorted {
		if cs.Num() >= maxInputs {
			break
		}
		cs.PushCoin(c)
		sum += c.Value()
		if change := sum - target; change == 0 || change >= minChange {
			return cs, true
		}
	}
	return nil, false
}

// branchAndBound searches for a subset of coins whose values sum exactly to
// target (a changeless selection).
func branchAndBound(
	target btcutil.Amount, maxInputs int, coins []coinset.Coin,
) (coinset.Coins, bool) {
	sorted := make([]coinset.Coin, len(coins))
	copy(sorted, coins)
	sort.Sort(sort.Reverse(bySmallestValue(sorted)))

	// suffix[i] = sum of values of sorted[i:], used to prune branches that
	// can't reach the target even by taking every remaining coin.
	suffix := make([]btcutil.Amount, len(sorted)+1)
	for i := len(sorted) - 1; i >= 0; i-- {
		suffix[i] = suffix[i+1] + sorted[i].Value()
	}

	var best []int
	tries := bnbMaxTries

	var dfs func(idx int, sum btcutil.Amount, picked []int) bool
	dfs = func(idx int, sum btcutil.Amount, picked []int) bool {
		if sum == target {
			best = append([]int(nil), picked...)
			return true
		}
		if tries <= 0 || sum > target || len(picked) >= maxInputs ||
			idx >= len(sorted) || sum+suffix[idx] < target {
			return false
		}
		tries--
		// include sorted[idx], then (on failure) omit it.
		return dfs(idx+1, sum+sorted[idx].Value(), append(picked, idx)) ||
			dfs(idx+1, sum, picked)
	}

	if !dfs(0, 0, nil) {
		return nil, false
	}

	cs := coinset.NewCoinSet(nil)
	for _, i := range best {
		cs.PushCoin(sorted[i])
	}
	return cs, true
}

type bySmallestValue []coinset.Coin

func (a bySmallestValue) Len() int           { return len(a) }
func (a bySmallestValue) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a bySmallestValue) Less(i, j int) bool { return a[i].Value() < a[j].Value() }

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

// effectiveValueCoin wraps a coin so the selector ranks and accumulates it by
// its effective value (real value minus the fee to spend it as an input), while
// still exposing the real outpoint/script/value for tx building. Selecting by
// effective value against a target of amount+baseFee guarantees the chosen
// UTXOs cover the amount plus the fee for their actual input count.
type effectiveValueCoin struct {
	coin
	effectiveValue btcutil.Amount
}

func (c effectiveValueCoin) Value() btcutil.Amount {
	return c.effectiveValue
}
