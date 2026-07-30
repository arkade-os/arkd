package wallet

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/coinset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestCoinSelect(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "coinselect_fixtures.json"))
	require.NoError(t, err)

	var fixtures coinSelectFixtures
	require.NoError(t, json.Unmarshal(data, &fixtures))
	require.NotEmpty(t, fixtures.Cases)

	coins := loadCoins(t, fixtures.Utxos)

	selectors := map[string]func(minChange btcutil.Amount) coinset.CoinSelector {
		"economical":       func(m btcutil.Amount) coinset.CoinSelector { return economicalCoinSelector{m} },
		"consolidateFirst": func(m btcutil.Amount) coinset.CoinSelector { return consolidateFirstCoinSelector{m} },
	}

	for name, newSelector := range selectors {
		t.Run(name, func(t *testing.T) {
			for _, f := range fixtures.Cases {
				t.Run(f.Name, func(t *testing.T) {
					target := btcutil.Amount(f.Amount)
					minChange := btcutil.Amount(f.MinChangeAmount)

					selected, err := newSelector(minChange).CoinSelect(target, coins)
					if f.ExpectError {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)

					picked := selected.Coins()
					var total btcutil.Amount
					for _, c := range picked {
						total += c.Value()
					}

					// covers the target
					require.GreaterOrEqual(t, total, target)

					// change is either exactly zero or at least minChange
					change := total - target
					if change != 0 {
						require.GreaterOrEqual(t, change, minChange)
					}

					// never exceeds the input cap
					require.LessOrEqual(t, len(picked), maxInputs)

					// no duplicate outpoints, all picks belong to the pool
					pool := make(map[wire.OutPoint]bool, len(coins))
					for _, c := range coins {
						pool[wire.OutPoint{Hash: *c.Hash(), Index: c.Index()}] = true
					}
					seen := make(map[wire.OutPoint]bool, len(picked))
					for _, c := range picked {
						op := wire.OutPoint{Hash: *c.Hash(), Index: c.Index()}
						require.True(t, pool[op], "picked utxo not in pool: %s", op)
						require.False(t, seen[op], "duplicate utxo picked: %s", op)
						seen[op] = true
					}
				})
			}
		})
	}
}

type coinSelectFixtures struct {
	Utxos []uint64         `json:"utxos"`
	Cases []coinSelectCase `json:"cases"`
}

type coinSelectCase struct {
	Name            string `json:"name"`
	Amount          uint64 `json:"amount"`
	MinChangeAmount int64  `json:"minChangeAmount"`
	ExpectError     bool   `json:"expectError"`
}

func loadCoins(t *testing.T, values []uint64) []coinset.Coin {
	t.Helper()
	require.NotEmpty(t, values)

	coins := make([]coinset.Coin, 0, len(values))
	for i, v := range values {
		var hash chainhash.Hash
		binary.LittleEndian.PutUint32(hash[:], uint32(i))
		coins = append(coins, coin{ports.Utxo{
			OutPoint: *wire.NewOutPoint(&hash, uint32(i)),
			Value:    v,
		}})
	}
	return coins
}
