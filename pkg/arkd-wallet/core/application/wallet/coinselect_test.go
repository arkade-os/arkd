package wallet

import (
	"encoding/json"
	"fmt"
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

	for _, f := range fixtures.Cases {
		t.Run(f.Name, func(t *testing.T) {
			target := btcutil.Amount(f.Amount)
			minChange := btcutil.Amount(f.MinChangeAmount)

			selected, err := coinSelector{minChange}.CoinSelect(target, coins)
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
}

// coinSelectFixtures is the single testdata file: a shared utxo pool plus the
// selection cases run against it.
type coinSelectFixtures struct {
	Utxos []fixtureUtxo    `json:"utxos"`
	Cases []coinSelectCase `json:"cases"`
}

// fixtureUtxo mirrors one entry of the shared utxo pool.
type fixtureUtxo struct {
	Txid  string `json:"txid"`
	Vout  uint32 `json:"vout"`
	Value string `json:"value"`
}

type coinSelectCase struct {
	Name            string `json:"name"`
	Amount          uint64 `json:"amount"`
	MinChangeAmount int64  `json:"minChangeAmount"`
	ExpectError     bool   `json:"expectError"`
}

func loadCoins(t *testing.T, raw []fixtureUtxo) []coinset.Coin {
	t.Helper()
	require.NotEmpty(t, raw)

	coins := make([]coinset.Coin, 0, len(raw))
	for _, u := range raw {
		hash, err := chainhash.NewHashFromStr(u.Txid)
		require.NoError(t, err)

		var value uint64
		_, err = fmt.Sscan(u.Value, &value)
		require.NoError(t, err)

		coins = append(coins, coin{ports.Utxo{
			OutPoint: *wire.NewOutPoint(hash, u.Vout),
			Value:    value,
		}})
	}
	return coins
}
