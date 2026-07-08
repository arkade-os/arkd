package clientlib_test

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

func TestNetworkFromString(t *testing.T) {
	testCases := []struct {
		networkName     string
		expectedNetwork arklib.Network
	}{
		{arklib.BitcoinTestNet.Name, arklib.BitcoinTestNet},
		{arklib.BitcoinTestNet4.Name, arklib.BitcoinTestNet4},
		{arklib.BitcoinSigNet.Name, arklib.BitcoinSigNet},
		{arklib.BitcoinMutinyNet.Name, arklib.BitcoinMutinyNet},
		{arklib.BitcoinRegTest.Name, arklib.BitcoinRegTest},
		{arklib.Bitcoin.Name, arklib.Bitcoin},
		{"unknown", arklib.Bitcoin},
	}

	for _, tc := range testCases {
		t.Run(tc.networkName, func(t *testing.T) {
			result := clientlib.NetworkFromString(tc.networkName)
			require.Equal(t, tc.expectedNetwork, result)
		})
	}
}

func TestToBitcoinNetwork(t *testing.T) {
	testCases := []struct {
		network         arklib.Network
		expectedNetwork chaincfg.Params
	}{
		{arklib.BitcoinTestNet, chaincfg.TestNet3Params},
		{arklib.BitcoinSigNet, chaincfg.SigNetParams},
		{arklib.BitcoinMutinyNet, arklib.MutinyNetSigNetParams},
		{arklib.BitcoinRegTest, chaincfg.RegressionNetParams},
		{arklib.Bitcoin, chaincfg.MainNetParams},
		{arklib.BitcoinTestNet4, chaincfg.MainNetParams}, // testnet4 as unknown
	}

	for _, tc := range testCases {
		t.Run(tc.network.Name, func(t *testing.T) {
			result := clientlib.ToBitcoinNetwork(tc.network)
			require.Equal(t, tc.expectedNetwork, result)
		})
	}
}

func TestCoinSelect(t *testing.T) {
	// Three vtxos with distinct expiries. After sort the loop consumes the
	// furthest-expiry first; the soonest-to-expire vtxo is held back.
	now := time.Now()
	soon := vtxoAt("a", 0, 1000, now.Add(1*time.Hour))
	mid := vtxoAt("b", 0, 1000, now.Add(24*time.Hour))
	later := vtxoAt("c", 0, 1000, now.Add(48*time.Hour))

	t.Run("insufficient funds", func(t *testing.T) {
		_, _, _, err := clientlib.CoinSelect(
			nil, []clientlib.Vtxo{soon},
			[]clientlib.Receiver{{Amount: 5000}}, 330, nil,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough funds")
	})

	t.Run("selects furthest-expiry vtxos first", func(t *testing.T) {
		_, sel, change, err := clientlib.CoinSelect(
			nil,
			// intentionally shuffled order; the sort puts later first.
			[]clientlib.Vtxo{soon, later, mid},
			// Target 1500 sats + dust=330: one vtxo (1000) won't cover; two
			// will. Expect later + mid picked, soon left aside.
			[]clientlib.Receiver{{Amount: 1500}}, 330, nil,
		)
		require.NoError(t, err)
		require.Len(t, sel, 2)
		require.Equal(t, "c", sel[0].Txid, "furthest-expiry first")
		require.Equal(t, "b", sel[1].Txid, "mid-expiry second")
		require.Equal(t, uint64(500), change)
	})

	t.Run("sub-dust change folds in spare vtxo", func(t *testing.T) {
		// Two vtxos of 1000 each, target 1900, dust 330. After picking the
		// first vtxo (later=1000) we still need 900, so we pick another
		// (mid=1000) and end up with change=100 — below dust. The fallback
		// folds in the remaining `soon` vtxo (1000) so change becomes 1100.
		_, sel, change, err := clientlib.CoinSelect(
			nil,
			[]clientlib.Vtxo{soon, later, mid},
			[]clientlib.Receiver{{Amount: 1900}}, 330, nil,
		)
		require.NoError(t, err)
		require.Len(t, sel, 3, "third vtxo folded in to lift change above dust")
		require.Equal(t, uint64(1100), change)
	})

	t.Run("sub-dust change with no spare drops change to zero", func(t *testing.T) {
		// Exactly one vtxo and a target that leaves sub-dust change. With
		// no spare to fold in, change is set to zero (the leftover dust is
		// implicitly absorbed by the receiver/server).
		_, sel, change, err := clientlib.CoinSelect(
			nil,
			[]clientlib.Vtxo{later},
			[]clientlib.Receiver{{Amount: 900}}, 330, nil,
		)
		require.NoError(t, err)
		require.Len(t, sel, 1)
		require.Equal(t, uint64(0), change)
	})

	t.Run("exact match returns zero change", func(t *testing.T) {
		_, sel, change, err := clientlib.CoinSelect(
			nil,
			[]clientlib.Vtxo{later},
			[]clientlib.Receiver{{Amount: 1000}}, 330, nil,
		)
		require.NoError(t, err)
		require.Len(t, sel, 1)
		require.Equal(t, uint64(0), change)
	})
}

func TestCoinSelectAsset(t *testing.T) {
	const asset = "deadbeef"
	now := time.Now()
	soon := vtxoWithAsset("a", 0, 1000, now.Add(1*time.Hour), asset, 100)
	mid := vtxoWithAsset("b", 0, 1000, now.Add(24*time.Hour), asset, 100)
	later := vtxoWithAsset("c", 0, 1000, now.Add(48*time.Hour), asset, 100)

	t.Run("no vtxos hold the asset", func(t *testing.T) {
		// A vtxo with a different asset must be filtered out, leaving zero
		// candidates.
		other := vtxoWithAsset("z", 0, 1000, now.Add(1*time.Hour), "other", 100)
		_, _, err := clientlib.CoinSelectAsset(
			[]clientlib.Vtxo{other}, 50, asset, false,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough funds")
	})

	t.Run("selects furthest-expiry first when sorting", func(t *testing.T) {
		// Need 150 units of the asset; each vtxo holds 100. Sort moves
		// later/mid to the front; the soon vtxo is held back.
		sel, change, err := clientlib.CoinSelectAsset(
			[]clientlib.Vtxo{soon, later, mid}, 150, asset, false,
		)
		require.NoError(t, err)
		require.Len(t, sel, 2)
		require.Equal(t, "c", sel[0].Txid, "furthest-expiry first")
		require.Equal(t, "b", sel[1].Txid)
		require.Equal(t, uint64(50), change)
	})

	t.Run("withoutExpirySorting consumes input order", func(t *testing.T) {
		// Same inputs but withoutExpirySorting=true; loop picks in the
		// order given (soon, later, mid).
		sel, change, err := clientlib.CoinSelectAsset(
			[]clientlib.Vtxo{soon, later, mid}, 150, asset, true,
		)
		require.NoError(t, err)
		require.Len(t, sel, 2)
		require.Equal(t, "a", sel[0].Txid, "input order preserved")
		require.Equal(t, "c", sel[1].Txid)
		require.Equal(t, uint64(50), change)
	})

	t.Run("filters out vtxos with no matching asset", func(t *testing.T) {
		other := vtxoWithAsset("z", 0, 1000, now.Add(1*time.Hour), "other", 100)
		sel, change, err := clientlib.CoinSelectAsset(
			[]clientlib.Vtxo{other, later}, 50, asset, false,
		)
		require.NoError(t, err)
		require.Len(t, sel, 1)
		require.Equal(t, "c", sel[0].Txid, "vtxo holding 'other' asset filtered out")
		require.Equal(t, uint64(50), change)
	})
}

func TestParseBitcoinAddress(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name string
			addr string
			net  chaincfg.Params
		}{
			{
				// Same fixture used by pkg/client-lib/explorer/service_test.go.
				name: "mainnet p2wpkh",
				addr: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
				net:  chaincfg.MainNetParams,
			},
			{
				name: "mainnet p2pkh",
				addr: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
				net:  chaincfg.MainNetParams,
			},
			{
				name: "testnet p2wpkh",
				addr: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
				net:  chaincfg.TestNet3Params,
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				ok, script, err := clientlib.ParseBitcoinAddress(f.addr, f.net)
				require.NoError(t, err)
				require.True(t, ok)
				require.NotEmpty(t, script)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name string
			addr string
			net  chaincfg.Params
		}{
			{name: "empty", addr: "", net: chaincfg.MainNetParams},
			{name: "invalid address", addr: "not-an-address", net: chaincfg.MainNetParams},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				ok, script, err := clientlib.ParseBitcoinAddress(f.addr, f.net)
				require.NoError(t, err)
				require.False(t, ok)
				require.Nil(t, script)
			})
		}
	})
}

func TestEcPubkeyFromHex(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name   string
			pubkey string
		}{
			{
				// Compressed secp256k1 generator point G.
				name:   "compressed",
				pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			},
			{
				// Uncompressed secp256k1 generator point G.
				name: "uncompressed",
				pubkey: "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
					"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				pubkey, err := clientlib.EcPubkeyFromHex(f.pubkey)
				require.NoError(t, err)
				require.NotNil(t, pubkey)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name   string
			pubkey string
		}{
			{name: "invalid format", pubkey: "nothex"},
			{name: "invalid hex", pubkey: "0279be66"},
			{name: "empty", pubkey: ""},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				pubkey, err := clientlib.EcPubkeyFromHex(f.pubkey)
				require.Error(t, err)
				require.Nil(t, pubkey)
			})
		}
	})
}

// vtxoAt is a helper to build a baseline Vtxo with the given amount and
// expiry. Only the fields read by CoinSelect / CoinSelectAsset are populated;
// everything else is left zero.
func vtxoAt(txid string, vout uint32, amount uint64, expiresAt time.Time) clientlib.Vtxo {
	return clientlib.Vtxo{
		Outpoint:  clientlib.Outpoint{Txid: txid, VOut: vout},
		Amount:    amount,
		ExpiresAt: expiresAt,
	}
}

// vtxoWithAsset returns a Vtxo carrying the given asset balance. Used by the
// CoinSelectAsset cases.
func vtxoWithAsset(
	txid string, vout uint32, amount uint64, expiresAt time.Time,
	assetID string, assetAmount uint64,
) clientlib.Vtxo {
	v := vtxoAt(txid, vout, amount, expiresAt)
	v.Assets = []clientlib.Asset{{AssetId: assetID, Amount: assetAmount}}
	return v
}
