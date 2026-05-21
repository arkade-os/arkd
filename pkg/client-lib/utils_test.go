package clientlib_test

import (
	"testing"

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
