package clientlib

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/chaincfg"
)

func NetworkFromString(net string) arklib.Network {
	switch net {
	case arklib.BitcoinTestNet.Name:
		return arklib.BitcoinTestNet
	case arklib.BitcoinTestNet4.Name:
		return arklib.BitcoinTestNet4
	case arklib.BitcoinSigNet.Name:
		return arklib.BitcoinSigNet
	case arklib.BitcoinMutinyNet.Name:
		return arklib.BitcoinMutinyNet
	case arklib.BitcoinRegTest.Name:
		return arklib.BitcoinRegTest
	case arklib.Bitcoin.Name:
		fallthrough
	default:
		return arklib.Bitcoin
	}
}

func ToBitcoinNetwork(net arklib.Network) chaincfg.Params {
	switch net.Name {
	case arklib.Bitcoin.Name:
		return chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		return chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	default:
		return chaincfg.MainNetParams
	}
}
