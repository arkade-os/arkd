package application

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/chaincfg"
)

func NetworkToChainParams(network string) *chaincfg.Params {
	switch network {
	case arklib.Bitcoin.Name:
		return &chaincfg.MainNetParams
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return &chaincfg.TestNet4Params
	case arklib.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case arklib.BitcoinSigNet.Name:
		return &chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return &arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}
