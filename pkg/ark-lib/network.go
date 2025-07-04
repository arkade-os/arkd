package arklib

import (
	"time"

	"github.com/btcsuite/btcd/chaincfg"
)

type Network struct {
	Name string
	Addr string
}

var Bitcoin = Network{
	Name: "bitcoin",
	Addr: "ark",
}

var BitcoinTestNet = Network{
	Name: "testnet",
	Addr: "tark",
}

var BitcoinTestNet4 = Network{
	Name: "testnet4",
	Addr: BitcoinTestNet.Addr,
}

var BitcoinSigNet = Network{
	Name: "signet",
	Addr: BitcoinTestNet.Addr,
}

var BitcoinMutinyNet = Network{
	Name: "mutinynet",
	Addr: BitcoinTestNet.Addr,
}

var BitcoinRegTest = Network{
	Name: "regtest",
	Addr: BitcoinTestNet.Addr,
}

var MutinyNetSigNetParams = func() chaincfg.Params {
	params := chaincfg.CustomSignetParams(mutinyNetChallenge, nil)
	params.TargetTimePerBlock = mutinyNetBlockTime
	return params
}()

var mutinyNetChallenge = []byte{
	0x51, 0x21, 0x02, 0xf7, 0x56, 0x1d, 0x20, 0x8d, 0xd9, 0xae, 0x99, 0xbf,
	0x49, 0x72, 0x73, 0xe1, 0x6f, 0x38, 0x9b, 0xdb, 0xd6, 0xc4, 0x74, 0x2d,
	0xdb, 0x8e, 0x6b, 0x21, 0x6e, 0x64, 0xfa, 0x29, 0x28, 0xad, 0x8f, 0x51,
	0xae,
}

const mutinyNetBlockTime = time.Second * 30
