package clientlib

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
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

func parseClosure(
	outpoint Outpoint, closure script.Closure, tapscripts []string,
) ([]byte, *arklib.TaprootMerkleProof, error) {
	if closure == nil {
		return nil, nil, fmt.Errorf("%s has no signing closure", outpoint.String())
	}
	if len(tapscripts) <= 0 {
		return nil, nil, fmt.Errorf("%s has no tapscripts", outpoint.String())
	}

	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid tapscripts: %w", outpoint.String(), err)
	}
	forfeitScript, err := closure.Script()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%s has invalid signing closure: %w", outpoint.String(), err,
		)
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid taptree: %w", outpoint.String(), err)
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%s has invalid signing script: %w", outpoint.String(), err,
		)
	}
	pkScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s has invalid tapkey: %w", outpoint.String(), err)
	}

	return pkScript, leafProof, nil
}
