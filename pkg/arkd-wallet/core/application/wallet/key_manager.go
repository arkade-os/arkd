package wallet

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

type keyManager struct {
	// m/86'/(cointype)'/0'
	mainAccount *hdkeychain.ExtendedKey
	// m/86'/(cointype)'/1'
	connectorAccount *hdkeychain.ExtendedKey
	// forfeit private key derived from path mainAccount/0/0
	forfeitPrvkey *btcec.PrivateKey

	// derivation schemes strings used by nbxplorer tracking system
	// arkd wallet is taproot account = "xpub-[taproot]"
	// https://github.com/dgarage/NBXplorer/blob/master/docs/API.md#derivation-scheme
	mainAccountDerivationScheme      string
	connectorAccountDerivationScheme string
}

// newKeyManager takes the seed key and derives BIP86 accounts
func newKeyManager(seed []byte, network *chaincfg.Params) (*keyManager, error) {
	masterKey, err := hdkeychain.NewMaster(seed, network)
	if err != nil {
		return nil, err
	}

	// m/86'
	taprootPurposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 86)
	if err != nil {
		return nil, err
	}

	cointypeIndex := uint32(0)
	if network.Name != chaincfg.MainNetParams.Name {
		cointypeIndex = 1
	}
	// m/86'/0' for mainnet, m/86'/1' for testnet/regtest
	coinTypeKey, err := taprootPurposeKey.Derive(hdkeychain.HardenedKeyStart + cointypeIndex)
	if err != nil {
		return nil, err
	}
	// m/86'/(cointype)'/0' (main account)
	mainAccount, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}
	// m/86'/(cointype)'/1' (connector account)
	connectorAccount, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + 1)
	if err != nil {
		return nil, err
	}

	mainAccountDerivationScheme, err := computeTaprootDerivationScheme(mainAccount)
	if err != nil {
		return nil, err
	}
	connectorAccountDerivationScheme, err := computeTaprootDerivationScheme(connectorAccount)
	if err != nil {
		return nil, err
	}

	forfeitPrvkey, err := deriveForfeitPrvkey(mainAccount, network)
	if err != nil {
		return nil, err
	}

	return &keyManager{
		mainAccount, connectorAccount, forfeitPrvkey,
		mainAccountDerivationScheme, connectorAccountDerivationScheme,
	}, nil
}

// compute the private key from main or connector account based on the derivation scheme and key path
func (k *keyManager) deriveKey(derivationScheme string, keyPath string) (*btcec.PrivateKey, error) {
	var key *hdkeychain.ExtendedKey
	switch derivationScheme {
	case k.mainAccountDerivationScheme:
		key = k.mainAccount
	case k.connectorAccountDerivationScheme:
		key = k.connectorAccount
	default:
		return nil, fmt.Errorf("invalid xpub")
	}

	splittedPath := strings.Split(keyPath, "/")
	for _, path := range splittedPath {
		pathIndex, err := strconv.Atoi(path)
		if err != nil {
			return nil, fmt.Errorf("invalid path")
		}

		key, err = key.Derive(uint32(pathIndex))
		if err != nil {
			return nil, err
		}
	}

	return key.ECPrivKey()
}

func computeTaprootDerivationScheme(accountKey *hdkeychain.ExtendedKey) (string, error) {
	neutered, err := accountKey.Neuter()
	if err != nil {
		return "", err
	}
	return neutered.String() + "-[taproot]", nil
}

func deriveForfeitPrvkey(xpub *hdkeychain.ExtendedKey, network *chaincfg.Params) (*btcec.PrivateKey, error) {
	key, err := xpub.Derive(0)
	if err != nil {
		return nil, err
	}
	key, err = key.Derive(0)
	if err != nil {
		return nil, err
	}
	return key.ECPrivKey()
}
