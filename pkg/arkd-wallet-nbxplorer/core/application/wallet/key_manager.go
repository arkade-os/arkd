package wallet

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type keyManager struct {
	// m/84'/0'/0'
	mainAccount *hdkeychain.ExtendedKey
	// m/86'/0'/1'
	connectorAccount *hdkeychain.ExtendedKey
	// m/86'/0'/0'
	arkSignerAccount *hdkeychain.ExtendedKey
}

// newKeyManager takes the seed key and derives BIP84 and BIP86 keys
func newKeyManager(seed []byte, network *chaincfg.Params) (*keyManager, error) {
	masterKey, err := hdkeychain.NewMaster(seed, network)
	if err != nil {
		return nil, err
	}

	p2wpkhPurposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 84)
	if err != nil {
		return nil, err
	}
	taprootPurposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 86)
	if err != nil {
		return nil, err
	}

	cointypeIndex := uint32(0)
	if network.Name != chaincfg.MainNetParams.Name {
		cointypeIndex = 1
	}
	cointypeHardenedIndex := hdkeychain.HardenedKeyStart + cointypeIndex

	bip84MasterKey, err := p2wpkhPurposeKey.Derive(cointypeHardenedIndex)
	if err != nil {
		return nil, err
	}
	mainAccount, err := bip84MasterKey.Derive(hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	bip86MasterKey, err := taprootPurposeKey.Derive(cointypeHardenedIndex)
	if err != nil {
		return nil, err
	}
	arkSignerAccount, err := bip86MasterKey.Derive(hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}
	connectorAccount, err := bip86MasterKey.Derive(hdkeychain.HardenedKeyStart + 1)
	if err != nil {
		return nil, err
	}

	return &keyManager{mainAccount, connectorAccount, arkSignerAccount}, nil
}

func (k *keyManager) getMainAccountDerivationScheme() string {
	neutered, err := k.mainAccount.Neuter()
	if err != nil {
		return ""
	}
	return neutered.String() // no suffix, nbxplorer default to segwit v0
}

func (k *keyManager) getConnectorAccountDerivationScheme() string {
	neutered, err := k.connectorAccount.Neuter()
	if err != nil {
		return ""
	}
	return neutered.String() + "-[taproot]"
}

func (k *keyManager) getForfeitPublicKey() (*secp256k1.PublicKey, error) {
	key, err := k.arkSignerAccount.Derive(0)
	if err != nil {
		return nil, err
	}
	key, err = key.Derive(0)
	if err != nil {
		return nil, err
	}

	ecPubKey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}

	return secp256k1.ParsePubKey(ecPubKey.SerializeCompressed())
}

func (k *keyManager) getArkSignerPublicKey() (*secp256k1.PublicKey, error) {
	key, err := k.arkSignerAccount.Derive(0)
	if err != nil {
		return nil, err
	}
	key, err = key.Derive(0)
	if err != nil {
		return nil, err
	}

	ecPubKey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}

	return secp256k1.ParsePubKey(ecPubKey.SerializeCompressed())
}

func (k *keyManager) getArkSignerPrivateKey() (*secp256k1.PrivateKey, error) {
	key, err := k.arkSignerAccount.Derive(0)
	if err != nil {
		return nil, err
	}
	key, err = key.Derive(0)
	if err != nil {
		return nil, err
	}

	ecPrivKey, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}

	return secp256k1.PrivKeyFromBytes(ecPrivKey.Serialize()), nil
}

func (k *keyManager) getPrivateKey(xpub string, keyPath string) (*secp256k1.PrivateKey, error) {
	var key *hdkeychain.ExtendedKey
	switch xpub {
	case k.getMainAccountDerivationScheme():
		key = k.mainAccount
	case k.getConnectorAccountDerivationScheme():
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

	ecPrivKey, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}

	return secp256k1.PrivKeyFromBytes(ecPrivKey.Serialize()), nil
}
