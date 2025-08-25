package wallet

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip32"
)

type keyManager struct {
	// m/84'/0'/0'
	mainAccount *bip32.Key
	// m/84'/0'/1'
	connectorAccount *bip32.Key
	// m/86'/0'/0'
	arkSignerAccount *bip32.Key
}

// newKeyManager takes the seed key and derives BIP84 and BIP86 keys
func newKeyManager(seed []byte, isMainnet bool) (*keyManager, error) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	purposeKeyP2wpkh, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 84)
	if err != nil {
		return nil, err
	}
	purposeKeyP2tr, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 86)
	if err != nil {
		return nil, err
	}
	cointypeIndex := uint32(0)
	if !isMainnet {
		cointypeIndex = 1
	}
	cointypeHardenedIndex := uint32(bip32.FirstHardenedChild + cointypeIndex)

	bip84MasterKey, err := purposeKeyP2wpkh.NewChildKey(cointypeHardenedIndex)
	if err != nil {
		return nil, err
	}
	mainAccount, err := bip84MasterKey.NewChildKey(bip32.FirstHardenedChild)
	if err != nil {
		return nil, err
	}
	connectorAccount, err := bip84MasterKey.NewChildKey(bip32.FirstHardenedChild + 1)
	if err != nil {
		return nil, err
	}

	bip86MasterKey, err := purposeKeyP2tr.NewChildKey(cointypeHardenedIndex)
	if err != nil {
		return nil, err
	}
	arkSignerAccount, err := bip86MasterKey.NewChildKey(bip32.FirstHardenedChild)
	if err != nil {
		return nil, err
	}

	return &keyManager{mainAccount, connectorAccount, arkSignerAccount}, nil
}

func (k *keyManager) getMainAccountXPub() string {
	return k.mainAccount.PublicKey().B58Serialize()
}

func (k *keyManager) getConnectorAccountXPub() string {
	return k.connectorAccount.PublicKey().B58Serialize()
}

func (k *keyManager) getArkSignerAccountXPub() string {
	return k.arkSignerAccount.PublicKey().B58Serialize()
}

func (k *keyManager) getForfeitPublicKey() (*secp256k1.PublicKey, error) {
	key, err := k.arkSignerAccount.NewChildKey(0)
	if err != nil {
		return nil, err
	}
	key, err = key.NewChildKey(0)
	if err != nil {
		return nil, err
	}
	return secp256k1.ParsePubKey(key.PublicKey().Key)
}

func (k *keyManager) getArkSignerPublicKey() (*secp256k1.PublicKey, error) {
	key, err := k.arkSignerAccount.NewChildKey(0)
	if err != nil {
		return nil, err
	}
	key, err = key.NewChildKey(0)
	if err != nil {
		return nil, err
	}

	return secp256k1.ParsePubKey(key.PublicKey().Key)
}

func (k *keyManager) getArkSignerPrivateKey() (*secp256k1.PrivateKey, error) {
	key, err := k.arkSignerAccount.NewChildKey(0)
	if err != nil {
		return nil, err
	}
	key, err = key.NewChildKey(0)
	if err != nil {
		return nil, err
	}
	return secp256k1.PrivKeyFromBytes(key.Key), nil
}

func (k *keyManager) getPrivateKey(xpub string, keyPath string) (*secp256k1.PrivateKey, error) {
	var key *bip32.Key
	switch xpub {
	case k.getMainAccountXPub():
		key = k.mainAccount
	case k.getConnectorAccountXPub():
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

		key, err = key.NewChildKey(uint32(pathIndex))
		if err != nil {
			return nil, err
		}
	}

	return secp256k1.PrivKeyFromBytes(key.Key), nil
}
