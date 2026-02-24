package store

import "github.com/btcsuite/btcd/btcec/v2"

type WalletData struct {
	EncryptedPrvkey []byte
	PasswordHash    []byte
	PubKey          *btcec.PublicKey
}

type WalletStore interface {
	AddWallet(data WalletData) error
	GetWallet() (*WalletData, error)
}
