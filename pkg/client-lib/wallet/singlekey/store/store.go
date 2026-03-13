package store

import "github.com/btcsuite/btcd/btcec/v2"

type WalletData struct {
	EncryptedPrvkey []byte
	PasswordHash    []byte
	PubKey          *btcec.PublicKey
}

type BoardingDescriptor struct {
	Address    string
	Tapscripts []string
}

type WalletStore interface {
	AddWallet(data WalletData) error
	GetWallet() (*WalletData, error)
	AddBoardingDescriptor(descriptor BoardingDescriptor) error
	GetBoardingDescriptors() ([]BoardingDescriptor, error)
}
