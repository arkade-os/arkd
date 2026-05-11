package identitystore

import "github.com/btcsuite/btcd/btcec/v2"

type IdentityData struct {
	EncryptedPrvkey []byte
	PasswordHash    []byte
	PubKey          *btcec.PublicKey
}

type IdentityStore interface {
	Add(data IdentityData) error
	Get() (*IdentityData, error)
}
