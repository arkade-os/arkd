package tree

import "github.com/btcsuite/btcd/btcec/v2"

func NewVtxoTreeSigner() (SignerSession, error) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return NewTreeSignerSession(key), nil
}
