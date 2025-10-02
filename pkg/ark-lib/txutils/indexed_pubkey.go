package txutils

import (
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
)

// IndexedCosignerPublicKey is a public key with its associated index.
// it is needed in ark cosigner public key field because we need to keep track of the order of the keys.
type IndexedCosignerPublicKey struct {
	Index     int
	PublicKey *btcec.PublicKey
}

func MakeCosignerPublicKeyList(fields []IndexedCosignerPublicKey) ([]*btcec.PublicKey, error) {
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Index < fields[j].Index
	})

	cosigners := make([]*btcec.PublicKey, 0, len(fields))
	for _, field := range fields {
		cosigners = append(cosigners, field.PublicKey)
	}
	return cosigners, nil
}
