package txutils

import (
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// IndexedCosignerPublicKey is a public key with its associated index.
// it is needed in ark cosigner public key field because we need to keep track of the order of the keys.
type IndexedCosignerPublicKey struct {
	Index     int
	PublicKey *btcec.PublicKey
}

func ParseCosignersToECPubKeys(fields []IndexedCosignerPublicKey) []*btcec.PublicKey {
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Index < fields[j].Index
	})

	cosigners := make([]*btcec.PublicKey, 0, len(fields))
	for _, field := range fields {
		cosigners = append(cosigners, field.PublicKey)
	}
	return cosigners
}

func ParseCosignerKeysFromArkPsbt(ptx *psbt.Packet, inIndex int) ([]*btcec.PublicKey, error) {
	fields, err := GetArkPsbtFields(ptx, inIndex, CosignerPublicKeyField)
	if err != nil {
		return nil, err
	}
	return ParseCosignersToECPubKeys(fields), nil
}
