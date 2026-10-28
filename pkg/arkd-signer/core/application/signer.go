package application

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txsigner"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// CutoffDate is informational (0 = unset): it is not enforced at signing time.
type DeprecatedSignerKey struct {
	Key        *btcec.PrivateKey
	CutoffDate int64
}

type DeprecatedSignerPubkey struct {
	Pubkey     string
	CutoffDate int64
}

type Signer struct {
	key        *btcec.PrivateKey
	deprecated []DeprecatedSignerKey
}

func New(key *btcec.PrivateKey, deprecated []DeprecatedSignerKey) *Signer {
	return &Signer{key: key, deprecated: deprecated}
}

func (s *Signer) GetPubkey() string {
	return hex.EncodeToString(s.key.PubKey().SerializeCompressed())
}

func (s *Signer) GetDeprecatedPubkeys() []DeprecatedSignerPubkey {
	pubkeys := make([]DeprecatedSignerPubkey, 0, len(s.deprecated))
	for _, k := range s.deprecated {
		pubkeys = append(pubkeys, DeprecatedSignerPubkey{
			Pubkey:     hex.EncodeToString(k.Key.PubKey().SerializeCompressed()),
			CutoffDate: k.CutoffDate,
		})
	}
	return pubkeys
}

func (s *Signer) SignTransaction(partialTx string, inputIndexes []int) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(partialTx), true)
	if err != nil {
		return "", err
	}

	for _, idx := range inputIndexes {
		if idx < 0 || idx >= len(ptx.Inputs) {
			return "", fmt.Errorf("input index %d out of range [0,%d)", idx, len(ptx.Inputs))
		}
	}

	fetcher, err := txutils.GetPrevOutputFetcher(ptx)
	if err != nil {
		return "", err
	}
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)

	for i, in := range ptx.Inputs {
		// skip P2A anchor inputs
		if bytes.Equal(in.WitnessUtxo.PkScript, txutils.ANCHOR_PKSCRIPT) {
			continue
		}
		if len(inputIndexes) > 0 && !slices.Contains(inputIndexes, i) {
			continue
		}
		if !txscript.IsPayToTaproot(in.WitnessUtxo.PkScript) {
			continue
		}
		if len(in.TaprootLeafScript) == 0 {
			continue
		}
		key := s.signerKeyForLeaf(in.TaprootLeafScript[0].Script)
		if err := txsigner.SignTapscriptInput(ptx, i, key, sigHashes); err != nil {
			return "", err
		}
	}

	return ptx.B64Encode()
}

// signerKeyForLeaf returns the deprecated key present in the leaf, or the current key.
func (s *Signer) signerKeyForLeaf(leafScript []byte) *btcec.PrivateKey {
	if len(s.deprecated) == 0 {
		return s.key
	}

	closure, err := script.DecodeClosure(leafScript)
	if err != nil {
		return s.key
	}

	var leafKeys []*btcec.PublicKey
	switch c := closure.(type) {
	case *script.MultisigClosure:
		leafKeys = c.PubKeys
	case *script.CSVMultisigClosure:
		leafKeys = c.PubKeys
	case *script.CLTVMultisigClosure:
		leafKeys = c.PubKeys
	case *script.ConditionMultisigClosure:
		leafKeys = c.PubKeys
	case *script.ConditionCSVMultisigClosure:
		leafKeys = c.PubKeys
	default:
		return s.key
	}

	for _, k := range s.deprecated {
		want := schnorr.SerializePubKey(k.Key.PubKey())
		for _, pubkey := range leafKeys {
			if bytes.Equal(schnorr.SerializePubKey(pubkey), want) {
				return k.Key
			}
		}
	}
	return s.key
}
