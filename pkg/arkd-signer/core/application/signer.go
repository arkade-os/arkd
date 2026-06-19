package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txsigner"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// DeprecatedSignerKey is an operator key still accepted for signing but scheduled
// for retirement. CutoffDate is the unix timestamp after which clients should
// stop locking new funds to it (0 = unset); it is informational and not enforced
// at signing time, matching arkd-wallet's behaviour.
type DeprecatedSignerKey struct {
	Key        *btcec.PrivateKey
	CutoffDate int64
}

// DeprecatedSignerPubkey is the public view of a DeprecatedSignerKey.
type DeprecatedSignerPubkey struct {
	Pubkey     string
	CutoffDate int64
}

// Signer is the operator signing service: it holds an injected current key plus
// any deprecated keys, and signs tapscript-path PSBT inputs. It has no chain
// access and requires complete PSBTs (every input must carry a WitnessUtxo).
type Signer interface {
	GetPubkey(ctx context.Context) (string, error)
	GetDeprecatedPubkeys(ctx context.Context) ([]DeprecatedSignerPubkey, error)
	IsReady(ctx context.Context) bool
	SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error)
	SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error)
}

type signer struct {
	key        *btcec.PrivateKey
	deprecated []DeprecatedSignerKey
}

// New returns a Signer backed by the given current operator key and optional
// deprecated keys.
func New(key *btcec.PrivateKey, deprecated []DeprecatedSignerKey) Signer {
	return &signer{key: key, deprecated: deprecated}
}

func (s *signer) GetPubkey(_ context.Context) (string, error) {
	if s.key == nil {
		return "", fmt.Errorf("signer key not loaded")
	}
	return hex.EncodeToString(s.key.PubKey().SerializeCompressed()), nil
}

func (s *signer) GetDeprecatedPubkeys(_ context.Context) ([]DeprecatedSignerPubkey, error) {
	pubkeys := make([]DeprecatedSignerPubkey, 0, len(s.deprecated))
	for _, k := range s.deprecated {
		pubkeys = append(pubkeys, DeprecatedSignerPubkey{
			Pubkey:     hex.EncodeToString(k.Key.PubKey().SerializeCompressed()),
			CutoffDate: k.CutoffDate,
		})
	}
	return pubkeys, nil
}

func (s *signer) IsReady(_ context.Context) bool {
	return s.key != nil
}

func (s *signer) SignTransaction(
	ctx context.Context, partialTx string, extractRawTx bool,
) (string, error) {
	return s.sign(ctx, partialTx, extractRawTx, nil)
}

func (s *signer) SignTransactionTapscript(
	ctx context.Context, partialTx string, inputIndexes []int,
) (string, error) {
	return s.sign(ctx, partialTx, false, inputIndexes)
}

func (s *signer) sign(
	_ context.Context, partialTx string, extractRawTx bool, inputIndexes []int,
) (string, error) {
	if s.key == nil {
		return "", fmt.Errorf("signer key not loaded")
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(partialTx), true)
	if err != nil {
		return "", err
	}

	fetcher, err := txsigner.BuildPrevoutFetcher(ptx)
	if err != nil {
		return "", err
	}
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)

	for i, in := range ptx.Inputs {
		// skip P2A anchor inputs
		if bytes.Equal(in.WitnessUtxo.PkScript, txutils.ANCHOR_PKSCRIPT) {
			continue
		}
		// skip inputs not selected when a subset was requested
		if len(inputIndexes) > 0 && !slices.Contains(inputIndexes, i) {
			continue
		}
		// pure signer signs taproot script-path inputs only
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

	if extractRawTx {
		return txsigner.ExtractFinalizedTx(ptx)
	}
	return ptx.B64Encode()
}

// signerKeyForLeaf returns the deprecated signer key whose pubkey appears in the
// leaf's multisig closure, or the current key. The cutoff date is not enforced
// here: the wallet always signs with the matching key whether or not the cutoff
// has passed, and arkd-signer preserves that behaviour.
func (s *signer) signerKeyForLeaf(leafScript []byte) *btcec.PrivateKey {
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
	case *script.CLTVMultisigClosure:
		leafKeys = c.PubKeys
	case *script.ConditionMultisigClosure:
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
