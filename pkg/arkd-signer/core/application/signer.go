package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/txsigner"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// Signer is the operator signing service: it holds a single injected private key
// and signs tapscript-path PSBT inputs. It has no chain access and requires
// complete PSBTs (every input must carry a WitnessUtxo).
type Signer interface {
	GetPubkey(ctx context.Context) (string, error)
	IsReady(ctx context.Context) bool
	SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error)
	SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error)
}

type signer struct {
	key *btcec.PrivateKey
}

// New returns a Signer backed by the given operator private key.
func New(key *btcec.PrivateKey) Signer {
	return &signer{key: key}
}

func (s *signer) GetPubkey(_ context.Context) (string, error) {
	if s.key == nil {
		return "", fmt.Errorf("signer key not loaded")
	}
	return hex.EncodeToString(s.key.PubKey().SerializeCompressed()), nil
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
		if err := txsigner.SignTapscriptInput(ptx, i, s.key, sigHashes); err != nil {
			return "", err
		}
	}

	if extractRawTx {
		return txsigner.ExtractFinalizedTx(ptx)
	}
	return ptx.B64Encode()
}
