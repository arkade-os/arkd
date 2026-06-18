// Package backfill signs the operator's half of forfeit transactions that were
// persisted before arkd started signing forfeit txs at collection time.
//
// It is meant to be run on demand by the operator (see cmd/arkd-forfeit-backfill).
// It only touches forfeit txs of vtxos that still require a forfeit (unswept,
// unexpired, not notes, not unrolled): those are the only forfeits that could
// ever still be broadcast. Forfeit txs that already carry the operator signature
// are left untouched, so the backfill is safe to run repeatedly.
package backfill

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// VtxoSource exposes the vtxos to scan. Satisfied by domain.VtxoRepository.
type VtxoSource interface {
	GetAllVtxos(ctx context.Context) ([]domain.Vtxo, error)
}

// ForfeitStore reads rounds and patches forfeit txs. Satisfied by
// domain.RoundRepository.
type ForfeitStore interface {
	GetRoundWithCommitmentTxid(ctx context.Context, txid string) (*domain.Round, error)
	PatchForfeitTxs(ctx context.Context, txByTxid map[string]string) error
}

// Signer adds the operator signature to a forfeit tx. Satisfied by
// ports.SignerService.
type Signer interface {
	GetPubkey(ctx context.Context) (*btcec.PublicKey, error)
	GetDeprecatedPubkeys(ctx context.Context) ([]ports.DeprecatedSignerPubkey, error)
	SignTransactionTapscript(
		ctx context.Context,
		partialTx string,
		inputIndexes []int,
	) (string, error)
}

// Result is a summary of a backfill run.
type Result struct {
	Scanned       int // unswept forfeited vtxos considered
	Signed        int // forfeit txs newly signed and persisted
	AlreadySigned int // forfeit txs already operator-signed (skipped)
	Failed        int // forfeit txs that could not be signed or persisted
}

// Run scans all unswept forfeited vtxos, signs the operator's half of their
// forfeit txs when missing, and persists the result. A per-forfeit failure is
// logged and counted but does not abort the run, so re-running retries only the
// forfeits that are still unsigned.
func Run(
	ctx context.Context,
	vtxos VtxoSource,
	rounds ForfeitStore,
	signer Signer,
) (Result, error) {
	pubkey, err := signer.GetPubkey(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("failed to get operator pubkey: %w", err)
	}
	operatorKeys := [][]byte{schnorr.SerializePubKey(pubkey)}

	// Include deprecated keys so forfeits signed before a key rotation are
	// recognized as already signed and not re-signed with the current key.
	deprecated, err := signer.GetDeprecatedPubkeys(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("failed to get deprecated operator pubkeys: %w", err)
	}
	for _, d := range deprecated {
		if d.PubKey != nil {
			operatorKeys = append(operatorKeys, schnorr.SerializePubKey(d.PubKey))
		}
	}

	allVtxos, err := vtxos.GetAllVtxos(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("failed to list vtxos: %w", err)
	}

	// Group the unswept forfeited vtxos by the commitment tx of the round that
	// holds their forfeit tx, so each round is loaded once.
	byCommitment := make(map[string][]domain.Vtxo)
	for _, v := range allVtxos {
		if !v.IsSettled() || !v.RequiresForfeit() {
			continue
		}
		byCommitment[v.SettledBy] = append(byCommitment[v.SettledBy], v)
	}

	var res Result
	for commitmentTxid, group := range byCommitment {
		round, err := rounds.GetRoundWithCommitmentTxid(ctx, commitmentTxid)
		if err != nil {
			res.Failed += len(group)
			log.WithError(err).Errorf(
				"failed to load round %s, skipping %d forfeit(s)", commitmentTxid, len(group),
			)
			continue
		}

		patch := make(map[string]string)
		for _, v := range group {
			res.Scanned++

			forfeitTx, err := findForfeitTx(round.ForfeitTxs, v.Outpoint)
			if err != nil {
				res.Failed++
				log.WithError(err).
					Errorf("failed to find forfeit tx for vtxo %s", v.Outpoint.String())
				continue
			}

			if forfeitOperatorSigned(forfeitTx, operatorKeys) {
				res.AlreadySigned++
				continue
			}

			b64, err := forfeitTx.B64Encode()
			if err != nil {
				res.Failed++
				log.WithError(err).
					Errorf("failed to encode forfeit tx for vtxo %s", v.Outpoint.String())
				continue
			}

			signedTx, err := signer.SignTransactionTapscript(ctx, b64, nil)
			if err != nil {
				res.Failed++
				log.WithError(err).
					Errorf("failed to sign forfeit tx for vtxo %s", v.Outpoint.String())
				continue
			}

			signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(signedTx), true)
			if err != nil {
				res.Failed++
				log.WithError(err).
					Errorf("failed to parse signed forfeit tx for vtxo %s", v.Outpoint.String())
				continue
			}

			patch[signedPtx.UnsignedTx.TxID()] = signedTx
		}

		if len(patch) == 0 {
			continue
		}

		if err := rounds.PatchForfeitTxs(ctx, patch); err != nil {
			res.Failed += len(patch)
			log.WithError(err).Errorf(
				"failed to persist %d signed forfeit tx(s) for round %s", len(patch), commitmentTxid,
			)
			continue
		}
		res.Signed += len(patch)
	}

	return res, nil
}

// findForfeitTx returns the forfeit tx whose input spends the given vtxo. Mirrors
// the lookup in internal/core/application/fraud.go (findForfeitTx), kept local so
// the tool does not depend on the application package.
func findForfeitTx(forfeits []domain.ForfeitTx, vtxo domain.Outpoint) (*psbt.Packet, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit.Tx), true)
		if err != nil {
			return nil, err
		}
		for _, in := range forfeitTx.UnsignedTx.TxIn {
			if in.PreviousOutPoint.Hash.String() == vtxo.Txid &&
				in.PreviousOutPoint.Index == vtxo.VOut {
				return forfeitTx, nil
			}
		}
	}
	return nil, fmt.Errorf("forfeit tx not found for vtxo %s", vtxo.String())
}

// forfeitOperatorSigned reports whether the forfeit tx already carries a tapscript
// signature from one of the operator's signer keys (the current key or any
// deprecated one). Deprecated keys are included so a forfeit signed before a key
// rotation is recognized as already signed and not re-signed with the current key.
func forfeitOperatorSigned(ptx *psbt.Packet, operatorXOnlyKeys [][]byte) bool {
	for _, in := range ptx.Inputs {
		for _, sig := range in.TaprootScriptSpendSig {
			for _, key := range operatorXOnlyKeys {
				if bytes.Equal(sig.XOnlyPubKey, key) {
					return true
				}
			}
		}
	}
	return false
}
