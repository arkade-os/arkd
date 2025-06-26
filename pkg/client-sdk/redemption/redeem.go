package redemption

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/indexer"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type CovenantlessRedeemBranch struct {
	vtxo     types.Vtxo
	branch   []indexer.ChainWithExpiry
	explorer explorer.Explorer
	indexer  indexer.Indexer
}

func NewRedeemBranch(ctx context.Context, explorer explorer.Explorer, indexerSvc indexer.Indexer, vtxo types.Vtxo) (*CovenantlessRedeemBranch, error) {
	chain, err := indexerSvc.GetVtxoChain(ctx, indexer.Outpoint{
		Txid: vtxo.Txid,
		VOut: vtxo.VOut,
	})
	if err != nil {
		return nil, err
	}

	return &CovenantlessRedeemBranch{
		vtxo:     vtxo,
		branch:   chain.Chain,
		explorer: explorer,
		indexer:  indexerSvc,
	}, nil
}

// RedeemPath returns the list of transactions to broadcast in order to access the vtxo output
// due to current P2A relay policy, we can't broadcast the branch tx until its parent tx is
// confirmed so we'll broadcast only the first tx of every branch
func (r *CovenantlessRedeemBranch) NextRedeemTx() (string, error) {
	nextTxToBroadcast := ""
	for i := len(r.branch) - 1; i >= 0; i-- {
		tx := r.branch[i]
		// commitment txs are always onchain, so we can skip them
		switch tx.Type {
		case indexer.IndexerChainedTxTypeCommitment, indexer.IndexerChainedTxTypeUnspecified:
			continue
		}

		confirmed, _, err := r.explorer.GetTxBlockTime(tx.Txid)

		// if the tx is not found, it's offchain, let's break
		if err != nil {
			nextTxToBroadcast = tx.Txid
			break
		}

		// if found but not confirmed, it means the tx is in the mempool
		// an unilateral exit is running, we must wait for it to be confirmed
		if !confirmed {
			return "", ErrPendingConfirmation{Txid: tx.Txid}
		}
	}

	if nextTxToBroadcast == "" {
		return "", fmt.Errorf("no offchain txs found, the vtxo is already redeemed")
	}

	txs, err := r.indexer.GetVirtualTxs(context.Background(), []string{nextTxToBroadcast})
	if err != nil {
		return "", err
	}

	if len(txs.Txs) == 0 {
		return "", fmt.Errorf("tx %s not found", nextTxToBroadcast)
	}

	tx, err := psbt.NewFromRawBytes(strings.NewReader(txs.Txs[0]), true)
	if err != nil {
		return "", err
	}

	for i, input := range tx.Inputs {
		if len(input.TaprootKeySpendSig) > 0 {
			// musig2 tx, finalize as tapkey spend
			var witness bytes.Buffer
			if err := psbt.WriteTxWitness(&witness, [][]byte{input.TaprootKeySpendSig}); err != nil {
				return "", err
			}

			tx.Inputs[i].FinalScriptWitness = witness.Bytes()
			continue
		}

		if len(input.TaprootLeafScript) > 0 {
			// leaf script tx, it means it's a vtxo
			// we need to extract the leaf script
			leaf := input.TaprootLeafScript[0]

			closure, err := tree.DecodeClosure(leaf.Script)
			if err != nil {
				return "", err
			}

			conditionWitness, err := tree.GetConditionWitness(input)
			if err != nil {
				return "", err
			}

			args := make(map[string][]byte)
			if len(conditionWitness) > 0 {
				var conditionWitnessBytes bytes.Buffer
				if err := psbt.WriteTxWitness(&conditionWitnessBytes, conditionWitness); err != nil {
					return "", err
				}
				args[tree.ConditionWitnessKey] = conditionWitnessBytes.Bytes()
			}

			for _, sig := range input.TaprootScriptSpendSig {
				args[hex.EncodeToString(sig.XOnlyPubKey)] = sig.Signature
			}

			witness, err := closure.Witness(leaf.ControlBlock, args)
			if err != nil {
				return "", err
			}

			var witnessBytes bytes.Buffer
			if err := psbt.WriteTxWitness(&witnessBytes, witness); err != nil {
				return "", err
			}

			tx.Inputs[i].FinalScriptWitness = witnessBytes.Bytes()
			continue
		}

		return "", fmt.Errorf("invalid tx, unable to finalize")
	}

	extracted, err := psbt.Extract(tx)
	if err != nil {
		return "", err
	}

	var txBytes bytes.Buffer

	if err := extracted.Serialize(&txBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(txBytes.Bytes()), nil
}

func (r *CovenantlessRedeemBranch) ExpiresAt() (*time.Time, error) {
	lastKnownBlocktime := int64(0)
	for _, node := range r.branch {
		confirmed, _, err := r.explorer.GetTxBlockTime(node.Txid)
		if err != nil {
			break
		}

		if confirmed {
			lastKnownBlocktime = node.ExpiresAt
			continue
		}

		break
	}

	t := time.Unix(lastKnownBlocktime, 0)
	return &t, nil
}

// ErrPendingConfirmation is returned when computing the offchain path of a redeem branch. Due to P2A relay policy, only 1C1P packages are accepted.
// This error is returned when the tx is found onchain but not confirmed yet, allowing the user to know when to wait for the tx to be confirmed or to continue with the redemption.
type ErrPendingConfirmation struct {
	Txid string
}

func (e ErrPendingConfirmation) Error() string {
	return fmt.Sprintf("unilateral exit is running, please wait for tx %s to be confirmed", e.Txid)
}
