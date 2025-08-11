package tree

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

var (
	ErrInvalidBatchOutputsNum = fmt.Errorf(
		"invalid number of batch outputs in commitment transaction",
	)
	ErrEmptyTree                  = fmt.Errorf("empty vtxo tree")
	ErrNoLeaves                   = fmt.Errorf("no leaves in the tree")
	ErrInvalidTaprootScript       = fmt.Errorf("invalid taproot script")
	ErrMissingCosignersPublicKeys = fmt.Errorf("missing cosigners public keys")
	ErrInvalidAmount              = fmt.Errorf("children amount is different from parent amount")
	ErrBatchOutputMismatch        = fmt.Errorf(
		"invalid vtxo tree root, tx input does not match batch outpoint",
	)
)

const batchOutputIndex = 0

// ValidateVtxoTree checks if the given vtxo tree is valid
// vtxoTree tx & commitmentTx are used to validate that the tree spends from the batch outpoint.
// signerPubkey & vtxoTreeExpiry are used to validate the sweep tapscript leaves.
// Along with that, the function validates:
// - the number of nodes
// - the number of leaves
// - children spend from parent
// - every control block and taproot output scripts
// - each tx matches input and output amounts
func ValidateVtxoTree(
	vtxoTree *TxTree, commitmentTx *psbt.Packet,
	signerPubkey *btcec.PublicKey, vtxoTreeExpiry arklib.RelativeLocktime,
) error {
	if len(commitmentTx.Outputs) < batchOutputIndex+1 {
		return ErrInvalidBatchOutputsNum
	}

	batchOutputAmount := commitmentTx.UnsignedTx.TxOut[batchOutputIndex].Value

	if vtxoTree.Root == nil {
		return ErrEmptyTree
	}

	rootInput := vtxoTree.Root.UnsignedTx.TxIn[0]
	if chainhash.Hash(rootInput.PreviousOutPoint.Hash).String() != commitmentTx.UnsignedTx.TxID() ||
		rootInput.PreviousOutPoint.Index != batchOutputIndex {
		return ErrBatchOutputMismatch
	}

	sumRootValue := int64(0)
	for _, output := range vtxoTree.Root.UnsignedTx.TxOut {
		sumRootValue += output.Value
	}

	if sumRootValue != batchOutputAmount {
		return ErrInvalidAmount
	}

	if len(vtxoTree.Leaves()) == 0 {
		return ErrNoLeaves
	}

	sweepClosure := &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{signerPubkey}},
		Locktime:        vtxoTreeExpiry,
	}

	sweepScript, err := sweepClosure.Script()
	if err != nil {
		return err
	}

	sweepLeaf := txscript.NewBaseTapLeaf(sweepScript)
	tapTree := txscript.AssembleTaprootScriptTree(sweepLeaf)
	tapTreeRoot := tapTree.RootNode.TapHash()

	// Validate the vtxo tree.
	if err := vtxoTree.Validate(); err != nil {
		return err
	}

	// Verify that all nodes' cosigners public keys match the parent output.
	if err := vtxoTree.Apply(func(node *TxTree) (bool, error) {
		for childIndex, child := range node.Children {
			parentOutput := node.Root.UnsignedTx.TxOut[childIndex]
			previousScriptKey := parentOutput.PkScript[2:]
			if len(previousScriptKey) != 32 {
				return false, ErrInvalidTaprootScript
			}

			cosigners, err := txutils.GetCosignerKeys(child.Root.Inputs[0])
			if err != nil {
				return false, fmt.Errorf("unable to get cosigners keys: %w", err)
			}

			cosigners = uniqueCosigners(cosigners)

			if len(cosigners) == 0 {
				return false, ErrMissingCosignersPublicKeys
			}

			aggregatedKey, err := AggregateKeys(cosigners, tapTreeRoot.CloneBytes())
			if err != nil {
				return false, fmt.Errorf("unable to aggregate keys: %w", err)
			}

			if !bytes.Equal(schnorr.SerializePubKey(aggregatedKey.FinalKey), previousScriptKey) {
				return false, ErrInvalidTaprootScript
			}
		}
		return true, nil
	}); err != nil {
		return err
	}

	return nil
}
