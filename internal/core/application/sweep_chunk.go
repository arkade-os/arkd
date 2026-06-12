package application

import (
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
)

const (
	// maxStandardTxWeight is the Bitcoin policy limit (in weight units) above
	// which a transaction is considered non-standard and won't be relayed.
	maxStandardTxWeight = 400_000

	// sweepTxWeightBudget is the per-sweep-tx weight target. It keeps a margin
	// below the standardness limit to absorb the upper-bound estimation drift.
	sweepTxWeightBudget lntypes.WeightUnit = maxStandardTxWeight * 95 / 100
)

// chunkSweepInputs partitions the given sweep inputs into groups, each of which
// fits in a single transaction below the weight budget. A greedy bin-packing is
// used: inputs are added to the current chunk until the next one would exceed
// the budget, then a new chunk is started. It returns an error if a single
// input alone exceeds the budget.
func chunkSweepInputs(
	inputs []ports.TxInput, budget lntypes.WeightUnit,
) ([][]ports.TxInput, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	newEstimator := func() *input.TxWeightEstimator {
		est := &input.TxWeightEstimator{}
		// every sweep tx has a single P2TR output paying the sweep address
		est.AddP2TROutput()
		return est
	}

	addInput := func(est *input.TxWeightEstimator, in ports.TxInput) error {
		if in.TapscriptLeaf == nil {
			// connector utxos are spent by the wallet via key-path
			est.AddTaprootKeySpendInput(txscript.SigHashDefault)
			return nil
		}
		witnessSize, err := tapscriptWitnessSize(in.TapscriptLeaf)
		if err != nil {
			return err
		}
		est.AddWitnessInput(witnessSize)
		return nil
	}

	chunks := make([][]ports.TxInput, 0)
	current := make([]ports.TxInput, 0)
	est := newEstimator()

	for _, in := range inputs {
		if err := addInput(est, in); err != nil {
			return nil, err
		}

		if est.Weight() <= budget {
			current = append(current, in)
			continue
		}

		// adding this input exceeds the budget: close the current chunk (which
		// does not include it) and start a new one with this input alone.
		if len(current) == 0 {
			return nil, fmt.Errorf(
				"sweep input %s:%d alone exceeds the max tx weight budget (%d WU)",
				in.Txid, in.Index, budget,
			)
		}

		chunks = append(chunks, current)
		current = []ports.TxInput{in}
		est = newEstimator()
		if err := addInput(est, in); err != nil {
			return nil, err
		}
		if est.Weight() > budget {
			return nil, fmt.Errorf(
				"sweep input %s:%d alone exceeds the max tx weight budget (%d WU)",
				in.Txid, in.Index, budget,
			)
		}
	}

	if len(current) > 0 {
		chunks = append(chunks, current)
	}

	return chunks, nil
}

// tapscriptWitnessSize returns the upper-bound witness size (in weight units) of
// a sweep input spending a CSV-multisig closure via the script path. The witness
// stack is: one schnorr signature per signer, the revealed script and the
// control block (plus the element-count byte and per-element length prefixes).
func tapscriptWitnessSize(leaf *ports.Tapscript) (lntypes.WeightUnit, error) {
	scriptBytes, err := hex.DecodeString(leaf.Tapscript)
	if err != nil {
		return 0, err
	}

	controlBlock, err := hex.DecodeString(leaf.ControlBlock)
	if err != nil {
		return 0, err
	}

	sweepClosure := script.CSVMultisigClosure{}
	valid, err := sweepClosure.Decode(scriptBytes)
	if err != nil {
		return 0, err
	}
	if !valid {
		return 0, fmt.Errorf("invalid csv multisig sweep script")
	}

	numSigs := len(sweepClosure.PubKeys)
	if numSigs == 0 {
		numSigs = 1
	}

	size := 1 + // number of witness elements
		numSigs*input.TaprootSignatureWitnessSize + // schnorr sigs (1 len + 64)
		wire.VarIntSerializeSize(uint64(len(scriptBytes))) + len(scriptBytes) +
		wire.VarIntSerializeSize(uint64(len(controlBlock))) + len(controlBlock)

	return lntypes.WeightUnit(size), nil
}
