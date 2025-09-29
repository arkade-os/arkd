package intent

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrMissingInputs             = fmt.Errorf("missing inputs")
	ErrMissingData               = fmt.Errorf("missing data")
	ErrMissingWitnessUtxo        = fmt.Errorf("missing witness utxo")
	ErrIncompletePSBT            = fmt.Errorf("incomplete psbt, missing signatures on inputs")
	ErrInvalidTxNumberOfInputs   = fmt.Errorf("invalid tx, expected at least 2 inputs")
	ErrInvalidTxNumberOfOutputs  = fmt.Errorf("invalid tx, expected at least 1 output")
	ErrInvalidTxWrongTxHash      = fmt.Errorf("invalid tx, wrong tx hash in first input")
	ErrInvalidTxWrongOutputIndex = fmt.Errorf("invalid tx, wrong output index in first input")
	ErrPrevoutNotFound           = fmt.Errorf("prevout not found")
	ErrMissingArkFields          = fmt.Errorf("expected at least 1 ark field, revealed taptree is required")
)

var (
	zeroHash              = chainhash.Hash(make([]byte, 32))
	opReturnEmptyPkScript = []byte{txscript.OP_RETURN}
	fakeOutpoint          = wire.OutPoint{
		Hash:  zeroHash,
		Index: 0xFFFFFFFF,
	}
)

// an intent proof is a special psbt containing the inputs to prove ownership,
// embeds a message and may include optional outputs to register in ark batches.
type Proof struct {
	psbt.Packet
}

// Input embeds data of the UTXO to prove ownership
type Input struct {
	OutPoint    *wire.OutPoint
	Sequence    uint32
	WitnessUtxo *wire.TxOut
}

// Verify takes an encoded b64 proof tx and a message to validate the proof
func Verify(proofB64, message string) error {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(proofB64), true)
	if err != nil {
		return fmt.Errorf("failed to parse proof tx: %s", err)
	}

	proof := Proof{Packet: *ptx}

	if len(proof.Inputs) < 2 {
		return ErrInvalidTxNumberOfInputs
	}

	if len(proof.Outputs) == 0 {
		return ErrInvalidTxNumberOfOutputs
	}

	prevoutFetcher, err := proof.getPrevoutFetcher()
	if err != nil {
		return fmt.Errorf("failed to get prevout fetcher: %s", err)
	}

	// the first input of the tx is always the toSpend tx,
	// we use the input index 1 to get initial pkscript use to craft toSpend
	secondInputPrevout := prevoutFetcher.FetchPrevOutput(proof.UnsignedTx.TxIn[1].PreviousOutPoint)
	if secondInputPrevout == nil {
		return ErrPrevoutNotFound
	}

	// craft the toSpend tx
	toSpend := buildToSpendTx(message, secondInputPrevout.PkScript)
	toSpendHash := toSpend.TxHash()

	// overwrite the prevoutFetcher to include the toSpend tx
	prevoutFetcher = &intentProofPrevoutFetcher{
		prevoutFetcher: prevoutFetcher,
		toSpend:        toSpend,
	}

	// verify that toSpend tx is used as first input
	if !proof.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.IsEqual(&toSpendHash) {
		return ErrInvalidTxWrongTxHash
	}
	if proof.UnsignedTx.TxIn[0].PreviousOutPoint.Index != 0 {
		return ErrInvalidTxWrongOutputIndex
	}

	tx, err := finalizeAndExtract(proof)
	if err != nil {
		return err
	}

	txSigHashes := txscript.NewTxSigHashes(tx, prevoutFetcher)
	sigCache := txscript.NewSigCache(1000)

	for i, input := range tx.TxIn {
		prevout := prevoutFetcher.FetchPrevOutput(input.PreviousOutPoint)
		if prevout == nil {
			return ErrPrevoutNotFound
		}

		engine, err := txscript.NewEngine(
			prevout.PkScript, tx, i, txscript.StandardVerifyFlags,
			sigCache, txSigHashes, prevout.Value, prevoutFetcher,
		)
		if err != nil {
			return fmt.Errorf("failed to execute bitcoin script: %s", err)
		}

		if err := engine.Execute(); err != nil {
			return err
		}

	}

	return nil
}

// New creates the proof psbt from the message, inputs and (optional) outputs list
// the psbt creation is greatly inspired by BIP322 (https://bips.xyz/322)
// it is composed of 2 transactions: toSpend and toSign
// * toSpend embeds the message and make the proof "invalid" from the chain point of view
// * toSign is the regular transaction that will be signed to prove ownership of the inputs and may include the specified outputs
// toSign spends toSpend input as first input, making the tx unusable onchain
func New(message string, inputs []Input, outputs []*wire.TxOut) (*Proof, error) {
	if len(inputs) == 0 {
		return nil, ErrMissingInputs
	}

	// validate the inputs
	for _, input := range inputs {
		if input.OutPoint == nil {
			return nil, ErrMissingData
		}

		if input.WitnessUtxo == nil {
			return nil, ErrMissingWitnessUtxo
		}
	}

	firstInput := inputs[0]
	toSpend := buildToSpendTx(message, firstInput.WitnessUtxo.PkScript)
	toSign, err := buildToSignTx(toSpend, inputs, outputs)
	if err != nil {
		return nil, err
	}

	return &Proof{Packet: *toSign}, nil
}

// GetOutpoints returns the list of inputs proving ownership of coins
// the first input is the toSpend tx, we ignore it
func (p Proof) GetOutpoints() []wire.OutPoint {
	outpoints := make([]wire.OutPoint, 0, len(p.UnsignedTx.TxIn)-1)
	for _, input := range p.UnsignedTx.TxIn[1:] {
		outpoints = append(outpoints, input.PreviousOutPoint)
	}
	return outpoints
}

// ContainsOutputs returns true if the proof specifies outputs to register in ark batches
func (p Proof) ContainsOutputs() bool {
	if len(p.UnsignedTx.TxOut) == 0 {
		return false
	}
	if len(p.UnsignedTx.TxOut) == 1 && bytes.Equal(p.UnsignedTx.TxOut[0].PkScript, opReturnEmptyPkScript) {
		return false
	}
	return true
}

func (p Proof) getPrevoutFetcher() (txscript.PrevOutputFetcher, error) {
	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for inputIndex, input := range p.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("witness utxo not found for input %d", inputIndex)
		}
		prevouts[p.UnsignedTx.TxIn[inputIndex].PreviousOutPoint] = input.WitnessUtxo
	}
	return txscript.NewMultiPrevOutFetcher(prevouts), nil
}

// buildToSpendTx creates the initial transaction that will be spent in the proof
func buildToSpendTx(message string, pkScript []byte) *wire.MsgTx {
	messageHash := hashMessage(message)
	toSpend := wire.NewMsgTx(0)
	toSpend.TxIn = []*wire.TxIn{
		{
			PreviousOutPoint: fakeOutpoint,
			Sequence:         0,
			SignatureScript:  append([]byte{txscript.OP_0, txscript.OP_DATA_32}, messageHash...),
			Witness:          wire.TxWitness{},
		},
	}
	toSpend.TxOut = []*wire.TxOut{{Value: 0, PkScript: pkScript}}
	return toSpend
}

// buildToSignTx creates the transaction that will be signed for the proof
func buildToSignTx(
	toSpend *wire.MsgTx, inputs []Input, outputs []*wire.TxOut,
) (*psbt.Packet, error) {
	outpoints := make([]*wire.OutPoint, 0, len(inputs)+1)
	sequences := make([]uint32, 0, len(inputs)+1)

	outpoints = append(outpoints, &wire.OutPoint{
		Hash:  toSpend.TxHash(),
		Index: 0,
	})
	firstInput := inputs[0]
	sequences = append(sequences, firstInput.Sequence)

	for _, input := range inputs {
		outpoints = append(outpoints, input.OutPoint)
		sequences = append(sequences, input.Sequence)
	}

	if len(outputs) == 0 {
		outputs = []*wire.TxOut{{Value: 0, PkScript: opReturnEmptyPkScript}}
	}

	toSign, err := psbt.New(outpoints, outputs, 2, 0, sequences)
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(toSign)
	if err != nil {
		return nil, err
	}

	if err := updater.AddInWitnessUtxo(&wire.TxOut{
		Value:    0,
		PkScript: firstInput.WitnessUtxo.PkScript,
	}, 0); err != nil {
		return nil, err
	}

	if err := updater.AddInSighashType(txscript.SigHashAll, 0); err != nil {
		return nil, err
	}

	for i, input := range inputs {
		if err := updater.AddInWitnessUtxo(input.WitnessUtxo, i+1); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(txscript.SigHashAll, i+1); err != nil {
			return nil, err
		}
	}

	return toSign, nil
}

// intentProofPrevoutFetcher is a wrapper of txscript.PrevOutputFetcher
// it handles the special case of the toSpend tx
type intentProofPrevoutFetcher struct {
	prevoutFetcher txscript.PrevOutputFetcher
	toSpend        *wire.MsgTx
}

func (f *intentProofPrevoutFetcher) FetchPrevOutput(outpoint wire.OutPoint) *wire.TxOut {
	// if toSpend prevout requested, return the first output
	toSpendHash := f.toSpend.TxHash()
	if outpoint.Hash.IsEqual(&toSpendHash) && outpoint.Index == 0 {
		return f.toSpend.TxOut[0]
	}
	// otherwise, fallback to the original prevoutFetcher
	return f.prevoutFetcher.FetchPrevOutput(outpoint)
}

func finalizeAndExtract(p Proof) (*wire.MsgTx, error) {
	ptx := &psbt.Packet{
		UnsignedTx: p.UnsignedTx,
		Inputs:     p.Inputs,
		Outputs:    p.Outputs,
		Unknowns:   p.Unknowns,
	}

	// copy the unknowns from the second input to the first input
	// in order to have the condition witness also in the first "fake" proof input
	ptx.Inputs[0].Unknowns = ptx.Inputs[1].Unknowns

	for i := range p.Inputs {
		if err := finalizeInput(ptx, i); err != nil {
			return nil, err
		}
	}

	return psbt.Extract(ptx)
}

// finalizeInput is a wrapper of script.FinalizeVtxoScript with note support
func finalizeInput(ptx *psbt.Packet, inputIndex int) error {
	// check if the input is a note first
	if len(ptx.Inputs) <= inputIndex {
		return fmt.Errorf("input index out of bounds %d, len(inputs)=%d", inputIndex, len(ptx.Inputs))
	}

	in := ptx.Inputs[inputIndex]
	if len(in.TaprootLeafScript) == 0 {
		return nil
	}

	var noteClosure note.NoteClosure
	valid, err := noteClosure.Decode(in.TaprootLeafScript[0].Script)
	if valid && err == nil {
		conditionWitness, err := txutils.GetConditionWitness(in)
		if err != nil {
			return err
		}

		if len(conditionWitness) != 1 {
			return fmt.Errorf("invalid condition witness, expected 1 witness for note vtxo, got %d", len(conditionWitness))
		}

		witness, err := noteClosure.Witness(in.TaprootLeafScript[0].ControlBlock, map[string][]byte{
			"preimage": conditionWitness[0],
		})
		if err != nil {
			return err
		}

		var witnessBuf bytes.Buffer
		if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
			return err
		}

		ptx.Inputs[inputIndex].FinalScriptWitness = witnessBuf.Bytes()
		return nil
	}

	// if it's not a note, finalize as vtxo script
	if err := script.FinalizeVtxoScript(ptx, inputIndex); err != nil {
		return err
	}

	return nil
}
