package intent

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrMissingInputs             = fmt.Errorf("missing inputs")
	ErrMissingData               = fmt.Errorf("missing data")
	ErrMissingWitnessUtxo        = fmt.Errorf("missing witness utxo")
	ErrInvalidTxNumberOfInputs   = fmt.Errorf("invalid intent proof: expected at least 2 inputs")
	ErrInvalidTxNumberOfOutputs  = fmt.Errorf("invalid intent proof: expected at least 1 output")
	ErrInvalidTxWrongTxHash      = fmt.Errorf("invalid intent proof: wrong tx hash in message input")
	ErrInvalidTxWrongOutputIndex = fmt.Errorf("invalid intent proof: wrong output index in message input")
	ErrPrevoutNotFound           = fmt.Errorf("invalid intent proof: missing witness utxo field")
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
	IsExtended  bool
}

// Verify takes an encoded b64 proof tx and a message to validate the proof
// skip lists public keys whose signatures are not required (e.g. the signer key)
func Verify(proofB64, message string, skip []*btcec.PublicKey) error {
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

	prevoutFetcher, err := txutils.GetPrevOutputFetcher(ptx)
	if err != nil {
		return err
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

	if _, err := script.VerifyTapscriptSigs(
		ptx, prevoutFetcher,
		script.WithSkipPublicKeys(skip...),
	); err != nil {
		return fmt.Errorf("invalid intent proof: %w", err)
	}

	// Note closures use hash-locks, not signatures — VerifyTapscriptSigs
	// skips them entirely, so we must verify the preimage here.
	for i := 1; i < len(ptx.Inputs); i++ {
		in := ptx.Inputs[i]
		if len(in.TaprootLeafScript) != 1 {
			return fmt.Errorf("malformed input %d: missing TaprootLeafScript", i)
		}
		
		if !script.IsNoteClosureScript(in.TaprootLeafScript[0].Script) {
			continue
		}
		if err := verifyNoteInput(ptx, i, prevoutFetcher); err != nil {
			return fmt.Errorf("invalid intent proof: %w", err)
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

func (p Proof) Fees() (int64, error) {
	sumOfInputs := int64(0)
	for i, input := range p.Inputs {
		if input.WitnessUtxo == nil {
			return 0, fmt.Errorf("missing witness utxo for input %d", i)
		}
		sumOfInputs += int64(input.WitnessUtxo.Value)
	}

	sumOfOutputs := int64(0)
	for _, output := range p.UnsignedTx.TxOut {
		sumOfOutputs += int64(output.Value)
	}

	fees := sumOfInputs - sumOfOutputs
	if fees < 0 {
		return 0, fmt.Errorf("sum of inputs is smaller than sum of outputs (diff: %d)", fees)
	}
	return fees, nil
}

// GetOutpoints returns the list of inputs proving ownership of coins
// the first input is the toSpend tx, we ignore it
func (p Proof) GetOutpoints() []wire.OutPoint {
	if len(p.UnsignedTx.TxIn) <= 1 {
		return nil
	}
	outpoints := make([]wire.OutPoint, 0, len(p.UnsignedTx.TxIn)-1)
	for _, input := range p.UnsignedTx.TxIn[1:] {
		outpoints = append(outpoints, input.PreviousOutPoint)
	}
	return outpoints
}

type IntentOutpoint struct {
	wire.OutPoint
	IsSeal bool
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

func (p Proof) FinalizeAndExtract(signer *btcec.PublicKey) (*wire.MsgTx, error) {
	if len(p.Inputs) < 2 {
		return nil, ErrInvalidTxNumberOfInputs
	}

	ins := make([]psbt.PInput, len(p.Inputs))
	copy(ins[:], p.Inputs)
	outs := make([]psbt.POutput, len(p.Outputs))
	copy(outs[:], p.Outputs)
	unknowns := make([]*psbt.Unknown, len(p.Unknowns))
	copy(unknowns[:], p.Unknowns)
	ptx := &psbt.Packet{
		UnsignedTx: p.UnsignedTx.Copy(),
		Inputs:     ins,
		Outputs:    outs,
		Unknowns:   unknowns,
	}

	// copy the unknowns from the second input to the first input
	// in order to have the condition witness also in the first "fake" proof input
	ptx.Inputs[0].Unknowns = ptx.Inputs[1].Unknowns

	// we add fakeSignerSignature to make the finalization possible
	// the signer is never signing intent proof but we need the finalization to estimate the right tx weight
	fakeSignerSig := psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(signer),
		Signature:   make([]byte, 64),
	}

	for i := range p.Inputs {
		ptx.Inputs[i].TaprootScriptSpendSig = append(ptx.Inputs[i].TaprootScriptSpendSig, &fakeSignerSig)

		if err := finalizeInput(ptx, i); err != nil {
			return nil, err
		}
	}

	return psbt.Extract(ptx)
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

// finalizeInput is a wrapper of script.FinalizeVtxoScript with note support
func finalizeInput(ptx *psbt.Packet, inputIndex int) error {
	if len(ptx.Inputs) <= inputIndex {
		return fmt.Errorf(
			"input index out of bounds %d, len(inputs)=%d", inputIndex, len(ptx.Inputs),
		)
	}

	in := ptx.Inputs[inputIndex]

	if len(in.FinalScriptWitness) > 0 {
		// already finalized, skip
		return nil
	}

	if len(in.TaprootLeafScript) == 0 {
		return nil
	}

	if err := note.FinalizeNoteClosure(ptx, inputIndex, in.TaprootLeafScript[0]); err != nil {
		if errors.Is(err, note.ErrInvalidNoteScript) {
			// if it's not a note, finalize as vtxo script
			return script.FinalizeVtxoScript(ptx, inputIndex)
		}
		return err
	}

	return nil
}

// verifyNoteInput verifies a note closure input by checking the control block
// against the prevout and validating that the provided preimage hashes to the
// value embedded in the script.
func verifyNoteInput(
	ptx *psbt.Packet, inputIndex int, prevoutFetcher txscript.PrevOutputFetcher,
) error {
	in := ptx.Inputs[inputIndex]
	tapscriptLeaf := in.TaprootLeafScript[0]

	// verify the control block matches the prevout pkscript
	prevout := prevoutFetcher.FetchPrevOutput(
		ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint,
	)
	if prevout == nil {
		return fmt.Errorf("prevout not found for note input %d", inputIndex)
	}

	controlBlock, err := txscript.ParseControlBlock(tapscriptLeaf.ControlBlock)
	if err != nil {
		return fmt.Errorf(
			"failed to parse control block for note input %d: %w", inputIndex, err,
		)
	}

	rootHash := controlBlock.RootHash(tapscriptLeaf.Script)
	unspendableKey := script.UnspendableKey()
	taprootKey := txscript.ComputeTaprootOutputKey(unspendableKey, rootHash[:])
	expectedTaprootKey := prevout.PkScript[2:]

	if !bytes.Equal(schnorr.SerializePubKey(taprootKey), expectedTaprootKey) {
		return fmt.Errorf("invalid control block for note input %d", inputIndex)
	}

	computedKeyIsOdd := taprootKey.SerializeCompressed()[0] == 0x03
	if controlBlock.OutputKeyYIsOdd != computedKeyIsOdd {
		return fmt.Errorf("invalid control block parity for note input %d", inputIndex)
	}

	// decode the note closure to extract the expected preimage hash
	var noteClosure note.NoteClosure
	valid, err := noteClosure.Decode(tapscriptLeaf.Script)
	if err != nil {
		return fmt.Errorf(
			"failed to decode note closure for input %d: %w", inputIndex, err,
		)
	}
	if !valid {
		return fmt.Errorf("invalid note closure script for input %d", inputIndex)
	}

	// retrieve the preimage from the PSBT condition witness field
	conditionWitnessFields, err := txutils.GetArkPsbtFields(
		ptx, inputIndex, txutils.ConditionWitnessField,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to get condition witness for note input %d: %w", inputIndex, err,
		)
	}

	if len(conditionWitnessFields) != 1 || len(conditionWitnessFields[0]) == 0 {
		return fmt.Errorf("missing preimage for note input %d", inputIndex)
	}

	preimage := conditionWitnessFields[0][0]
	preimageHash := sha256.Sum256(preimage)

	if preimageHash != noteClosure.PreimageHash {
		return fmt.Errorf("invalid preimage for note input %d", inputIndex)
	}

	return nil
}

