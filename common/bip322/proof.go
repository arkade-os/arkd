// https://bips.xyz/322
package bip322

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrMissingInputs      = fmt.Errorf("missing inputs")
	ErrMissingData        = fmt.Errorf("missing data")
	ErrMissingWitnessUtxo = fmt.Errorf("missing witness utxo")
	ErrIncompletePSBT     = fmt.Errorf("incomplete psbt, missing signatures on inputs")
)

var (
	tagBIP322             = []byte("BIP0322-signed-message")
	zeroHash              = chainhash.Hash(make([]byte, 32))
	opReturnEmptyPkScript = []byte{txscript.OP_RETURN}
)

// BIP0322 full proof of funds is a special invalid psbt containing the inputs to prove ownership
// signing the proof means signing the psbt as a regular transaction
type FullProof psbt.Packet

// Input embeds data of the UTXO to prove ownership
type Input struct {
	OutPoint    *wire.OutPoint
	Sequence    uint32
	WitnessUtxo *wire.TxOut
}

// New creates the proof psbt from the message and inputs
func New(message string, inputs []Input, outputs []*wire.TxOut) (*FullProof, error) {
	if len(inputs) == 0 {
		return nil, ErrMissingInputs
	}

	for _, input := range inputs {
		if err := input.validate(); err != nil {
			return nil, err
		}
	}

	firstInput := inputs[0]
	toSpend := buildToSpendTx(message, firstInput.WitnessUtxo.PkScript)
	toSign, err := buildToSignTx(toSpend, inputs, outputs)
	if err != nil {
		return nil, err
	}

	return (*FullProof)(toSign), nil
}

// Signature extracts the BIP-0322 signature, fails if the tx is not fully signed.
// If the inputs contains custom witness, you may want to specify a finalization function,
// if otherwise the default finalizer is used.
func (p *FullProof) Signature(finalize ...func(*psbt.Packet) error) (*Signature, error) {
	if len(finalize) == 0 {
		finalize = []func(*psbt.Packet) error{psbt.MaybeFinalizeAll}
	}

	proofTx := psbt.Packet(*p)
	for _, f := range finalize {
		if err := f(&proofTx); err != nil {
			return nil, err
		}
	}

	if !proofTx.IsComplete() {
		return nil, ErrIncompletePSBT
	}

	signed, err := psbt.Extract(&proofTx)
	if err != nil {
		return nil, err
	}

	return (*Signature)(signed), nil
}

func (i *Input) validate() error {
	if i.OutPoint == nil {
		return ErrMissingData
	}

	if i.WitnessUtxo == nil {
		return ErrMissingWitnessUtxo
	}

	return nil
}

func hashMessage(message string) []byte {
	tagged := chainhash.TaggedHash(tagBIP322, []byte(message))
	return tagged[:]
}

// buildToSpendTx creates the initial transaction that will be spent in the proof
func buildToSpendTx(message string, pkScript []byte) *wire.MsgTx {
	messageHash := hashMessage(message)
	toSpend := wire.NewMsgTx(0)
	toSpend.TxIn = []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  zeroHash,
				Index: 0xFFFFFFFF,
			},
			Sequence:        0,
			SignatureScript: append([]byte{txscript.OP_0, txscript.OP_DATA_32}, messageHash...),
			Witness:         wire.TxWitness{},
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
