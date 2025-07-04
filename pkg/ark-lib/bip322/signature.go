package bip322

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrInvalidTxNumberOfInputs   = fmt.Errorf("invalid tx, expected at least 2 inputs")
	ErrInvalidTxNumberOfOutputs  = fmt.Errorf("invalid tx, expected at least 1 output")
	ErrInvalidTxWrongTxHash      = fmt.Errorf("invalid tx, wrong tx hash in first input")
	ErrInvalidTxWrongOutputIndex = fmt.Errorf("invalid tx, wrong output index in first input")
	ErrPrevoutNotFound           = fmt.Errorf("prevout not found")
)

// Signature is the signed and extracted toSign transaction
type Signature wire.MsgTx

func DecodeSignature(b64 string) (*Signature, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(decoded)); err != nil {
		return nil, err
	}

	return (*Signature)(tx), nil
}

// Encode encodes the tx to a base64 string
func (s Signature) Encode() (string, error) {
	var buf bytes.Buffer

	tx := wire.MsgTx(s)

	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// Verify validates the BIP-0322 full proof of funds
// Our version does not check the input sequences to be compatible with offchain txs.
func (s Signature) Verify(message string, prevoutFetcher txscript.PrevOutputFetcher) error {
	if len(s.TxIn) < 2 {
		return ErrInvalidTxNumberOfInputs
	}

	if len(s.TxOut) == 0 {
		return ErrInvalidTxNumberOfOutputs
	}

	// the first input of the tx is always the toSpend tx,
	// we use the input index 1 to get initial pkscript use to craft toSpend
	secondInputPrevout := prevoutFetcher.FetchPrevOutput(s.TxIn[1].PreviousOutPoint)
	if secondInputPrevout == nil {
		return ErrPrevoutNotFound
	}

	// craft the toSpend tx
	toSpend := buildToSpendTx(message, secondInputPrevout.PkScript)
	toSpendHash := toSpend.TxHash()

	// overwrite the prevoutFetcher to include the toSpend tx
	prevoutFetcher = &bip322PrevoutFetcher{
		prevoutFetcher: prevoutFetcher,
		toSpend:        toSpend,
	}

	// verify that toSpend tx is used as first input
	if !s.TxIn[0].PreviousOutPoint.Hash.IsEqual(&toSpendHash) {
		return ErrInvalidTxWrongTxHash
	}
	if s.TxIn[0].PreviousOutPoint.Index != 0 {
		return ErrInvalidTxWrongOutputIndex
	}

	tx := wire.MsgTx(s)

	txSigHashes := txscript.NewTxSigHashes(&tx, prevoutFetcher)
	sigCache := txscript.NewSigCache(1000)

	for i, input := range s.TxIn {
		prevout := prevoutFetcher.FetchPrevOutput(input.PreviousOutPoint)
		if prevout == nil {
			return ErrPrevoutNotFound
		}

		engine, err := txscript.NewEngine(
			prevout.PkScript, &tx, i, txscript.StandardVerifyFlags,
			sigCache, txSigHashes, prevout.Value, prevoutFetcher,
		)
		if err != nil {
			return err
		}

		if err := engine.Execute(); err != nil {
			return err
		}

	}

	return nil
}

func (s *Signature) GetOutpoints() []wire.OutPoint {
	outpoints := make([]wire.OutPoint, 0, len(s.TxIn)-1)
	for _, input := range s.TxIn[1:] {
		outpoints = append(outpoints, input.PreviousOutPoint)
	}
	return outpoints
}

func (s *Signature) ContainsOutputs() bool {
	if len(s.TxOut) == 0 {
		return false
	}
	if len(s.TxOut) == 1 && bytes.Equal(s.TxOut[0].PkScript, opReturnEmptyPkScript) {
		return false
	}
	return true
}

type bip322PrevoutFetcher struct {
	prevoutFetcher txscript.PrevOutputFetcher
	toSpend        *wire.MsgTx
}

func (f *bip322PrevoutFetcher) FetchPrevOutput(outpoint wire.OutPoint) *wire.TxOut {
	// if toSpend prevout requested, return the first output
	toSpendHash := f.toSpend.TxHash()
	if outpoint.Hash.IsEqual(&toSpendHash) && outpoint.Index == 0 {
		return f.toSpend.TxOut[0]
	}
	// otherwise, fallback to the original prevoutFetcher
	return f.prevoutFetcher.FetchPrevOutput(outpoint)
}
