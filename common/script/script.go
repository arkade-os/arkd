package script

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1
	OP_INSPECTOUTPUTVALUE        = 0xcf
	OP_PUSHCURRENTINPUTINDEX     = 0xcd
	OP_INSPECTINPUTVALUE         = 0xc9
	OP_SUB64                     = 0xd8
)

type MultisigType int

const (
	MultisigTypeChecksig MultisigType = iota
	MultisigTypeChecksigAdd
)

var ConditionWitnessKey = "condition"

// forbiddenOpcodes are opcodes that are not allowed in a condition script
var forbiddenOpcodes = []byte{
	txscript.OP_CHECKMULTISIG,
	txscript.OP_CHECKSIG,
	txscript.OP_CHECKSIGVERIFY,
	txscript.OP_CHECKSIGADD,
	txscript.OP_CHECKMULTISIGVERIFY,
	txscript.OP_CHECKLOCKTIMEVERIFY,
	txscript.OP_CHECKSEQUENCEVERIFY,
}

// EvaluateScriptToBool executes the script with the provided witness as argument and returns a
// boolean result that can be evaluated by OP_IF / OP_NOIF opcodes.
func EvaluateScriptToBool(script []byte, witness wire.TxWitness) (bool, error) {
	// make sure the script doesn't contain any introspections opcodes (sig or locktime)
	tokenizer := txscript.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		for _, opcode := range forbiddenOpcodes {
			if tokenizer.OpcodePosition() != -1 && tokenizer.Opcode() == opcode {
				return false, fmt.Errorf("forbidden opcode %x", opcode)
			}
		}
	}

	// Create a fake transaction with minimal required fields
	// this is needed to instantiate the script engine without a tx
	// as we don't validate any tx data, we just need to have a valid tx structure
	fakeTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}}, // At least one input required
		TxOut:   []*wire.TxOut{{Value: 0}},            // At least one output required
	}

	// Create a new script engine with the fake tx
	vm, err := txscript.NewEngine(
		script,
		fakeTx,
		0, // Input index
		txscript.ScriptVerifyTaproot,
		nil,
		nil,
		0,
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("failed to create script engine: %w", err)
	}

	vm.SetStack(witness)

	// Execute the script with the provided witness
	if err := vm.Execute(); err != nil {
		if scriptError, ok := err.(txscript.Error); ok {
			if scriptError.ErrorCode == txscript.ErrEvalFalse {
				return false, nil
			}
		}
		return false, err
	}

	finalStack := vm.GetStack()

	if len(finalStack) != 0 {
		return false, fmt.Errorf(
			"script must return zero value on the stack, got %d",
			len(finalStack),
		)
	}

	return true, nil
}

// 0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
var unspendablePoint = []byte{
	0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
	0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
}

func UnspendableKey() *btcec.PublicKey {
	key, _ := btcec.ParsePubKey(unspendablePoint)
	return key
}

func P2TRScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}

func SubDustScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_RETURN).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}

func IsSubDustScript(script []byte) bool {
	return len(script) == 32+1+1 &&
		script[0] == txscript.OP_RETURN &&
		script[1] == 0x20
}
