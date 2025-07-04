package script

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	common "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type Closure interface {
	Script() ([]byte, error)
	Decode(script []byte) (bool, error)
	Witness(controlBlock []byte, opts map[string][]byte) (wire.TxWitness, error)
}

// MultisigClosure is a closure that contains a list of public keys and a
// CHECKSIG for each key. The witness size is 64 bytes per key, admitting the
// sighash type is SIGHASH_DEFAULT.
type MultisigClosure struct {
	PubKeys []*btcec.PublicKey
	Type    MultisigType
}

func DecodeClosure(script []byte) (Closure, error) {
	if len(script) == 0 {
		return nil, fmt.Errorf("cannot decode empty script")
	}

	types := []struct {
		closure Closure
		name    string
	}{
		{&CSVMultisigClosure{}, "CSV Multisig"},
		{&CLTVMultisigClosure{}, "CLTV Multisig"},
		{&MultisigClosure{}, "Multisig"},
		{&ConditionMultisigClosure{}, "Condition Multisig"},
		{&ConditionCSVMultisigClosure{}, "Condition CSV Multisig"},
	}

	var decodeErr []string
	for _, t := range types {
		scriptCopy := make([]byte, len(script))
		copy(scriptCopy, script)
		valid, err := t.closure.Decode(scriptCopy)
		if err != nil {
			decodeErr = append(decodeErr, fmt.Sprintf("%s: %v", t.name, err))
			continue
		}
		if valid {
			return t.closure, nil
		}
	}

	if len(decodeErr) > 0 {
		return nil, fmt.Errorf(
			"failed to decode script %x.\n%s", script, strings.Join(decodeErr, "\n"),
		)
	}

	return nil, fmt.Errorf("script does not match any known closure type: %s",
		hex.EncodeToString(script))
}

func (f *MultisigClosure) Script() ([]byte, error) {
	scriptBuilder := txscript.NewScriptBuilder()

	switch f.Type {
	case MultisigTypeChecksig:
		for i, pubkey := range f.PubKeys {
			scriptBuilder.AddData(schnorr.SerializePubKey(pubkey))
			if i == len(f.PubKeys)-1 {
				scriptBuilder.AddOp(txscript.OP_CHECKSIG)
				continue
			}
			scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY)
		}
	case MultisigTypeChecksigAdd:
		for i, pubkey := range f.PubKeys {
			scriptBuilder.AddData(schnorr.SerializePubKey(pubkey))
			if i == 0 {
				scriptBuilder.AddOp(txscript.OP_CHECKSIG)
				continue
			}
			scriptBuilder.AddOp(txscript.OP_CHECKSIGADD)
		}
		scriptBuilder.AddInt64(int64(len(f.PubKeys)))
		scriptBuilder.AddOp(txscript.OP_NUMEQUAL)
	}

	return scriptBuilder.Script()
}

func (f *MultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("failed to decode: script is empty")
	}

	valid, err := f.decodeChecksig(script)

	if err != nil {
		return false, fmt.Errorf("failed to decode checksig: %w", err)
	}

	if valid {
		return true, nil
	}

	valid, err = f.decodeChecksigAdd(script)

	if err != nil {
		return false, fmt.Errorf("failed to decode checksigadd: %w", err)
	}

	if valid {
		return valid, nil
	}

	return false, nil

}

func (f *MultisigClosure) decodeChecksigAdd(script []byte) (bool, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	pubkeys := make([]*btcec.PublicKey, 0)

	for tokenizer.Next() {
		// Stop processing if a small integer opcode is encountered,
		// indicating the required threshold for signature validation.
		if txscript.IsSmallInt(tokenizer.Opcode()) {
			break
		}

		// Verify we have a 32-byte data push
		if tokenizer.Opcode() != txscript.OP_DATA_32 {
			return false, nil
		}

		// Parse the public key
		pubkey, err := schnorr.ParsePubKey(tokenizer.Data())
		if err != nil {
			return false, err
		}

		pubkeys = append(pubkeys, pubkey)

		// Check if we've reached the end
		if !tokenizer.Next() {
			return false, nil
		}

		if tokenizer.Opcode() == txscript.OP_CHECKSIGADD ||
			tokenizer.Opcode() == txscript.OP_CHECKSIG {
			continue
		} else {
			return false, nil
		}
	}

	// Verify public keys len
	if tokenizer.Err() != nil || len(pubkeys) != txscript.AsSmallInt(tokenizer.Opcode()) {
		return false, nil
	}

	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_NUMEQUAL {
		return false, nil
	}

	f.PubKeys = pubkeys
	f.Type = MultisigTypeChecksigAdd

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		f.PubKeys = nil
		f.Type = 0
		return false, err
	}

	if !bytes.Equal(rebuilt, script) {
		f.PubKeys = nil
		f.Type = 0
		return false, nil
	}

	return true, nil
}

func (f *MultisigClosure) decodeChecksig(script []byte) (bool, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	pubkeys := make([]*btcec.PublicKey, 0)

	for tokenizer.Next() {
		// Verify we have a 32-byte data push
		if tokenizer.Opcode() != txscript.OP_DATA_32 {
			return false, nil
		}

		// Parse the public key
		pubkey, err := schnorr.ParsePubKey(tokenizer.Data())
		if err != nil {
			return false, err
		}

		pubkeys = append(pubkeys, pubkey)

		// Check if we've reached the end
		if !tokenizer.Next() {
			return false, nil
		}

		if tokenizer.Opcode() == txscript.OP_CHECKSIGVERIFY {
			continue
		} else {
			break
		}
	}

	// This should be the last operation
	if tokenizer.Err() != nil || tokenizer.Opcode() != txscript.OP_CHECKSIG {
		return false, nil
	}

	// Verify we found at least one public key
	if len(pubkeys) == 0 {
		return false, nil
	}

	f.PubKeys = pubkeys
	f.Type = MultisigTypeChecksig

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		f.PubKeys = nil
		f.Type = 0
		return false, err
	}

	if !bytes.Equal(rebuilt, script) {
		f.PubKeys = nil
		f.Type = 0
		return false, nil
	}

	return true, nil
}

func (f *MultisigClosure) Witness(
	controlBlock []byte, signatures map[string][]byte,
) (wire.TxWitness, error) {
	// Create witness stack with capacity for all signatures plus script and control block
	witness := make(wire.TxWitness, 0, len(f.PubKeys)+2)

	// Add signatures in the reverse order as public keys
	for i := len(f.PubKeys) - 1; i >= 0; i-- {
		pubkey := f.PubKeys[i]
		xOnlyPubkey := schnorr.SerializePubKey(pubkey)
		sig, ok := signatures[hex.EncodeToString(xOnlyPubkey)]
		if !ok {
			return nil, fmt.Errorf("missing signature for pubkey %x", xOnlyPubkey)
		}
		witness = append(witness, sig)
	}

	// Get script
	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// Add script and control block
	witness = append(witness, script)
	witness = append(witness, controlBlock)

	return witness, nil
}

// CSVMultisigClosure is a closure that contains a list of public keys and a
// CHECKSEQUENCEVERIFY. The witness size is 64 bytes per key, admitting
// the sighash type is SIGHASH_DEFAULT.
type CSVMultisigClosure struct {
	MultisigClosure
	Locktime common.RelativeLocktime
}

func (f *CSVMultisigClosure) Witness(
	controlBlock []byte, signatures map[string][]byte,
) (wire.TxWitness, error) {
	multisigWitness, err := f.MultisigClosure.Witness(controlBlock, signatures)
	if err != nil {
		return nil, err
	}

	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// replace script with csv script
	multisigWitness[len(multisigWitness)-2] = script

	return multisigWitness, nil
}

func (d *CSVMultisigClosure) Script() ([]byte, error) {
	sequence, err := common.BIP68Sequence(d.Locktime)
	if err != nil {
		return nil, err
	}

	csvScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(sequence)).
		AddOps([]byte{
			txscript.OP_CHECKSEQUENCEVERIFY,
			txscript.OP_DROP,
		}).
		Script()
	if err != nil {
		return nil, err
	}

	multisigScript, err := d.MultisigClosure.Script()
	if err != nil {
		return nil, err
	}

	return append(csvScript, multisigScript...), nil
}

func (d *CSVMultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("empty script")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, script)

	// Advance the tokenizer to the next token and extract the sequence.
	// If the opcode represents a small integer, store it as a single byte in the sequence.
	// Otherwise, extract the data directly from the tokenizer.
	if !tokenizer.Next() {
		return false, nil
	}

	var sequence []byte
	if txscript.IsSmallInt(tokenizer.Opcode()) {
		sequence = []byte{tokenizer.Opcode()}
	} else {
		sequence = tokenizer.Data()
	}

	for _, opCode := range []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP} {

		if !tokenizer.Next() || tokenizer.Opcode() != opCode {
			return false, nil
		}

	}

	locktime, err := common.BIP68DecodeSequenceFromBytes(sequence)
	if err != nil {
		return false, err
	}

	multisigClosure := &MultisigClosure{}
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := multisigClosure.Decode(subScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	d.Locktime = *locktime
	d.MultisigClosure = *multisigClosure

	return valid, nil
}

// CLTVMultisigClosure is a closure that contains a list of public keys and a
// CHECKLOCKTIMEVERIFY. The witness size is 64 bytes per key, admitting
// the sighash type is SIGHASH_DEFAULT.
type CLTVMultisigClosure struct {
	MultisigClosure
	Locktime common.AbsoluteLocktime
}

func (f *CLTVMultisigClosure) Witness(
	controlBlock []byte, signatures map[string][]byte,
) (wire.TxWitness, error) {
	multisigWitness, err := f.MultisigClosure.Witness(controlBlock, signatures)
	if err != nil {
		return nil, err
	}

	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// replace script with cltv script
	multisigWitness[len(multisigWitness)-2] = script

	return multisigWitness, nil
}

func (d *CLTVMultisigClosure) Script() ([]byte, error) {
	cltvScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(d.Locktime)).
		AddOps([]byte{
			txscript.OP_CHECKLOCKTIMEVERIFY,
			txscript.OP_DROP,
		}).
		Script()
	if err != nil {
		return nil, err
	}

	multisigScript, err := d.MultisigClosure.Script()
	if err != nil {
		return nil, err
	}

	return append(cltvScript, multisigScript...), nil
}

func (d *CLTVMultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("empty script")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, script)

	// Advance the tokenizer to the next token and extract the locktime.
	// If the opcode represents a small integer, store it as a single byte in the sequence.
	// Otherwise, extract the data directly from the tokenizer.
	if !tokenizer.Next() {
		return false, nil
	}

	var locktime []byte
	if txscript.IsSmallInt(tokenizer.Opcode()) {
		locktime = []byte{tokenizer.Opcode()}
	} else {
		locktime = tokenizer.Data()
	}

	for _, opCode := range []byte{txscript.OP_CHECKLOCKTIMEVERIFY, txscript.OP_DROP} {

		if !tokenizer.Next() || tokenizer.Opcode() != opCode {
			return false, nil
		}
	}

	var locktimeValue uint32
	// read uint32 from bytes
	if len(locktime) > 3 {
		locktimeValue = binary.LittleEndian.Uint32(locktime)
	} else if len(locktime) == 2 {
		locktimeValue = uint32(binary.LittleEndian.Uint16(locktime))
	} else if len(locktime) == 1 {
		locktimeValue = uint32(locktime[0])
	} else {
		return false, fmt.Errorf(
			"invalid locktime length: expected 1, 2 or 4 bytes, got %d", len(locktime),
		)
	}

	multisigClosure := &MultisigClosure{}
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := multisigClosure.Decode(subScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	d.Locktime = common.AbsoluteLocktime(locktimeValue)
	d.MultisigClosure = *multisigClosure

	return valid, nil
}

// ConditionMultisigClosure is a closure that contains a condition and a
// multisig closure. The condition is a boolean script that is executed with the
// multisig witness.
type ConditionMultisigClosure struct {
	MultisigClosure
	Condition []byte
}

func (f *ConditionMultisigClosure) Script() ([]byte, error) {
	scriptBuilder := txscript.NewScriptBuilder()

	scriptBuilder.AddOps(f.Condition)
	scriptBuilder.AddOp(txscript.OP_VERIFY)

	// Add the multisig script
	multisigScript, err := f.MultisigClosure.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate multisig script: %w", err)
	}
	scriptBuilder.AddOps(multisigScript)

	return scriptBuilder.Script()
}

func (f *ConditionMultisigClosure) Decode(script []byte) (bool, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	if len(tokenizer.Script()) == 0 {
		return false, fmt.Errorf("empty script")
	}

	condition := make([]byte, 0)
	for tokenizer.Next() {
		if tokenizer.Opcode() == txscript.OP_VERIFY {
			break
		} else {
			condition = append(condition, tokenizer.Opcode())
			if len(tokenizer.Data()) > 0 {
				condition = append(condition, tokenizer.Data()...)
			}
		}
	}

	f.Condition = condition

	// Decode multisig closure
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := f.MultisigClosure.Decode(subScript)
	if err != nil || !valid {
		return false, err
	}

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		return false, err
	}

	return bytes.Equal(rebuilt, script), nil
}

func (f *ConditionMultisigClosure) Witness(
	controlBlock []byte, args map[string][]byte,
) (wire.TxWitness, error) {
	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// Read and execute condition witness
	condWitness, err := txutils.ReadTxWitness(args[ConditionWitnessKey])
	if err != nil {
		return nil, fmt.Errorf("failed to read condition witness: %w", err)
	}

	returnValue, err := EvaluateScriptToBool(f.Condition, condWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to execute condition: %w", err)
	}

	if !returnValue {
		return nil, fmt.Errorf("condition evaluated to false")
	}

	// Get multisig witness
	multisigWitness, err := f.MultisigClosure.Witness(controlBlock, args)
	if err != nil {
		return nil, err
	}

	multisigWitness = multisigWitness[:len(multisigWitness)-2] // remove control block and script
	witness := append(multisigWitness, condWitness...)
	witness = append(witness, script)
	witness = append(witness, controlBlock)

	return witness, nil
}

// ConditionCSVMultisigClosure is a closure that contains a condition and a
// CSV multisig closure. The condition is a boolean script that is executed with the
// multisig witness.
type ConditionCSVMultisigClosure struct {
	CSVMultisigClosure
	Condition []byte
}

func (f *ConditionCSVMultisigClosure) Script() ([]byte, error) {
	scriptBuilder := txscript.NewScriptBuilder()

	scriptBuilder.AddOps(f.Condition)
	scriptBuilder.AddOp(txscript.OP_VERIFY)

	// Add the multisig script
	multisigScript, err := f.CSVMultisigClosure.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate multisig script: %w", err)
	}
	scriptBuilder.AddOps(multisigScript)

	return scriptBuilder.Script()
}

func (f *ConditionCSVMultisigClosure) Decode(script []byte) (bool, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	if len(tokenizer.Script()) == 0 {
		return false, fmt.Errorf("empty script")
	}

	condition := make([]byte, 0)
	for tokenizer.Next() {
		if tokenizer.Opcode() == txscript.OP_VERIFY {
			break
		} else {
			condition = append(condition, tokenizer.Opcode())
			if len(tokenizer.Data()) > 0 {
				condition = append(condition, tokenizer.Data()...)
			}
		}
	}

	f.Condition = condition

	// Decode multisig closure
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := f.CSVMultisigClosure.Decode(subScript)
	if err != nil || !valid {
		return false, err
	}

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		return false, err
	}

	return bytes.Equal(rebuilt, script), nil
}

func (f *ConditionCSVMultisigClosure) Witness(
	controlBlock []byte, args map[string][]byte,
) (wire.TxWitness, error) {
	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// Read and execute condition witness
	condWitness, err := txutils.ReadTxWitness(args[ConditionWitnessKey])
	if err != nil {
		return nil, fmt.Errorf("failed to read condition witness: %w", err)
	}

	returnValue, err := EvaluateScriptToBool(f.Condition, condWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to execute condition: %w", err)
	}

	if !returnValue {
		return nil, fmt.Errorf("condition evaluated to false")
	}

	// Get multisig witness
	multisigWitness, err := f.CSVMultisigClosure.Witness(controlBlock, args)
	if err != nil {
		return nil, err
	}

	multisigWitness = multisigWitness[:len(multisigWitness)-2] // remove control block and script
	witness := append(multisigWitness, condWitness...)
	witness = append(witness, script)
	witness = append(witness, controlBlock)

	return witness, nil
}
