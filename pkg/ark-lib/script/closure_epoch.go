package script

import (
	"bytes"
	"fmt"
	"math"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// CLTVCSVMultisigClosure is the operator's epoch sweep closure. It requires both
// an absolute date (ExpiryDate, shared by every batch in the epoch) and a
// relative delay since the spent output appeared (UnrollGrace).
//
// For an untouched batch node the relative delay is satisfied long before the
// date, so the output matures at exactly ExpiryDate and the whole epoch can be
// swept in one transaction. For a node created by a mid-flight unilateral unroll
// at time u it matures at max(ExpiryDate, u+UnrollGrace), which hands the exiting
// user UnrollGrace per tree level without needing a different script per level.
//
// This closure is only ever used in the sweep leaf. It must never appear in a
// user's vtxo script, where ForfeitClosures/ExitClosures would not classify it.
type CLTVCSVMultisigClosure struct {
	MultisigClosure
	ExpiryDate  arklib.AbsoluteLocktime
	UnrollGrace arklib.RelativeLocktime
}

func (d *CLTVCSVMultisigClosure) Script() ([]byte, error) {
	sequence, err := arklib.BIP68Sequence(d.UnrollGrace)
	if err != nil {
		return nil, err
	}

	prefix, err := txscript.NewScriptBuilder().
		AddInt64(int64(d.ExpiryDate)).
		AddOps([]byte{txscript.OP_CHECKLOCKTIMEVERIFY, txscript.OP_DROP}).
		AddInt64(int64(sequence)).
		AddOps([]byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP}).
		Script()
	if err != nil {
		return nil, err
	}

	multisigScript, err := d.MultisigClosure.Script()
	if err != nil {
		return nil, err
	}

	return append(prefix, multisigScript...), nil
}

func (d *CLTVCSVMultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("empty script")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, script)

	// Absolute locktime. Kept as int64 throughout: an nLockTime timestamp exceeds
	// int32 in 2038, and CLTVMultisigClosure.Decode narrows there.
	if !tokenizer.Next() {
		return false, nil
	}

	var locktime int64
	if txscript.IsSmallInt(tokenizer.Opcode()) {
		locktime = int64(txscript.AsSmallInt(tokenizer.Opcode()))
	} else {
		num, err := txscript.MakeScriptNum(tokenizer.Data(), true, 6)
		if err != nil {
			return false, err
		}
		locktime = int64(num)
		if locktime > 0 && locktime <= 16 {
			return false, fmt.Errorf(
				"expected minimal encoding OP_%d for locktime value %d", locktime, locktime,
			)
		}
	}
	if locktime < 0 || locktime > math.MaxUint32 {
		return false, fmt.Errorf("locktime %d out of uint32 range", locktime)
	}

	for _, opCode := range []byte{txscript.OP_CHECKLOCKTIMEVERIFY, txscript.OP_DROP} {
		if !tokenizer.Next() || tokenizer.Opcode() != opCode {
			return false, nil
		}
	}

	// Relative locktime.
	if !tokenizer.Next() {
		return false, nil
	}

	var sequence []byte
	if txscript.IsSmallInt(tokenizer.Opcode()) {
		if tokenizer.Opcode() == txscript.OP_0 {
			// minimal encoding policy forces an empty byte slice for OP_0
			sequence = []byte{}
		} else {
			sequence = []byte{tokenizer.Opcode() - (txscript.OP_1 - 1)}
		}
	} else {
		sequence = tokenizer.Data()
	}

	for _, opCode := range []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP} {
		if !tokenizer.Next() || tokenizer.Opcode() != opCode {
			return false, nil
		}
	}

	grace, err := arklib.BIP68DecodeSequenceFromBytes(sequence)
	if err != nil {
		return false, err
	}
	if grace == nil {
		return false, fmt.Errorf("failed to decode sequence: locktime is nil")
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

	d.ExpiryDate = arklib.AbsoluteLocktime(locktime)
	d.UnrollGrace = *grace
	d.MultisigClosure = *multisigClosure

	// Same rebuild-and-compare guard the other closures use: reject anything that
	// parses but would not re-serialise identically.
	rebuilt, err := d.Script()
	if err != nil {
		return false, err
	}
	if !bytes.Equal(rebuilt, script) {
		return false, nil
	}

	return true, nil
}

func (f *CLTVCSVMultisigClosure) Witness(
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

	// replace the bare multisig script with the full hybrid script
	multisigWitness[len(multisigWitness)-2] = script

	return multisigWitness, nil
}
