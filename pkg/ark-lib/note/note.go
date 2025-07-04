package note

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/bip322"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	preimageSize            = 32
	noteHRP                 = "arknote"
	fakeOutpointOutputIndex = uint32(0)
)

// Note contains the data of a note
type Note struct {
	Preimage [preimageSize]byte
	Value    uint32
}

// NewNote generate a new note data struct with a random preimage and the given value
func NewNote(value uint32) (*Note, error) {
	randomPreimage := make([]byte, preimageSize)
	_, err := rand.Read(randomPreimage)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random preimage: %w", err)
	}
	var preimageArray [preimageSize]byte
	copy(preimageArray[:], randomPreimage)

	return &Note{
		Preimage: preimageArray,
		Value:    value,
	}, nil
}

// NewNoteFromString converts a base58 encoded string with HRP to a Note
func NewNoteFromString(s string) (*Note, error) {
	if !strings.HasPrefix(s, noteHRP) {
		return nil, fmt.Errorf(
			"invalid human-readable part: expected %s prefix (note '%s')", noteHRP, s,
		)
	}

	encoded := strings.TrimPrefix(s, noteHRP)
	decoded := base58.Decode(encoded)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("failed to decode base58 string")
	}

	note := &Note{}
	err := note.Deserialize(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize note: %w", err)
	}

	return note, nil
}

// Serialize converts Note's data to a byte slice
func (n *Note) Serialize() []byte {
	buf := make([]byte, preimageSize+4)
	copy(buf[:preimageSize], n.Preimage[:])
	binary.BigEndian.PutUint32(buf[preimageSize:], n.Value)
	return buf
}

// Deserialize converts a byte slice to Data
func (n *Note) Deserialize(data []byte) error {
	if len(data) != preimageSize+4 {
		return fmt.Errorf(
			"invalid data length: expected %d bytes, got %d", preimageSize+4, len(data),
		)
	}

	copy(n.Preimage[:], data[:preimageSize])
	n.Value = binary.BigEndian.Uint32(data[preimageSize:])
	return nil
}

// String converts the Note to a base58 encoded string with HRP
func (n Note) String() string {
	return noteHRP + base58.Encode(n.Serialize())
}

func (n Note) PreimageHash() [preimageSize]byte {
	return sha256.Sum256(n.Preimage[:])
}

func (n Note) VtxoScript() script.TapscriptsVtxoScript {
	// this vtxo script is not valid because it doesn't contain any CHECKSIG
	// Validate() will always fail
	// that's not a problem because none of the real vtxos will be locked by that script
	// it's a way to allow fake "note vtxo" to be standard in the bip322 proof
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{&NoteClosure{PreimageHash: n.PreimageHash()}},
	}
}

func (n Note) BIP322Input() (*bip322.Input, error) {
	vtxoScript := n.VtxoScript()
	taprootKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to get taproot key: %w", err)
	}

	p2trPkScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get p2tr pk script: %w", err)
	}

	return &bip322.Input{
		OutPoint: &wire.OutPoint{
			Hash:  n.PreimageHash(),
			Index: fakeOutpointOutputIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		WitnessUtxo: &wire.TxOut{
			PkScript: p2trPkScript,
			Value:    int64(n.Value),
		},
	}, nil
}

// implements tree.Closure interface,
// can't be used in a classic vtxo script but only in the fake vtxo note script
type NoteClosure struct {
	PreimageHash [preimageSize]byte
}

// Script returns the tapscript for the note closure
func (n *NoteClosure) Script() ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_SHA256).
		AddData(n.PreimageHash[:]).
		AddOp(txscript.OP_EQUAL).
		Script()
}

// Decode attempts to decode a script into a NoteClosure
func (n *NoteClosure) Decode(script []byte) (bool, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_SHA256 {
		return false, nil
	}

	if !tokenizer.Next() || len(tokenizer.Data()) != 32 {
		return false, nil
	}
	copy(n.PreimageHash[:], tokenizer.Data())

	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_EQUAL {
		return false, nil
	}

	if tokenizer.Next() {
		return false, nil
	}

	rebuiltScript, err := n.Script()
	if err != nil {
		return false, fmt.Errorf("failed to rebuild script: %w", err)
	}

	if !bytes.Equal(rebuiltScript, script) {
		return false, nil
	}
	return true, nil
}

// Witness returns the witness stack for spending the fake vtxo note
func (n *NoteClosure) Witness(controlBlock []byte, opts map[string][]byte) (wire.TxWitness, error) {
	preimage, ok := opts["preimage"]
	if !ok {
		return nil, fmt.Errorf("missing preimage for hash %x", n.PreimageHash)
	}

	script, err := n.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	return wire.TxWitness{preimage, script, controlBlock}, nil
}
