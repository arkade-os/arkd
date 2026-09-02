package txutils

import (
	"bytes"
	"encoding/binary"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const ArkPsbtFieldKeyType = 222

// cosignerIndexLen is the size of the big endian index appended to a cosigner
// field key. It is the only ark field key carrying data after the field name.
const cosignerIndexLen = 4

var (
	// ArkPsbtFieldTaprootTree reveals the taproot tree associated with an input
	ArkFieldTaprootTree = []byte("taptree")
	// ArkFieldTreeExpiry attach the CSV locktime expiring a tx input
	ArkFieldTreeExpiry = []byte("expiry")
	// ArkFieldCosigner attach a musig2 cosigner public key to an unsigned tx input
	ArkFieldCosigner = []byte("cosigner")
	// ArkFieldConditionWitness allows to set extra witness elements used to sign custom script inputs
	ArkFieldConditionWitness = []byte("condition")
)

// Singletons instances for each field type
var VtxoTaprootTreeField ArkPsbtFieldCoder[TapTree] = arkPsbtFieldCoderTaprootTree{}
var VtxoTreeExpiryField ArkPsbtFieldCoder[arklib.RelativeLocktime] = arkPsbtFieldCoderTreeExpiry{}
var CosignerPublicKeyField ArkPsbtFieldCoder[IndexedCosignerPublicKey] = arkPsbtFieldCoderCosignerPublicKey{}
var ConditionWitnessField ArkPsbtFieldCoder[wire.TxWitness] = arkPsbtFieldCoderConditionWitness{}

type ArkPsbtFieldCoder[T any] interface {
	Encode(T) (*psbt.Unknown, error)
	Decode(*psbt.Unknown) (*T, error) // nil means not found
}

// SetArkPsbtField sets an ark psbt field on the given psbt at the given input index
func SetArkPsbtField[T any](ptx *psbt.Packet, inputIndex int, coder ArkPsbtFieldCoder[T], value T) error {
	if len(ptx.Inputs) <= inputIndex {
		return fmt.Errorf("input index out of bounds %d, len(inputs)=%d", inputIndex, len(ptx.Inputs))
	}

	arkField, err := coder.Encode(value)
	if err != nil {
		return err
	}
	ptx.Inputs[inputIndex].Unknowns = append(ptx.Inputs[inputIndex].Unknowns, arkField)
	return nil
}

// GetArkPsbtFields gets all ark psbt fields of the given type from the given psbt at the given input index
func GetArkPsbtFields[T any](ptx *psbt.Packet, inputIndex int, coder ArkPsbtFieldCoder[T]) ([]T, error) {
	if len(ptx.Inputs) <= inputIndex {
		return nil, fmt.Errorf("input index out of bounds %d, len(inputs)=%d", inputIndex, len(ptx.Inputs))
	}

	fieldsFound := make([]T, 0)

	for _, unknown := range ptx.Inputs[inputIndex].Unknowns {
		value, err := coder.Decode(unknown)
		if err != nil {
			return nil, err
		}
		if value == nil {
			continue
		}
		fieldsFound = append(fieldsFound, *value)
	}

	return fieldsFound, nil
}

// GetArkPsbtConditionWitness returns the condition witness set on the given
// input, or nil if the input carries none. Nil means no field was set and only
// that: a field encoding a witness with no stack items comes back as a non-nil
// empty witness, so a caller telling the two apart must compare against nil
// rather than check the length.
//
// An input may carry at most one. Consumers of a condition witness read the
// first one set, and two field encodings are accepted, so a producer setting
// both forms with different values would reveal one witness to whoever reads
// the first field and another to whoever looks only for the canonical key.
// Reject that outright instead of letting the two disagree.
func GetArkPsbtConditionWitness(ptx *psbt.Packet, inputIndex int) (wire.TxWitness, error) {
	fields, err := GetArkPsbtFields(ptx, inputIndex, ConditionWitnessField)
	if err != nil {
		return nil, err
	}

	if len(fields) > 1 {
		return nil, fmt.Errorf(
			"input %d sets %d condition witnesses, expected at most one",
			inputIndex, len(fields),
		)
	}
	if len(fields) == 0 {
		return nil, nil
	}
	return fields[0], nil
}

// ArkPsbtFieldCoder implementation for taproot tree
type arkPsbtFieldCoderTaprootTree struct{}

func (c arkPsbtFieldCoderTaprootTree) Encode(taptree TapTree) (*psbt.Unknown, error) {
	encodedTaprootTree, err := taptree.Encode()
	if err != nil {
		return nil, err
	}
	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkFieldTaprootTree),
		Value: encodedTaprootTree,
	}, nil
}

func (c arkPsbtFieldCoderTaprootTree) Decode(unknown *psbt.Unknown) (*TapTree, error) {
	if !matchesArkPsbtKey(unknown, ArkFieldTaprootTree, 0) {
		return nil, nil
	}

	taptree, err := DecodeTapTree(unknown.Value)
	if err != nil {
		return nil, err
	}
	return &taptree, nil
}

// ArkPsbtFieldCoder implementation for tree expiry
type arkPsbtFieldCoderTreeExpiry struct{}

func (c arkPsbtFieldCoderTreeExpiry) Encode(expiry arklib.RelativeLocktime) (*psbt.Unknown, error) {
	sequence, err := arklib.BIP68Sequence(expiry)
	if err != nil {
		return nil, err
	}

	// the sequence must be encoded as minimal little-endian bytes
	var sequenceLE [4]byte
	binary.LittleEndian.PutUint32(sequenceLE[:], sequence)

	// compute the minimum number of bytes needed
	numBytes := 4
	for numBytes > 1 && sequenceLE[numBytes-1] == 0 {
		numBytes-- // remove trailing zeros
	}

	// if the most significant bit of the last byte is set,
	// we need one more byte to avoid sign ambiguity
	if sequenceLE[numBytes-1]&0x80 != 0 {
		numBytes++
	}

	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkFieldTreeExpiry),
		Value: sequenceLE[:numBytes],
	}, nil
}

func (c arkPsbtFieldCoderTreeExpiry) Decode(unknown *psbt.Unknown) (*arklib.RelativeLocktime, error) {
	if !matchesArkPsbtKey(unknown, ArkFieldTreeExpiry, 0) {
		return nil, nil
	}

	return arklib.BIP68DecodeSequenceFromBytes(unknown.Value)
}

// ArkPsbtFieldCoder implementation for cosigner public key
type arkPsbtFieldCoderCosignerPublicKey struct{}

func (c arkPsbtFieldCoderCosignerPublicKey) Encode(indexedPubKey IndexedCosignerPublicKey) (*psbt.Unknown, error) {
	indexBytes := make([]byte, cosignerIndexLen)
	binary.BigEndian.PutUint32(indexBytes, uint32(indexedPubKey.Index))

	return &psbt.Unknown{
		Key:   append(makeArkPsbtKey(ArkFieldCosigner), indexBytes...),
		Value: indexedPubKey.PublicKey.SerializeCompressed(),
	}, nil
}

func (c arkPsbtFieldCoderCosignerPublicKey) Decode(unknown *psbt.Unknown) (*IndexedCosignerPublicKey, error) {
	if !matchesArkPsbtKey(unknown, ArkFieldCosigner, cosignerIndexLen) {
		return nil, nil
	}

	// last 4 bytes are the index
	indexBytes := unknown.Key[len(unknown.Key)-cosignerIndexLen:]
	index := binary.BigEndian.Uint32(indexBytes)

	publicKey, err := btcec.ParsePubKey(unknown.Value)
	if err != nil {
		return nil, err
	}

	return &IndexedCosignerPublicKey{
		Index:     int(index),
		PublicKey: publicKey,
	}, nil
}

// ArkPsbtFieldCoder implementation for condition witness
type arkPsbtFieldCoderConditionWitness struct{}

func (c arkPsbtFieldCoderConditionWitness) Encode(witness wire.TxWitness) (*psbt.Unknown, error) {
	var witnessBytes bytes.Buffer

	err := psbt.WriteTxWitness(&witnessBytes, witness)
	if err != nil {
		return nil, err
	}

	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkFieldConditionWitness),
		Value: witnessBytes.Bytes(),
	}, nil
}

func (c arkPsbtFieldCoderConditionWitness) Decode(unknown *psbt.Unknown) (*wire.TxWitness, error) {
	if !matchesArkPsbtKey(unknown, ArkFieldConditionWitness, 0) {
		return nil, nil
	}

	witness, err := ReadTxWitness(unknown.Value)
	if err != nil {
		return nil, err
	}

	return &witness, nil
}

func makeArkPsbtKey(keyData []byte) []byte {
	return append([]byte{ArkPsbtFieldKeyType}, keyData...)
}

// matchesArkPsbtKey reports whether the unknown field's key names keyFieldName,
// carrying exactly suffixLen bytes of field specific data after the name. Only
// the cosigner field uses a suffix, for its index; every other field passes 0.
func matchesArkPsbtKey(unknownField *psbt.Unknown, keyFieldName []byte, suffixLen int) bool {
	key := unknownField.Key
	if len(key) == 0 {
		return false
	}

	// Every ark field name starts with an ASCII letter, so a bare legacy key can
	// never begin with the key type byte and stripping it here is unambiguous.
	if key[0] == ArkPsbtFieldKeyType {
		key = key[1:]
	}

	if len(key) != len(keyFieldName)+suffixLen {
		return false
	}
	return bytes.Equal(key[:len(keyFieldName)], keyFieldName)
}
