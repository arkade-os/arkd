package txutils

import (
	"bytes"
	"encoding/binary"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

const ArkPsbtFieldKeyType = 222

var (
	// ArkPsbtFieldTaprootTree reveals the taproot tree associated with an input
	ArkFieldTaprootTree = []byte("taptree")
	// ArkFieldTreeExpiry attach the CSV locktime expiring a tx input
	ArkFieldTreeExpiry = []byte("expiry")
	// ArkFieldCosigner attach a musig2 cosigner public key to an unsigned tx input
	ArkFieldCosigner = []byte("cosigner")
	// ArkFieldConditionWitness allows to set extra witness elements used to sign custom script inputs
	ArkFieldConditionWitness = []byte("condition")
	// ArkAssetSealVtxoField marks an input as an asset seal input
	ArkAssetSealVtxoField = []byte("asset_seal")
)

// Singletons instances for each field type
var VtxoTaprootTreeField ArkPsbtFieldCoder[TapTree] = arkPsbtFieldCoderTaprootTree{}
var VtxoTreeExpiryField ArkPsbtFieldCoder[arklib.RelativeLocktime] = arkPsbtFieldCoderTreeExpiry{}
var CosignerPublicKeyField ArkPsbtFieldCoder[IndexedCosignerPublicKey] = arkPsbtFieldCoderCosignerPublicKey{}
var ConditionWitnessField ArkPsbtFieldCoder[wire.TxWitness] = arkPsbtFieldCoderConditionWitness{}
var AssetSealVtxoField ArkPsbtFieldCoder[bool] = arkPsbtFieldCoderAssetSealVtxo{}

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
	if !containsArkPsbtKey(unknown, ArkFieldTaprootTree) {
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
	if !containsArkPsbtKey(unknown, ArkFieldTreeExpiry) {
		return nil, nil
	}

	return arklib.BIP68DecodeSequenceFromBytes(unknown.Value)
}

// ArkPsbtFieldCoder implementation for cosigner public key
type arkPsbtFieldCoderCosignerPublicKey struct{}

func (c arkPsbtFieldCoderCosignerPublicKey) Encode(indexedPubKey IndexedCosignerPublicKey) (*psbt.Unknown, error) {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, uint32(indexedPubKey.Index))

	return &psbt.Unknown{
		Key:   append(makeArkPsbtKey(ArkFieldCosigner), indexBytes...),
		Value: indexedPubKey.PublicKey.SerializeCompressed(),
	}, nil
}

func (c arkPsbtFieldCoderCosignerPublicKey) Decode(unknown *psbt.Unknown) (*IndexedCosignerPublicKey, error) {
	if !containsArkPsbtKey(unknown, ArkFieldCosigner) {
		return nil, nil
	}

	// last 4 bytes are the index
	indexBytes := unknown.Key[len(unknown.Key)-4:]
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
	if !containsArkPsbtKey(unknown, ArkFieldConditionWitness) {
		return nil, nil
	}

	witness, err := ReadTxWitness(unknown.Value)
	if err != nil {
		return nil, err
	}

	return &witness, nil
}

type arkPsbtFieldCoderAssetSealVtxo struct{}

func (c arkPsbtFieldCoderAssetSealVtxo) Encode(isSeal bool) (*psbt.Unknown, error) {
	var value byte
	if isSeal {
		value = 1
	} else {
		value = 0
	}
	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkAssetSealVtxoField),
		Value: []byte{value},
	}, nil
}

func (c arkPsbtFieldCoderAssetSealVtxo) Decode(unknown *psbt.Unknown) (*bool, error) {
	if !containsArkPsbtKey(unknown, ArkAssetSealVtxoField) {
		return nil, nil
	}

	if len(unknown.Value) != 1 {
		return nil, fmt.Errorf("invalid asset seal vtxo field length: %d", len(unknown.Value))
	}

	isSeal := unknown.Value[0] != 0
	return &isSeal, nil
}

func makeArkPsbtKey(keyData []byte) []byte {
	return append([]byte{ArkPsbtFieldKeyType}, keyData...)
}

func containsArkPsbtKey(unknownField *psbt.Unknown, keyFieldName []byte) bool {
	if len(unknownField.Key) == 0 {
		return false
	}

	// TODO: uncomment key type check once all client migrated to proper PSBT key encoding
	// 		not checking the key type is relatively safe because ark transactions shouldn't have other unknown fields
	// 		however, safer to make sure the key type is correct in case we conflict with other protocols using unknown fields

	// keyType := unknownField.Key[0]
	// if keyType != ArkPsbtFieldKeyType {
	// 	return false
	// }

	return bytes.Contains(unknownField.Key, keyFieldName)
}
