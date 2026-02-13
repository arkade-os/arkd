package asset

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// AssetInputType distinguishes how an asset input references its source.
type AssetInputType uint8

const (
	// AssetInputTypeUnspecified is the zero value, representing an invalid input type.
	AssetInputTypeUnspecified AssetInputType = iota
	// AssetInputTypeLocal references an input of the same transaction.
	AssetInputTypeLocal
	// AssetInputTypeIntent references an input from an external (intent) transaction.
	AssetInputTypeIntent
)

// String returns the human-readable name of the input type ("local", "intent", or "unspecified").
func (t AssetInputType) String() string {
	switch t {
	case AssetInputTypeLocal:
		return "local"
	case AssetInputTypeIntent:
		return "intent"
	default:
		return "unspecified"
	}
}

// AssetInput describes an asset amount consumed from a transaction input.
type AssetInput struct {
	// Type is the input kind, either 'local' (referencing a tx input) or 'intent' (referencing an external tx).
	Type AssetInputType
	// Vin is the transaction input index this asset input refers to.
	Vin uint16
	// Txid is the hash of the referenced transaction. Only set when Type is 'intent'; empty for 'local' inputs.
	Txid chainhash.Hash
	// Amount is the quantity of the asset consumed by this input.
	Amount uint64
}

// NewAssetInputs creates a validated AssetInputs list from the given slice.
func NewAssetInputs(ins []AssetInput) (AssetInputs, error) {
	list := AssetInputs(ins)
	if err := list.validate(); err != nil {
		return nil, err
	}
	return list, nil
}

// NewAssetInputsFromString parses a hex-encoded string into an AssetInputs list.
func NewAssetInputsFromString(s string) (AssetInputs, error) {
	if len(s) <= 0 {
		return nil, fmt.Errorf("missing asset inputs")
	}
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset inputs format, must be hex")
	}
	return newAssetInputsFromReader(bytes.NewReader(buf))
}

// NewAssetInput creates a local asset input for the given transaction input index and amount.
func NewAssetInput(index uint16, amount uint64) (*AssetInput, error) {
	in := AssetInput{Type: AssetInputTypeLocal, Vin: index, Amount: amount}
	if err := in.validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

// NewIntentAssetInput creates an intent asset input referencing an external transaction
// by its hex-encoded txid, input index, and amount.
func NewIntentAssetInput(txid string, index uint16, amount uint64) (*AssetInput, error) {
	if len(txid) <= 0 {
		return nil, fmt.Errorf("missing input intent txid")
	}

	if len(txid) != chainhash.HashSize * 2 {
		return nil, fmt.Errorf("invalid input intent txid length, got %d want %d", len(txid), chainhash.HashSize * 2)
	}

	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		if strings.Contains(err.Error(), "encoding/hex") {
			return nil, fmt.Errorf("invalid input intent txid format")
		}
		if errors.Is(err, chainhash.ErrHashStrSize) {
			return nil, fmt.Errorf("invalid input intent txid length")
		}
		return nil, err
	}
	
	in := AssetInput{
		Type:   AssetInputTypeIntent,
		Vin:    index,
		Txid:   *txhash,
		Amount: amount,
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

// NewAssetInputFromString parses a hex-encoded string into a single AssetInput.
func NewAssetInputFromString(s string) (*AssetInput, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid format, must be hex")
	}
	return NewAssetInputFromBytes(buf)
}

// NewAssetInputFromBytes deserializes a single AssetInput from a raw byte slice.
func NewAssetInputFromBytes(buf []byte) (*AssetInput, error) {
	r := bytes.NewReader(buf)
	return newAssetInputFromReader(r)
}

// Serialize encodes the AssetInput into a byte slice.
func (in AssetInput) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := in.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized AssetInput.
func (in AssetInput) String() string {
	// nolint
	buf, _ := in.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks the AssetInput type is specified and, for intent inputs, that the txid is non-empty.
func (in AssetInput) validate() error {
	switch in.Type {
	case AssetInputTypeLocal:
		// nothing to do
		return nil
	case AssetInputTypeIntent:
		if bytes.Equal(in.Txid[:], make([]byte, chainhash.HashSize)) {
			return fmt.Errorf("missing input intent txid")
		}
		return nil
	case AssetInputTypeUnspecified:
		return fmt.Errorf("asset input type unspecified")
	default:
		return fmt.Errorf("asset input type %d unknown", in.Type)
	}
}

// serialize writes the AssetInput type byte and type-specific fields to the writer.
func (in AssetInput) serialize(w io.Writer) error {
	if _, err := w.Write([]byte{byte(in.Type)}); err != nil {
		return err
	}
	switch in.Type {
	case AssetInputTypeLocal:
		if err := serializeUint16(w, in.Vin); err != nil {
			return err
		}
		if err := serializeVarUint(w, in.Amount); err != nil {
			return err
		}
	case AssetInputTypeIntent:
		if err := serializeTxHash(w, in.Txid); err != nil {
			return err
		}
		if err := serializeUint16(w, in.Vin); err != nil {
			return err
		}
		if err := serializeVarUint(w, in.Amount); err != nil {
			return err
		}
	case AssetInputTypeUnspecified:
		return fmt.Errorf("asset input type unspecified")
	default:
		return fmt.Errorf("asset input type %d unknown", in.Type)
	}
	return nil
}

// AssetInputs is an ordered list of AssetInput that serializes with a varint length prefix.
type AssetInputs []AssetInput

// Serialize encodes the full input list (length-prefixed) into a byte slice.
func (ins AssetInputs) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := ins.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized input list.
func (ins AssetInputs) String() string {
	// nolint
	buf, _ := ins.Serialize()
	return hex.EncodeToString(buf)
}

// validate ensures all inputs share the same type, have unique vin values, and are individually valid.
func (ins AssetInputs) validate() error {
	m := make(map[uint16]struct{})
	var inType AssetInputType
	for _, in := range ins {
		if _, ok := m[in.Vin]; ok {
			return fmt.Errorf("duplicated input vin %d", in.Vin)
		}
		m[in.Vin] = struct{}{}

		if inType == AssetInputTypeUnspecified {
			inType = in.Type
		}
		if in.Type != inType {
			return fmt.Errorf("all inputs must be of the same type")
		}
		if err := in.validate(); err != nil {
			return err
		}
	}
	return nil
}

// serialize writes the varint count followed by each serialized input to the writer.
func (ins AssetInputs) serialize(w io.Writer) error {
	if err := serializeVarUint(w, uint64(len(ins))); err != nil {
		return err
	}
	for _, in := range ins {
		if err := in.serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// newAssetInputFromReader deserializes a single AssetInput from the reader.
func newAssetInputFromReader(r *bytes.Reader) (*AssetInput, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	in := AssetInput{Type: AssetInputType(typ)}
	switch in.Type {
	case AssetInputTypeLocal:
		index, err := deserializeUint16(r)
		if err != nil {
			return nil, err
		}
		amount, err := deserializeVarUint(r)
		if err != nil {
			return nil, err
		}
		in.Vin = index
		in.Amount = amount
	case AssetInputTypeIntent:
		txid, err := deserializeTxHash(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("invalid input intent txid length")
			}
			return nil, err
		}
		index, err := deserializeUint16(r)
		if err != nil {
			return nil, err
		}
		amount, err := deserializeVarUint(r)
		if err != nil {
			return nil, err
		}
		in.Txid = txid
		in.Vin = index
		in.Amount = amount
	case AssetInputTypeUnspecified:
		return nil, fmt.Errorf("asset input type unspecified")
	default:
		return nil, fmt.Errorf("asset input type %d unknown", in.Type)
	}

	if err := in.validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

// newAssetInputsFromReader deserializes a length-prefixed list of AssetInput from the reader.
func newAssetInputsFromReader(r *bytes.Reader) ([]AssetInput, error) {
	count, err := deserializeVarUint(r)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	inputs := make([]AssetInput, 0, count)
	for range count {
		in, err := newAssetInputFromReader(r)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, *in)
	}
	return inputs, nil
}
