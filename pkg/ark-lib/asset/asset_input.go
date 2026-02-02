package asset

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type AssetInput struct {
	// Can be either 'local' or 'intent'
	Type AssetType
	// Always present
	Vin uint16
	// Can be empty if type is 'local'
	Txid chainhash.Hash
	// Always present
	Amount uint64
}

func NewAssetInputs(ins []AssetInput) (AssetInputs, error) {
	list := AssetInputs(ins)
	if err := list.validate(); err != nil {
		return nil, err
	}
	return list, nil
}

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

func NewAssetInput(index uint16, amount uint64) (*AssetInput, error) {
	in := AssetInput{Type: AssetTypeLocal, Vin: index, Amount: amount}
	if err := in.validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

func NewIntentAssetInput(txid string, index uint16, amount uint64) (*AssetInput, error) {
	if len(txid) <= 0 {
		return nil, fmt.Errorf("missing input intent txid")
	}
	buf, err := hex.DecodeString(txid)
	if err != nil {
		return nil, fmt.Errorf("invalid input intent txid format, must be hex")
	}
	if len(buf) != chainhash.HashSize {
		return nil, fmt.Errorf("invalid input intent txid length")
	}
	in := AssetInput{
		Type:   AssetTypeIntent,
		Vin:    index,
		Txid:   chainhash.Hash(buf),
		Amount: amount,
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

func NewAssetInputFromString(s string) (*AssetInput, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid format, must be hex")
	}
	return NewAssetInputFromBytes(buf)
}

func NewAssetInputFromBytes(buf []byte) (*AssetInput, error) {
	r := bytes.NewReader(buf)
	return newAssetInputFromReader(r)
}

func (in AssetInput) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := in.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (in AssetInput) String() string {
	// nolint
	buf, _ := in.Serialize()
	return hex.EncodeToString(buf)
}

func (in AssetInput) validate() error {
	switch in.Type {
	case AssetTypeLocal:
		// nothing to do
		return nil
	case AssetTypeIntent:
		if bytes.Equal(in.Txid[:], make([]byte, chainhash.HashSize)) {
			return fmt.Errorf("missing input intent txid")
		}
		return nil
	case AssetTypeUnspecified:
		return fmt.Errorf("asset input type unspecified")
	default:
		return fmt.Errorf("asset input type %d unknown", in.Type)
	}
}

func (in AssetInput) serialize(w io.Writer) error {
	if _, err := w.Write([]byte{byte(in.Type)}); err != nil {
		return err
	}
	switch in.Type {
	case AssetTypeLocal:
		if err := serializeUint16(w, in.Vin); err != nil {
			return err
		}
		if err := serializeVarUint(w, in.Amount); err != nil {
			return err
		}
	case AssetTypeIntent:
		if err := serializeSlice(w, in.Txid[:]); err != nil {
			return err
		}
		if err := serializeUint16(w, in.Vin); err != nil {
			return err
		}
		if err := serializeVarUint(w, in.Amount); err != nil {
			return err
		}
	case AssetTypeUnspecified:
		return fmt.Errorf("asset input type unspecified")
	default:
		return fmt.Errorf("asset input type %d unknown", in.Type)
	}
	return nil
}

type AssetInputs []AssetInput

func (ins AssetInputs) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	if err := ins.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (ins AssetInputs) String() string {
	// nolint
	buf, _ := ins.Serialize()
	return hex.EncodeToString(buf)
}

func (ins AssetInputs) validate() error {
	m := make(map[uint16]struct{})
	var inType AssetType
	for _, in := range ins {
		if _, ok := m[in.Vin]; ok {
			return fmt.Errorf("duplicated input vin %d", in.Vin)
		}
		m[in.Vin] = struct{}{}

		if inType == AssetTypeUnspecified {
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

func newAssetInputFromReader(r *bytes.Reader) (*AssetInput, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	in := AssetInput{Type: AssetType(typ)}
	switch in.Type {
	case AssetTypeLocal:
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
	case AssetTypeIntent:
		txid, err := deserializeSlice(r, chainhash.HashSize)
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
		in.Txid = chainhash.Hash(txid)
		in.Vin = index
		in.Amount = amount
	case AssetTypeUnspecified:
		return nil, fmt.Errorf("asset input type unspecified")
	default:
		return nil, fmt.Errorf("asset input type %d unknown", in.Type)
	}

	if err := in.validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

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
