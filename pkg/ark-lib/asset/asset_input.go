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

type AssetInputType uint8

const (
	AssetInputTypeUnspecified AssetInputType = iota
	AssetInputTypeLocal
	AssetInputTypeIntent
)

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

type AssetInput struct {
	// Can be either 'local' or 'intent'
	Type AssetInputType
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
	in := AssetInput{Type: AssetInputTypeLocal, Vin: index, Amount: amount}
	if err := in.validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

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
