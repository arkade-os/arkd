package asset

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type AssetOutput struct {
	Type   AssetType
	Vout   uint16
	Amount uint64
}

func NewAssetOutputs(outs []AssetOutput) (AssetOutputs, error) {
	list := AssetOutputs(outs)
	if err := list.validate(); err != nil {
		return nil, err
	}
	return list, nil
}

func NewAssetOutputsFromString(s string) (AssetOutputs, error) {
	if len(s) <= 0 {
		return nil, fmt.Errorf("missing asset outputs")
	}
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset outputs format, must be hex")
	}
	return newAssetOutputsFromReader(bytes.NewReader(buf))
}

func NewAssetOutput(vout uint16, amount uint64) (*AssetOutput, error) {
	out := AssetOutput{Type: AssetTypeLocal, Vout: vout, Amount: amount}
	if err := out.validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

func NewAssetOutputFromString(s string) (*AssetOutput, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset output format, must be hex")
	}
	return NewAssetOutputFromBytes(buf)
}

func NewAssetOutputFromBytes(buf []byte) (*AssetOutput, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing asset output")
	}

	r := bytes.NewReader(buf)
	out, err := newAssetOutputFromReader(r)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (out AssetOutput) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if err := out.serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (out AssetOutput) String() string {
	buf, _ := out.Serialize()
	return hex.EncodeToString(buf)
}

func (out AssetOutput) validate() error {
	switch out.Type {
	case AssetTypeUnspecified:
		return fmt.Errorf("asset output type unspecified")
	case AssetTypeLocal:
		return nil
	case AssetTypeIntent:
		return fmt.Errorf("asset output type not supported %d", out.Type)
	default:
		return fmt.Errorf("asset output type unknown %d", out.Type)
	}
}

func (out AssetOutput) serialize(w io.Writer) error {
	if _, err := w.Write([]byte{byte(out.Type)}); err != nil {
		return err
	}
	switch out.Type {
	case AssetTypeLocal:
		if err := serializeUint16(w, out.Vout); err != nil {
			return err
		}
		if err := serializeVarUint(w, out.Amount); err != nil {
			return err
		}
	case AssetTypeIntent:
		return fmt.Errorf("asset output type not supported %d", out.Type)
	case AssetTypeUnspecified:
		return fmt.Errorf("asset output type unspecified")
	default:
		return fmt.Errorf("asset output type unknown %d", out.Type)
	}
	return nil
}

func newAssetOutputFromReader(r *bytes.Reader) (*AssetOutput, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	out := AssetOutput{Type: AssetType(typ)}
	switch out.Type {
	case AssetTypeLocal:
		index, err := deserializeUint16(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("invalid asset output vout length")
			}
			return nil, err
		}
		amount, err := deserializeVarUint(r)
		if err != nil {
			return nil, err
		}
		out.Vout = index
		out.Amount = amount
	case AssetTypeIntent:
		return nil, fmt.Errorf("asset output type not supported %d", out.Type)
	case AssetTypeUnspecified:
		return nil, fmt.Errorf("asset output type unspecified")
	default:
		return nil, fmt.Errorf("asset output type unknown %d", out.Type)
	}

	if err := out.validate(); err != nil {
		return nil, err
	}

	return &out, nil
}

type AssetOutputs []AssetOutput

func (outs AssetOutputs) String() string {
	// nolint
	buf, _ := outs.Serialize()
	return hex.EncodeToString(buf)
}

func (outs AssetOutputs) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if err := outs.serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (outs AssetOutputs) serialize(w io.Writer) error {
	if err := outs.validate(); err != nil {
		return err
	}

	if err := serializeVarUint(w, uint64(len(outs))); err != nil {
		return err
	}
	for _, out := range outs {
		if err := out.serialize(w); err != nil {
			return err
		}
	}
	return nil
}

func (outs AssetOutputs) validate() error {
	m := make(map[uint16]struct{})
	var outType AssetType
	for _, out := range outs {
		if _, ok := m[out.Vout]; ok {
			return fmt.Errorf("duplicated output vout %d", out.Vout)
		}
		m[out.Vout] = struct{}{}

		if outType == AssetTypeUnspecified {
			outType = out.Type
		}
		if out.Type != outType {
			return fmt.Errorf("all outputs must be of the same type")
		}
		if err := out.validate(); err != nil {
			return err
		}
	}

	return nil
}

func newAssetOutputsFromReader(r *bytes.Reader) ([]AssetOutput, error) {
	count, err := deserializeVarUint(r)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	outputs := make([]AssetOutput, 0, count)
	for range count {
		out, err := newAssetOutputFromReader(r)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, *out)
	}
	return outputs, nil
}
