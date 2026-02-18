package asset

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// AssetOutputType distinguishes how an asset output references its source.
type AssetOutputType uint8

const (
	// AssetOutputTypeUnspecified is the zero value, representing an invalid output type.
	AssetOutputTypeUnspecified AssetOutputType = iota
	// AssetOutputTypeLocal references an output of the same transaction.
	AssetOutputTypeLocal
)

// AssetOutput describes an asset amount assigned to a transaction output.
type AssetOutput struct {
	Type AssetOutputType
	// Vout is the transaction output index this asset output is assigned to.
	Vout uint16
	// Amount is the quantity of the asset assigned to this output.
	Amount uint64
}

// NewAssetOutputs creates a validated AssetOutputs list from the given slice.
func NewAssetOutputs(outs []AssetOutput) (AssetOutputs, error) {
	if len(outs) <= 0 {
		return nil, fmt.Errorf("missing asset outputs")
	}

	list := AssetOutputs(outs)
	if err := list.validate(); err != nil {
		return nil, err
	}
	return list, nil
}

// NewAssetOutputsFromString parses a hex-encoded string into an AssetOutputs list.
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

// NewAssetOutput creates a single validated AssetOutput for the given output index and amount.
func NewAssetOutput(vout uint16, amount uint64) (*AssetOutput, error) {
	out := AssetOutput{Type: AssetOutputTypeLocal, Vout: vout, Amount: amount}
	if err := out.validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// NewAssetOutputFromString parses a hex-encoded string into a single AssetOutput.
func NewAssetOutputFromString(s string) (*AssetOutput, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid asset output format, must be hex")
	}
	return NewAssetOutputFromBytes(buf)
}

// NewAssetOutputFromBytes deserializes a single AssetOutput from a raw byte slice.
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

// Serialize encodes the AssetOutput into a byte slice.
func (out AssetOutput) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if err := out.serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized AssetOutput.
func (out AssetOutput) String() string {
	buf, _ := out.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks that the output amount is greater than zero.
func (out AssetOutput) validate() error {
	if out.Amount == 0 {
		return fmt.Errorf("asset output amount must be greater than 0")
	}
	return nil
}

// serialize writes the vout and amount fields to the writer.
func (out AssetOutput) serialize(w io.Writer) error {
	if _, err := w.Write([]byte{byte(out.Type)}); err != nil {
		return err
	}
	if err := serializeUint16(w, out.Vout); err != nil {
		return err
	}
	if err := serializeVarUint(w, out.Amount); err != nil {
		return err
	}
	return nil
}

// newAssetOutputFromReader deserializes a single AssetOutput from the reader.
func newAssetOutputFromReader(r *bytes.Reader) (*AssetOutput, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	out := AssetOutput{Type: AssetOutputType(typ)}
	switch out.Type {
	case AssetOutputTypeLocal:
	case AssetOutputTypeUnspecified:
		return nil, fmt.Errorf("asset output type unspecified")
	default:
		return nil, fmt.Errorf("asset output type unknown %d", out.Type)
	}

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
	return NewAssetOutput(index, amount)
}

// AssetOutputs is an ordered list of AssetOutput that serializes with a varint length prefix.
type AssetOutputs []AssetOutput

// String returns the hex-encoded representation of the serialized output list.
func (outs AssetOutputs) String() string {
	// nolint
	buf, _ := outs.Serialize()
	return hex.EncodeToString(buf)
}

// Serialize encodes the full output list (length-prefixed) into a byte slice.
func (outs AssetOutputs) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if err := outs.serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serialize validates the list and writes the varint count followed by each output to the writer.
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

// validate ensures all outputs have unique vout values and are individually valid.
func (outs AssetOutputs) validate() error {
	m := make(map[uint16]struct{})
	for _, out := range outs {
		if _, ok := m[out.Vout]; ok {
			return fmt.Errorf("all outputs must have unique vout")
		}
		m[out.Vout] = struct{}{}

		if err := out.validate(); err != nil {
			return err
		}
	}
	return nil
}

// newAssetOutputsFromReader deserializes a length-prefixed list of AssetOutput from the reader.
func newAssetOutputsFromReader(r *bytes.Reader) (AssetOutputs, error) {
	count, err := deserializeVarUint(r)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	outputs := make(AssetOutputs, 0, count)
	for range count {
		out, err := newAssetOutputFromReader(r)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, *out)
	}
	if err := outputs.validate(); err != nil {
		return nil, err
	}
	return outputs, nil
}
