package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	// Presence byte masks
	maskAssetId      uint8 = 1 << 0 // 0x01
	maskControlAsset uint8 = 1 << 1 // 0x02
	maskMetadata     uint8 = 1 << 2 // 0x04
)

// AssetGroup represents a set of inputs and outputs for a single asset within a packet.
// It can represent an issuance (no AssetId), a transfer, a reissuance, or a burn (no outputs).
type AssetGroup struct {
	// AssetId identifies the asset. Nil when the group represents a new issuance
	// (the id is derived from the transaction hash and group index).
	AssetId *AssetId
	// ControlAsset references the control asset that authorizes reissuance (optional).
	// Only valid for issuances; must be nil for all other group types.
	ControlAsset *AssetRef
	// Outputs lists the asset amounts assigned to transaction outputs. Can be empty for burns.
	Outputs []AssetOutput
	// Inputs lists the asset amounts consumed from transaction inputs. Empty for issuances.
	Inputs []AssetInput
	// Metadata holds arbitrary key-value pairs attached to the asset group.
	Metadata []Metadata
}

// NewAssetGroup creates a new asset group and validates it.
func NewAssetGroup(
	assetId *AssetId, controlAsset *AssetRef, ins []AssetInput, outs []AssetOutput, md []Metadata,
) (*AssetGroup, error) {
	ag := AssetGroup{
		AssetId:      assetId,
		ControlAsset: controlAsset,
		Outputs:      outs,
		Inputs:       ins,
		Metadata:     md,
	}
	if err := ag.validate(); err != nil {
		return nil, err
	}
	return &ag, nil
}

// NewAssetGroupFromString creates a new asset group from its hex-encoded serialization.
func NewAssetGroupFromString(s string) (*AssetGroup, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid format, must be hex")
	}
	return NewAssetGroupFromBytes(buf)
}

// NewAssetGroupFromBytes creates a new asset group from its raw serialization in bytes.
func NewAssetGroupFromBytes(buf []byte) (*AssetGroup, error) {
	if len(buf) <= 0 {
		return nil, fmt.Errorf("missing asset group")
	}
	r := bytes.NewReader(buf)
	return newAssetGroupFromReader(r)
}

// IsIssuance returns true when the group has no AssetId, meaning it creates a new asset.
func (ag AssetGroup) IsIssuance() bool {
	return ag.AssetId == nil
}

// IsReissuance returns whether the group is a reissuance by comparing the sum of inputs and
// outputs. A reissuance is a group that is not an issuance and where sum(outputs) > sum(inputs).
func (ag AssetGroup) IsReissuance() bool {
	outAmounts := make([]uint64, len(ag.Outputs))
	inAmounts := make([]uint64, len(ag.Inputs))
	for i, out := range ag.Outputs {
		outAmounts[i] = out.Amount
	}
	for i, in := range ag.Inputs {
		inAmounts[i] = in.Amount
	}
	sumOutputs := safeSumUint64(outAmounts)
	sumInputs := safeSumUint64(inAmounts)

	return !ag.IsIssuance() && sumInputs.Cmp(sumOutputs) < 0
}

// Serialize validates the asset group and returns its raw byte serialization.
func (ag AssetGroup) Serialize() ([]byte, error) {
	if err := ag.validate(); err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(nil)
	if err := ag.serialize(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// String returns the hex-encoded representation of the serialized AssetGroup.
func (ag AssetGroup) String() string {
	// nolint
	buf, _ := ag.Serialize()
	return hex.EncodeToString(buf)
}

// validate checks that the group's fields are consistent (e.g. issuances have no inputs,
// non-issuances have no control asset) and that all nested elements are valid.
func (ag AssetGroup) validate() error {
	if ag.AssetId == nil && len(ag.Inputs) <= 0 && len(ag.Outputs) <= 0 {
		return fmt.Errorf("empty asset group")
	}

	if ag.AssetId != nil {
		if err := ag.AssetId.validate(); err != nil {
			return err
		}
	}
	if ag.ControlAsset != nil {
		if err := ag.ControlAsset.validate(); err != nil {
			return err
		}
	}

	if ag.IsIssuance() {
		if len(ag.Inputs) != 0 {
			return fmt.Errorf("issuance must have no inputs")
		}
	} else {
		if ag.ControlAsset != nil {
			return fmt.Errorf("only issuance can have a control asset")
		}
	}

	for _, in := range ag.Inputs {
		if err := in.validate(); err != nil {
			return err
		}
	}
	for _, out := range ag.Outputs {
		if err := out.validate(); err != nil {
			return err
		}
	}
	for _, md := range ag.Metadata {
		if err := md.validate(); err != nil {
			return err
		}
	}
	return nil
}

// serialize writes the presence byte, optional fields, inputs, and outputs to the writer.
func (ag AssetGroup) serialize(w io.Writer) error {
	// 1. Calculate and write Presence Byte
	var presence uint8
	if ag.AssetId != nil {
		presence |= maskAssetId
	}
	if ag.ControlAsset != nil {
		presence |= maskControlAsset
	}
	if len(ag.Metadata) > 0 {
		presence |= maskMetadata
	}
	if _, err := w.Write([]byte{presence}); err != nil {
		return err
	}

	// 2. Write fields in fixed order based on presence

	// AssetId
	if (presence & maskAssetId) != 0 {
		if err := ag.AssetId.serialize(w); err != nil {
			return err
		}
	}

	// ControlAsset
	if (presence & maskControlAsset) != 0 {
		if err := ag.ControlAsset.serialize(w); err != nil {
			return err
		}
	}

	// Metadata
	if (presence & maskMetadata) != 0 {
		if err := metadataList(ag.Metadata).serialize(w); err != nil {
			return err
		}
	}

	// Immutable: No payload, presence bit is the value (true).

	// 3. Inputs
	if err := AssetInputs(ag.Inputs).serialize(w); err != nil {
		return err
	}

	// 4. Outputs
	if err := AssetOutputs(ag.Outputs).serialize(w); err != nil {
		return err
	}

	return nil
}

// toBatchLeafAssetGroup converts the group into its batch-leaf form by replacing the
// inputs with a single intent input referencing the given transaction hash.
func (ag AssetGroup) toBatchLeafAssetGroup(intentTxid chainhash.Hash) AssetGroup {
	return AssetGroup{
		AssetId:      ag.AssetId,
		Outputs:      ag.Outputs,
		ControlAsset: ag.ControlAsset,
		Metadata:     ag.Metadata,
		Inputs: []AssetInput{{
			Type: AssetInputTypeIntent,
			Txid: intentTxid,
		}},
	}
}

// newAssetGroupFromReader deserializes an AssetGroup by reading the presence byte,
// optional fields, inputs, and outputs from the reader.
func newAssetGroupFromReader(r *bytes.Reader) (*AssetGroup, error) {
	// 1. Read Presence Byte
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	var assetId *AssetId
	var controlAsset *AssetRef
	var metadata []Metadata
	// 2. Read fields

	// AssetId
	if (presence & maskAssetId) != 0 {
		assetId, err = newAssetIdFromReader(r)
		if err != nil {
			return nil, err
		}
	}

	// ControlAsset
	if (presence & maskControlAsset) != 0 {
		controlAsset, err = newAssetRefFromReader(r)
		if err != nil {
			return nil, err
		}
	}

	// Metadata
	if (presence & maskMetadata) != 0 {
		metadata, err = newMetadataListFromReader(r)
		if err != nil {
			return nil, err
		}
	}

	// 3. Inputs
	inputs, err := newAssetInputsFromReader(r)
	if err != nil {
		return nil, err
	}

	// 4. Outputs
	outputs, err := newAssetOutputsFromReader(r)
	if err != nil {
		return nil, err
	}

	ag := AssetGroup{
		AssetId:      assetId,
		ControlAsset: controlAsset,
		Metadata:     metadata,
		Inputs:       inputs,
		Outputs:      outputs,
	}
	if err := ag.validate(); err != nil {
		return nil, err
	}

	return &ag, nil
}

// safeSumUint64 sums uint64 values using big.Int to avoid overflow.
func safeSumUint64(values []uint64) *big.Int {
	sum := new(big.Int)
	for _, value := range values {
		sum.Add(sum, new(big.Int).SetUint64(value))
	}
	return sum
}
