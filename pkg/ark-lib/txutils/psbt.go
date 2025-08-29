package txutils

import (
	"bytes"
	"encoding/binary"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	COSIGNER_PSBT_KEY_PREFIX     = []byte("cosigner")
	CONDITION_WITNESS_KEY_PREFIX = []byte("condition")
	VTXO_TREE_EXPIRY_PSBT_KEY    = []byte("expiry")
	VTXO_TAPROOT_TREE_KEY        = []byte("taptree")
)

// AddTaprootTree adds the whole taproot tree of the VTXO to the given PSBT input.
// it follows the format of PSBT_OUT_TAP_TREE / BIP-371
func AddTaprootTree(inIndex int, ptx *psbt.Packet, leaves []string) error {
	tapscriptsBytes, err := TapTree(leaves).Encode()
	if err != nil {
		return err
	}

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: tapscriptsBytes,
		Key:   VTXO_TAPROOT_TREE_KEY,
	})
	return nil
}

// GetTaprootTree returns the taproot tree of the given PSBT input.
func GetTaprootTree(in psbt.PInput) (TapTree, error) {
	for _, u := range in.Unknowns {
		if bytes.Contains(u.Key, VTXO_TAPROOT_TREE_KEY) {
			return DecodeTapTree(u.Value)
		}
	}

	return nil, fmt.Errorf("no taproot tree found")
}

func AddConditionWitness(inIndex int, ptx *psbt.Packet, witness wire.TxWitness) error {
	var witnessBytes bytes.Buffer

	err := psbt.WriteTxWitness(&witnessBytes, witness)
	if err != nil {
		return err
	}

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: witnessBytes.Bytes(),
		Key:   CONDITION_WITNESS_KEY_PREFIX,
	})
	return nil
}

func GetConditionWitness(in psbt.PInput) (wire.TxWitness, error) {
	for _, u := range in.Unknowns {
		if bytes.Contains(u.Key, CONDITION_WITNESS_KEY_PREFIX) {
			return ReadTxWitness(u.Value)
		}
	}

	return wire.TxWitness{}, nil
}

func AddVtxoTreeExpiry(
	inIndex int, ptx *psbt.Packet, vtxoTreeExpiry arklib.RelativeLocktime,
) error {
	sequence, err := arklib.BIP68Sequence(vtxoTreeExpiry)
	if err != nil {
		return err
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

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: sequenceLE[:numBytes],
		Key:   VTXO_TREE_EXPIRY_PSBT_KEY,
	})

	return nil
}

func GetVtxoTreeExpiry(in psbt.PInput) (*arklib.RelativeLocktime, error) {
	for _, u := range in.Unknowns {
		if bytes.Contains(u.Key, VTXO_TREE_EXPIRY_PSBT_KEY) {
			return arklib.BIP68DecodeSequenceFromBytes(u.Value)
		}
	}

	return nil, nil
}

func AddCosignerKey(inIndex int, ptx *psbt.Packet, key *btcec.PublicKey) error {
	currentCosigners, err := GetCosignerKeys(ptx.Inputs[inIndex])
	if err != nil {
		return err
	}

	nextCosignerIndex := len(currentCosigners)

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: key.SerializeCompressed(),
		Key:   cosignerPrefixedKey(nextCosignerIndex),
	})

	return nil
}

func GetCosignerKeys(in psbt.PInput) ([]*btcec.PublicKey, error) {
	var keys []*btcec.PublicKey
	for _, u := range in.Unknowns {
		if !parsePrefixedCosignerKey(u.Key) {
			continue
		}

		key, err := btcec.ParsePubKey(u.Value)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func ReadTxWitness(witnessSerialized []byte) (wire.TxWitness, error) {
	r := bytes.NewReader(witnessSerialized)

	// first we extract the number of witness elements
	witCount, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	// read each witness item
	witness := make(wire.TxWitness, witCount)
	for i := uint64(0); i < witCount; i++ {
		witness[i], err = wire.ReadVarBytes(r, 0, txscript.MaxScriptSize, "witness")
		if err != nil {
			return nil, err
		}
	}

	return witness, nil
}

func cosignerPrefixedKey(index int) []byte {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, uint32(index))

	return append(COSIGNER_PSBT_KEY_PREFIX, indexBytes...)
}

func parsePrefixedCosignerKey(key []byte) bool {
	return bytes.HasPrefix(key, COSIGNER_PSBT_KEY_PREFIX)
}
