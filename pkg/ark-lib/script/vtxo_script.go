package script

import (
	"bytes"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

var ErrNoExitLeaf = fmt.Errorf("no exit leaf")

type VtxoScript arklib.VtxoScript[taprootTree, Closure]

// NewDefaultVtxoScript returns the common VTXO script: A + S | A after T with:
// - A: the owner of the VTXO.
// - S: the pubkey of the signer who provided the liquidity for the VTXO.
// - T: exit delay that must be waited by alice to spend the VTXO once unrolled onchain.
func NewDefaultVtxoScript(
	owner, signer *btcec.PublicKey, exitDelay arklib.RelativeLocktime,
) *TapscriptsVtxoScript {
	return &TapscriptsVtxoScript{
		[]Closure{
			&CSVMultisigClosure{
				MultisigClosure: MultisigClosure{PubKeys: []*btcec.PublicKey{owner}},
				Locktime:        exitDelay,
			},
			&MultisigClosure{PubKeys: []*btcec.PublicKey{owner, signer}},
		},
	}
}

func ParseVtxoScript(scripts []string) (VtxoScript, error) {
	if len(scripts) == 0 {
		return nil, fmt.Errorf("empty tapscripts array")
	}

	types := []VtxoScript{
		&TapscriptsVtxoScript{},
	}

	for _, v := range types {
		if err := v.Decode(scripts); err == nil {
			return v, nil
		}
	}

	return nil, fmt.Errorf("invalid vtxo scripts: %s", scripts)
}

type TapscriptsVtxoScript struct {
	Closures []Closure
}

func (v *TapscriptsVtxoScript) Encode() ([]string, error) {
	encoded := make([]string, 0)
	for _, closure := range v.Closures {
		script, err := closure.Script()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, hex.EncodeToString(script))
	}
	return encoded, nil
}

func (v *TapscriptsVtxoScript) Decode(scripts []string) error {
	if len(scripts) == 0 {
		return fmt.Errorf("empty scripts array")
	}

	v.Closures = make([]Closure, 0, len(scripts))
	for _, script := range scripts {
		scriptBytes, err := hex.DecodeString(script)
		if err != nil {
			return err
		}

		closure, err := DecodeClosure(scriptBytes)
		if err != nil {
			return err
		}
		v.Closures = append(v.Closures, closure)
	}

	if len(v.Closures) == 0 {
		return fmt.Errorf("no valid closures found in scripts")
	}

	return nil
}

func (v *TapscriptsVtxoScript) Validate(
	signer *btcec.PublicKey, minLocktime arklib.RelativeLocktime, blockTypeAllowed bool,
) error {
	xOnlySigner := schnorr.SerializePubKey(signer)
	for _, forfeit := range v.ForfeitClosures() {
		keys := make([]*btcec.PublicKey, 0)
		switch c := forfeit.(type) {
		case *MultisigClosure:
			keys = c.PubKeys
		case *CLTVMultisigClosure:
			if !blockTypeAllowed && !c.Locktime.IsSeconds() {
				return fmt.Errorf("invalid forfeit closure, CLTV block type not allowed")
			}
			keys = c.PubKeys
		case *ConditionMultisigClosure:
			keys = c.PubKeys
		}

		if len(keys) == 0 {
			return fmt.Errorf(
				"invalid forfeit closure, expected MultisigClosure, CLTVMultisigClosure or ConditionMultisigClosure",
			)
		}

		// must contain signer pubkey
		found := false
		for _, pubkey := range keys {
			if bytes.Equal(schnorr.SerializePubKey(pubkey), xOnlySigner) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid forfeit closure, signer pubkey not found")
		}
	}

	for _, closure := range v.ExitClosures() {
		c := closure.(*CSVMultisigClosure)
		if !blockTypeAllowed && c.Locktime.Type == arklib.LocktimeTypeBlock {
			return fmt.Errorf("invalid exit closure, CSV block type not allowed")
		}
	}

	smallestExit, err := v.SmallestExitDelay()
	if err != nil {
		if err == ErrNoExitLeaf {
			return nil
		}
		return err
	}

	if smallestExit.LessThan(minLocktime) {
		return fmt.Errorf("exit delay is too short")
	}

	return nil
}

func (v *TapscriptsVtxoScript) SmallestExitDelay() (*arklib.RelativeLocktime, error) {
	var smallest *arklib.RelativeLocktime

	for _, closure := range v.Closures {
		if csvClosure, ok := closure.(*CSVMultisigClosure); ok {
			if smallest == nil || csvClosure.Locktime.LessThan(*smallest) {
				smallest = &csvClosure.Locktime
			}
		}
	}

	if smallest == nil {
		return nil, ErrNoExitLeaf
	}

	return smallest, nil
}

func (v *TapscriptsVtxoScript) ForfeitClosures() []Closure {
	forfeits := make([]Closure, 0)
	for _, closure := range v.Closures {
		switch closure.(type) {
		case *MultisigClosure, *CLTVMultisigClosure, *ConditionMultisigClosure:
			forfeits = append(forfeits, closure)
		}
	}
	return forfeits
}

func (v *TapscriptsVtxoScript) ExitClosures() []Closure {
	exits := make([]Closure, 0)
	for _, closure := range v.Closures {
		switch closure.(type) {
		case *CSVMultisigClosure:
			exits = append(exits, closure)
		}
	}
	return exits
}

func (v *TapscriptsVtxoScript) TapTree() (*btcec.PublicKey, taprootTree, error) {
	leaves := make([]txscript.TapLeaf, len(v.Closures))
	for i, closure := range v.Closures {
		script, err := closure.Script()
		if err != nil {
			return nil, taprootTree{}, fmt.Errorf("failed to get script for closure %d: %w", i, err)
		}
		leaves[i] = txscript.NewBaseTapLeaf(script)
	}

	tapTree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tapTree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	return taprootKey, taprootTree{tapTree}, nil
}

// taprootTree is a wrapper around txscript.IndexedTapScriptTree to implement the common.TaprootTree interface
type taprootTree struct {
	*txscript.IndexedTapScriptTree
}

func (b taprootTree) GetRoot() chainhash.Hash {
	return b.RootNode.TapHash()
}

func (b taprootTree) GetTaprootMerkleProof(
	leafhash chainhash.Hash,
) (*arklib.TaprootMerkleProof, error) {
	index, ok := b.LeafProofIndex[leafhash]
	if !ok {
		return nil, fmt.Errorf("leaf %s not found in tree", leafhash.String())
	}
	proof := b.LeafMerkleProofs[index]

	controlBlock := proof.ToControlBlock(UnspendableKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	return &arklib.TaprootMerkleProof{
		ControlBlock: controlBlockBytes,
		Script:       proof.Script,
	}, nil
}

func (b taprootTree) GetLeaves() []chainhash.Hash {
	leafHashes := make([]chainhash.Hash, 0)
	for hash := range b.LeafProofIndex {
		leafHashes = append(leafHashes, hash)
	}
	return leafHashes
}
