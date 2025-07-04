package arklib

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type TaprootMerkleProof struct {
	ControlBlock []byte
	Script       []byte
}

// TaprootTree is an interface wrapping the methods needed to spend a vtxo taproot contract
type TaprootTree interface {
	GetLeaves() []chainhash.Hash
	GetTaprootMerkleProof(leafhash chainhash.Hash) (*TaprootMerkleProof, error)
	GetRoot() chainhash.Hash
}

// VtxoScript abstracts the taproot complexity behind vtxo contracts.
//
// A vtxo script is defined as a taproot contract with at least 1 collaborative closure (A + S) and 1 exit closure (A after t).
// It may also contain others closures implementing specific use cases.
//
// TODO: gather common and tree package to prevent circular dependency and move C generic
type VtxoScript[T TaprootTree, C interface{}] interface {
	Validate(signer *btcec.PublicKey, minLocktime RelativeLocktime, blockTypeAllowed bool) error
	TapTree() (taprootKey *btcec.PublicKey, taprootScriptTree T, err error)
	Encode() ([]string, error)
	Decode(scripts []string) error
	SmallestExitDelay() (*RelativeLocktime, error)
	ForfeitClosures() []C
	ExitClosures() []C
}

// BiggestLeafMerkleProof returns the leaf with the biggest witness size (for fee estimation)
// we need this to estimate the fee without knowning the exact leaf that will be spent
func BiggestLeafMerkleProof(t TaprootTree) (*TaprootMerkleProof, error) {
	var biggest *TaprootMerkleProof
	var biggestSize int

	for _, leaf := range t.GetLeaves() {
		proof, err := t.GetTaprootMerkleProof(leaf)
		if err != nil {
			return nil, err
		}

		if len(proof.ControlBlock)+len(proof.Script) > biggestSize {
			biggest = proof
			biggestSize = len(proof.ControlBlock) + len(proof.Script)
		}
	}

	return biggest, nil
}
