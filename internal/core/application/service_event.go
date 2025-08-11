/*
* This package contains intermediary events that are used only by the covenantless version
* they let to sign the vtxo tree using musig2 algorithm
* they are not included in domain because they don't mutate the Round state and should not be persisted
 */
package application

import (
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

// the user should react to this event by confirming the registration using intent_id
type BatchStarted struct {
	domain.RoundEvent
	IntentIdsHashes [][32]byte
	BatchExpiry     uint32
}

// signer should react to this event by generating a musig2 nonce for each transaction in the tree
type RoundSigningStarted struct {
	domain.RoundEvent
	UnsignedCommitmentTx string
	CosignersPubkeys     []string
}

// signer should react to this event by partially signing the vtxo tree transactions
// then, delete its ephemeral key
type TreeNoncesAggregated struct {
	domain.RoundEvent
	Nonces tree.TreeNonces // aggregated nonces
}

type RoundFinalized struct {
	domain.RoundFinalized
	Txid string
}

type TreeTxMessage struct {
	domain.RoundEvent
	Topic      []string
	BatchIndex int32
	Node       tree.TxTreeNode
}

type TreeSignatureMessage struct {
	domain.RoundEvent
	Topic      []string
	BatchIndex int32
	Txid       string
	Signature  string
}

// implement domain.RoundEvent interface
func (r RoundSigningStarted) GetTopic() string  { return domain.RoundTopic }
func (r TreeNoncesAggregated) GetTopic() string { return domain.RoundTopic }
func (r TreeTxMessage) GetTopic() string        { return domain.RoundTopic }
func (r TreeSignatureMessage) GetTopic() string { return domain.RoundTopic }
