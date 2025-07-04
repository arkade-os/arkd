package domain

import (
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

const RoundTopic = "round"

type RoundEvent struct {
	Id   string
	Type EventType
}

func (r RoundEvent) GetTopic() string   { return RoundTopic }
func (r RoundEvent) GetType() EventType { return r.Type }

type RoundStarted struct {
	RoundEvent
	Timestamp int64
}

type RoundFinalizationStarted struct {
	RoundEvent
	VtxoTree           tree.FlatTxTree
	Connectors         tree.FlatTxTree
	ConnectorAddress   string
	CommitmentTxid     string
	CommitmentTx       string
	VtxoTreeExpiration int64
}

type RoundFinalized struct {
	RoundEvent
	ForfeitTxs        []ForfeitTx
	FinalCommitmentTx string
	Timestamp         int64
}

type RoundFailed struct {
	RoundEvent
	Reason    string
	Timestamp int64
}

type IntentsRegistered struct {
	RoundEvent
	Intents []Intent
}

type BatchSwept struct {
	RoundEvent
	Vtxos      []Outpoint
	Txid       string
	Tx         string
	FullySwept bool
}
