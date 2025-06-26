package domain

import (
	"github.com/ark-network/ark/common/tree"
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
	VtxoTree           []tree.TxGraphChunk
	Connectors         []tree.TxGraphChunk
	ConnectorAddress   string
	Txid               string
	RoundTx            string
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
	Err       string
	Timestamp int64
}

type TxRequestsRegistered struct {
	RoundEvent
	TxRequests []TxRequest
}
