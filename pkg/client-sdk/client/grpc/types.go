package grpcclient

import (
	"encoding/json"
	"fmt"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

// wrapper for GetEventStreamResponse and PingResponse
type eventResponse interface {
	GetBatchFailed() *arkv1.BatchFailed
	GetBatchStarted() *arkv1.BatchStartedEvent
	GetBatchFinalization() *arkv1.BatchFinalizationEvent
	GetBatchFinalized() *arkv1.BatchFinalizedEvent
	GetTreeSigningStarted() *arkv1.TreeSigningStartedEvent
	GetTreeNoncesAggregated() *arkv1.TreeNoncesAggregatedEvent
	GetTreeTx() *arkv1.TreeTxEvent
	GetTreeSignature() *arkv1.TreeSignatureEvent
}

type event struct {
	eventResponse
}

func (e event) toBatchEvent() (any, error) {
	if ee := e.GetBatchFailed(); ee != nil {
		return client.BatchFailedEvent{
			Id:     ee.GetId(),
			Reason: ee.GetReason(),
		}, nil
	}

	if ee := e.GetBatchStarted(); ee != nil {
		return client.BatchStartedEvent{
			Id:              ee.GetId(),
			HashedIntentIds: ee.GetIntentIdHashes(),
			BatchExpiry:     ee.GetBatchExpiry(),
		}, nil
	}

	if ee := e.GetBatchFinalization(); ee != nil {
		return client.BatchFinalizationEvent{
			Id: ee.GetId(),
			Tx: ee.GetCommitmentTx(),
		}, nil
	}

	if ee := e.GetBatchFinalized(); ee != nil {
		return client.BatchFinalizedEvent{
			Id:   ee.GetId(),
			Txid: ee.GetCommitmentTxid(),
		}, nil
	}

	if ee := e.GetTreeSigningStarted(); ee != nil {
		return client.TreeSigningStartedEvent{
			Id:                   ee.GetId(),
			UnsignedCommitmentTx: ee.GetUnsignedCommitmentTx(),
			CosignersPubkeys:     ee.GetCosignersPubkeys(),
		}, nil
	}

	if ee := e.GetTreeNoncesAggregated(); ee != nil {
		nonces := make(tree.TreeNonces)

		if err := json.Unmarshal([]byte(ee.GetTreeNonces()), &nonces); err != nil {
			return nil, err
		}
		return client.TreeNoncesAggregatedEvent{
			Id:     ee.GetId(),
			Nonces: nonces,
		}, nil
	}

	if ee := e.GetTreeTx(); ee != nil {
		return client.TreeTxEvent{
			Id:         ee.GetId(),
			Topic:      ee.GetTopic(),
			BatchIndex: ee.GetBatchIndex(),
			TxGraphChunk: tree.TxGraphChunk{
				Txid:     ee.GetTxid(),
				Tx:       ee.GetTx(),
				Children: ee.GetChildren(),
			},
		}, nil
	}

	if ee := e.GetTreeSignature(); ee != nil {
		return client.TreeSignatureEvent{
			Id:         ee.GetId(),
			Topic:      ee.GetTopic(),
			BatchIndex: ee.GetBatchIndex(),
			Txid:       ee.GetTxid(),
			Signature:  ee.GetSignature(),
		}, nil
	}

	return nil, fmt.Errorf("unknown event")
}

type vtxo struct {
	*arkv1.Vtxo
}

func (v vtxo) toVtxo() types.Vtxo {
	return types.Vtxo{
		Outpoint: types.Outpoint{
			Txid: v.GetOutpoint().GetTxid(),
			VOut: v.GetOutpoint().GetVout(),
		},
		Script:          v.GetScript(),
		Amount:          v.GetAmount(),
		CommitmentTxids: v.GetCommitmentTxids(),
		CreatedAt:       time.Unix(v.GetCreatedAt(), 0),
		ExpiresAt:       time.Unix(v.GetExpiresAt(), 0),
		Preconfirmed:    v.GetIsPreconfirmed(),
		Swept:           v.GetIsSwept(),
		Unrolled:        v.GetIsUnrolled(),
		Spent:           v.GetIsSpent(),
		SpentBy:         v.GetSpentBy(),
		SettledBy:       v.GetSettledBy(),
		ArkTxid:         v.GetArkTxid(),
	}
}

type vtxos []*arkv1.Vtxo

func (v vtxos) toVtxos() []types.Vtxo {
	list := make([]types.Vtxo, 0, len(v))
	for _, vv := range v {
		list = append(list, vtxo{vv}.toVtxo())
	}
	return list
}
