package grpcclient

import (
	"encoding/hex"
	"fmt"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

// wrapper for GetEventStreamResponse
type eventResponse interface {
	GetBatchFailed() *arkv1.BatchFailedEvent
	GetBatchStarted() *arkv1.BatchStartedEvent
	GetBatchFinalization() *arkv1.BatchFinalizationEvent
	GetBatchFinalized() *arkv1.BatchFinalizedEvent
	GetTreeSigningStarted() *arkv1.TreeSigningStartedEvent
	GetTreeNoncesAggregated() *arkv1.TreeNoncesAggregatedEvent
	GetTreeNonces() *arkv1.TreeNoncesEvent
	GetTreeTx() *arkv1.TreeTxEvent
	GetTreeSignature() *arkv1.TreeSignatureEvent
	GetHeartbeat() *arkv1.Heartbeat
}

type event struct {
	eventResponse
}

func (e event) toBatchEvent() (any, error) {
	if ee := e.GetHeartbeat(); ee != nil {
		return nil, nil
	}

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
		nonces, err := tree.NewTreeNonces(ee.GetTreeNonces())
		if err != nil {
			return nil, err
		}
		return client.TreeNoncesAggregatedEvent{
			Id:     ee.GetId(),
			Nonces: nonces,
		}, nil
	}

	if ee := e.GetTreeNonces(); ee != nil {
		nonces := make(map[string]*tree.Musig2Nonce)
		for pubkey, nonce := range ee.GetNonces() {
			pubnonce, err := hex.DecodeString(nonce)
			if err != nil {
				return nil, err
			}

			if len(pubnonce) != 66 {
				return nil, fmt.Errorf(
					"invalid nonce length expected 66 bytes got %d",
					len(pubnonce),
				)
			}

			nonces[pubkey] = &tree.Musig2Nonce{
				PubNonce: [66]byte(pubnonce),
			}
		}

		return client.TreeNoncesEvent{
			Id:     ee.GetId(),
			Topic:  ee.GetTopic(),
			Txid:   ee.GetTxid(),
			Nonces: nonces,
		}, nil
	}

	if ee := e.GetTreeTx(); ee != nil {
		return client.TreeTxEvent{
			Id:         ee.GetId(),
			Topic:      ee.GetTopic(),
			BatchIndex: ee.GetBatchIndex(),
			Node: tree.TxTreeNode{
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
