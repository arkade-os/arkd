package indexer

import (
	"context"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type Indexer interface {
	GetCommitmentTx(ctx context.Context, txid string) (*CommitmentTx, error)
	GetCommitmentTxLeaves(ctx context.Context, txid string, opts ...RequestOption) (*CommitmentTxLeavesResponse, error)
	GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) (*VtxoTreeResponse, error)
	GetFullVtxoTree(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) ([]tree.TxGraphChunk, error)
	GetVtxoTreeLeaves(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) (*VtxoTreeLeavesResponse, error)
	GetForfeitTxs(ctx context.Context, txid string, opts ...RequestOption) (*ForfeitTxsResponse, error)
	GetConnectors(ctx context.Context, txid string, opts ...RequestOption) (*ConnectorsResponse, error)
	GetVtxos(ctx context.Context, opts ...GetVtxosRequestOption) (*VtxosResponse, error)
	GetTransactionHistory(ctx context.Context, address string, opts ...GetTxHistoryRequestOption) (*TxHistoryResponse, error)
	GetVtxoChain(ctx context.Context, outpoint Outpoint, opts ...RequestOption) (*VtxoChainResponse, error)
	GetVirtualTxs(ctx context.Context, txids []string, opts ...RequestOption) (*VirtualTxsResponse, error)
	GetBatchSweepTxs(ctx context.Context, batchOutpoint Outpoint) ([]string, error)
	SubscribeForScripts(ctx context.Context, subscriptionId string, scripts []string) (string, error)
	UnsubscribeForScripts(ctx context.Context, subscriptionId string, scripts []string) error
	GetSubscription(ctx context.Context, subscriptionId string) (<-chan *ScriptEvent, func(), error)

	Close()
}

type CommitmentTxLeavesResponse struct {
	Leaves []Outpoint
	Page   *PageResponse
}

type VtxoTreeResponse struct {
	Tree []TxNode
	Page *PageResponse
}

type VtxoTreeLeavesResponse struct {
	Leaves []Outpoint
	Page   *PageResponse
}

type ForfeitTxsResponse struct {
	Txids []string
	Page  *PageResponse
}

type ConnectorsResponse struct {
	Tree []TxNode
	Page *PageResponse
}

type VtxosResponse struct {
	Vtxos []types.Vtxo
	Page  *PageResponse
}

type TxHistoryResponse struct {
	History []types.Transaction
	Page    *PageResponse
}

type VtxoChainResponse struct {
	Chain []ChainWithExpiry
	Page  *PageResponse
}

type VirtualTxsResponse struct {
	Txs  []string
	Page *PageResponse
}

type TxData struct {
	Txid string
	Tx   string
}

type ScriptEvent struct {
	Txid          string
	Tx            string
	Scripts       []string
	NewVtxos      []types.Vtxo
	SpentVtxos    []types.Vtxo
	CheckpointTxs map[string]TxData
	Err           error
}

type PageRequest struct {
	Size  int32
	Index int32
}

type PageResponse struct {
	Current int32
	Next    int32
	Total   int32
}

type TxNodes []TxNode

func (t TxNodes) ToTree(txMap map[string]string) []tree.TxGraphChunk {
	vtxoTree := make([]tree.TxGraphChunk, 0)
	for _, node := range t {
		vtxoTree = append(vtxoTree, tree.TxGraphChunk{
			Txid:     node.Txid,
			Tx:       txMap[node.Txid],
			Children: node.Children,
		})
	}
	return vtxoTree
}

func (t TxNodes) Txids() []string {
	txids := make([]string, 0, len(t))
	for _, node := range t {
		txids = append(txids, node.Txid)
	}
	return txids
}

type TxNode struct {
	Txid     string
	Children map[uint32]string
}

type Batch struct {
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
	ExpiresAt         int64
	Swept             bool
}

type CommitmentTx struct {
	StartedAt         int64
	EndedAt           int64
	TotalInputAmount  uint64
	TotalInputVtxos   int32
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
	Batches           map[uint32]*Batch
}

type Outpoint struct {
	Txid string
	VOut uint32
}

type IndexerChainedTxType string

const (
	IndexerChainedTxTypeUnspecified IndexerChainedTxType = "unspecified"
	IndexerChainedTxTypeCommitment  IndexerChainedTxType = "commitment"
	IndexerChainedTxTypeArk         IndexerChainedTxType = "ark"
	IndexerChainedTxTypeTree        IndexerChainedTxType = "tree"
	IndexerChainedTxTypeCheckpoint  IndexerChainedTxType = "checkpoint"
)

type ChainWithExpiry struct {
	Txid      string
	ExpiresAt int64
	Type      IndexerChainedTxType
	Spends    []string
}
