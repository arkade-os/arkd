package indexer

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type Indexer interface {
	GetCommitmentTx(ctx context.Context, txid string) (*CommitmentTx, error)
	GetVtxoTree(
		ctx context.Context, batchOutpoint types.Outpoint, opts ...PageOption,
	) (*VtxoTreeResponse, error)
	GetFullVtxoTree(
		ctx context.Context, batchOutpoint types.Outpoint, opts ...PageOption,
	) ([]tree.TxTreeNode, error)
	GetVtxoTreeLeaves(
		ctx context.Context, batchOutpoint types.Outpoint, opts ...PageOption,
	) (*VtxoTreeLeavesResponse, error)
	GetForfeitTxs(
		ctx context.Context, txid string, opts ...PageOption,
	) (*ForfeitTxsResponse, error)
	GetConnectors(
		ctx context.Context, txid string, opts ...PageOption,
	) (*ConnectorsResponse, error)
	GetVtxos(ctx context.Context, opts ...GetVtxosOption) (*VtxosResponse, error)
	GetVtxoChain(
		ctx context.Context, outpoint types.Outpoint, opts ...PageOption,
	) (*VtxoChainResponse, error)
	GetVirtualTxs(
		ctx context.Context, txids []string, opts ...PageOption,
	) (*VirtualTxsResponse, error)
	GetBatchSweepTxs(ctx context.Context, batchOutpoint types.Outpoint) ([]string, error)
	SubscribeForScripts(
		ctx context.Context, subscriptionId string, scripts []string,
	) (string, error)
	UnsubscribeForScripts(ctx context.Context, subscriptionId string, scripts []string) error
	GetSubscription(ctx context.Context, subscriptionId string, scripts ...string) (<-chan ScriptEvent, func(), error)
	ModifySubscriptionScripts(ctx context.Context, addScripts, removeScripts []string) (scriptsAdded, scriptsRemoved, allScripts []string, err error)
	OverwriteSubscriptionScripts(ctx context.Context, scripts []string) (scriptsAdded, scriptsRemoved, allScripts []string, err error)
	GetAsset(ctx context.Context, assetID string) (*AssetInfo, error)

	Close()
}

type AssetInfo struct {
	AssetId        string
	Supply         string
	ControlAssetId string
	Metadata       []asset.Metadata
}

type VtxoTreeResponse struct {
	Tree []TxNode
	Page *PageResponse
}

type VtxoTreeLeavesResponse struct {
	Leaves []types.Outpoint
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
	Data       *ScriptEventData
	Connection *types.StreamConnectionEvent
	Err        error
}

type ScriptEventData struct {
	Txid          string
	Tx            string
	Scripts       []string
	NewVtxos      []types.Vtxo
	SpentVtxos    []types.Vtxo
	CheckpointTxs map[string]TxData
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

func (t TxNodes) ToTree(txMap map[string]string) []tree.TxTreeNode {
	vtxoTree := make([]tree.TxTreeNode, 0)
	for _, node := range t {
		vtxoTree = append(vtxoTree, tree.TxTreeNode{
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
