package indexer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	indexer_service "github.com/arkade-os/arkd/pkg/client-lib/indexer/rest/service"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"resty.dev/v3"
)

type restClient struct {
	serverURL      string
	svc            *indexer_service.APIClient
	requestTimeout time.Duration
}

// NewClient creates a new REST client for the Indexer service
func NewClient(serverURL string, _ bool) (indexer.Indexer, error) {
	if len(serverURL) <= 0 {
		return nil, fmt.Errorf("missing server url")
	}
	svc, err := newRestClient(serverURL)
	if err != nil {
		return nil, err
	}
	// TODO: use twice the round interval.
	reqTimeout := 15 * time.Second

	return &restClient{serverURL, svc, reqTimeout}, nil
}

func (a *restClient) GetCommitmentTx(
	ctx context.Context, txid string,
) (*indexer.CommitmentTx, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetCommitmentTx(ctx, txid)
	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	batches := make(map[uint32]*indexer.Batch)
	for vout, batch := range resp.GetBatches() {
		voutUint32, err := strconv.ParseUint(vout, 10, 32)
		if err != nil {
			return nil, err
		}

		batches[uint32(voutUint32)] = &indexer.Batch{
			TotalOutputAmount: uint64(batch.GetTotalOutputAmount()),
			TotalOutputVtxos:  batch.GetTotalOutputVtxos(),
			ExpiresAt:         batch.GetExpiresAt(),
			Swept:             batch.GetSwept(),
		}
	}

	return &indexer.CommitmentTx{
		StartedAt:         resp.GetStartedAt(),
		EndedAt:           resp.GetEndedAt(),
		Batches:           batches,
		TotalInputAmount:  uint64(resp.GetTotalInputAmount()),
		TotalInputVtxos:   resp.GetTotalInputVtxos(),
		TotalOutputAmount: uint64(resp.GetTotalOutputAmount()),
		TotalOutputVtxos:  resp.GetTotalOutputVtxos(),
	}, nil
}

func (a *restClient) GetVtxoTree(
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeResponse, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetVtxoTree(
		ctx, batchOutpoint.Txid, int32(batchOutpoint.VOut),
	)
	if len(opts) > 0 {
		opt := opts[0]
		if opt.GetPage() != nil {
			req = req.PageIndex(opt.GetPage().Index).PageSize(opt.GetPage().Size)
		}
	}

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	nodes := make([]indexer.TxNode, 0, len(resp.GetVtxoTree()))
	for _, node := range resp.GetVtxoTree() {
		children := make(map[uint32]string)
		for k, v := range node.GetChildren() {
			vout, err := strconv.ParseUint(k, 10, 32)
			if err != nil {
				return nil, err
			}
			children[uint32(vout)] = v
		}
		nodes = append(nodes, indexer.TxNode{
			Txid:     node.GetTxid(),
			Children: children,
		})
	}

	return &indexer.VtxoTreeResponse{
		Tree: nodes,
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *restClient) GetFullVtxoTree(
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.RequestOption,
) ([]tree.TxTreeNode, error) {
	resp, err := a.GetVtxoTree(ctx, batchOutpoint, opts...)
	if err != nil {
		return nil, err
	}

	var allTxs indexer.TxNodes = resp.Tree
	for resp.Page != nil && resp.Page.Next != resp.Page.Total {
		opt := indexer.RequestOption{}
		opt.WithPage(&indexer.PageRequest{
			Index: resp.Page.Next,
		})
		resp, err = a.GetVtxoTree(ctx, batchOutpoint, opts...)
		if err != nil {
			return nil, err
		}
		allTxs = append(allTxs, resp.Tree...)
	}

	txids := allTxs.Txids()
	txResp, err := a.GetVirtualTxs(ctx, txids)
	if err != nil {
		return nil, err
	}
	txMap := make(map[string]string)
	for i, tx := range txResp.Txs {
		txMap[txids[i]] = tx
	}
	return allTxs.ToTree(txMap), nil
}

func (a *restClient) GetVtxoTreeLeaves(
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeLeavesResponse, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetVtxoTreeLeaves(
		ctx, batchOutpoint.Txid, int32(batchOutpoint.VOut),
	)
	if len(opts) > 0 {
		opt := opts[0]
		if opt.GetPage() != nil {
			req = req.PageIndex(opt.GetPage().Index).PageSize(opt.GetPage().Size)
		}
	}

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	leaves := make([]types.Outpoint, 0, len(resp.GetLeaves()))
	for _, leaf := range resp.GetLeaves() {
		leaves = append(leaves, types.Outpoint{
			Txid: leaf.GetTxid(),
			VOut: uint32(leaf.GetVout()),
		})
	}

	return &indexer.VtxoTreeLeavesResponse{
		Leaves: leaves,
		Page:   parsePage(resp.GetPage()),
	}, nil
}

func (a *restClient) GetForfeitTxs(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ForfeitTxsResponse, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetForfeitTxs(ctx, txid)
	if len(opts) > 0 {
		opt := opts[0]
		if opt.GetPage() != nil {
			req = req.PageIndex(opt.GetPage().Index).PageSize(opt.GetPage().Size)
		}
	}

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	return &indexer.ForfeitTxsResponse{
		Txids: resp.GetTxids(),
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *restClient) GetConnectors(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ConnectorsResponse, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetConnectors(ctx, txid)
	if len(opts) > 0 {
		opt := opts[0]
		if opt.GetPage() != nil {
			req = req.PageIndex(opt.GetPage().Index).PageSize(opt.GetPage().Size)
		}
	}

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	connectors := make([]indexer.TxNode, 0, len(resp.GetConnectors()))
	for _, connector := range resp.GetConnectors() {
		children := make(map[uint32]string)
		for k, v := range connector.GetChildren() {
			vout, err := strconv.ParseUint(k, 10, 32)
			if err != nil {
				return nil, err
			}
			children[uint32(vout)] = v
		}

		connectors = append(connectors, indexer.TxNode{
			Txid:     connector.GetTxid(),
			Children: children,
		})
	}

	return &indexer.ConnectorsResponse{
		Tree: connectors,
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *restClient) GetVtxos(
	ctx context.Context, opts ...indexer.GetVtxosRequestOption,
) (*indexer.VtxosResponse, error) {
	if len(opts) <= 0 {
		return nil, fmt.Errorf("missing opts")
	}
	opt := opts[0]

	req := a.svc.IndexerServiceAPI.IndexerServiceGetVtxos(ctx).
		SpendableOnly(opt.GetSpendableOnly()).
		SpentOnly(opt.GetSpentOnly()).
		RecoverableOnly(opt.GetRecoverableOnly()).
		PendingOnly(opt.GetPendingOnly())

	if len(opt.GetOutpoints()) > 0 {
		req = req.Outpoints(opt.GetOutpoints())
	}
	if len(opt.GetScripts()) > 0 {
		req = req.Scripts(opt.GetScripts())
	}
	if opt.GetPage() != nil {
		req = req.PageIndex(opt.GetPage().Index).PageSize(opt.GetPage().Size)
	}

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	return &indexer.VtxosResponse{
		Vtxos: newIndexerVtxos(resp.GetVtxos()),
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *restClient) GetVtxoChain(
	ctx context.Context, outpoint types.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoChainResponse, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetVtxoChain(
		ctx, outpoint.Txid, int32(outpoint.VOut),
	)
	if len(opts) > 0 {
		opt := opts[0]
		if opt.GetPage() != nil {
			req = req.PageIndex(opt.GetPage().Index).PageSize(opt.GetPage().Size)
		}
	}

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	chain := make([]indexer.ChainWithExpiry, 0, len(resp.GetChain()))
	for _, v := range resp.GetChain() {
		var txType indexer.IndexerChainedTxType
		switch v.GetType() {
		case indexer_service.INDEXER_CHAINED_TX_TYPE_COMMITMENT:
			txType = indexer.IndexerChainedTxTypeCommitment
		case indexer_service.INDEXER_CHAINED_TX_TYPE_ARK:
			txType = indexer.IndexerChainedTxTypeArk
		case indexer_service.INDEXER_CHAINED_TX_TYPE_TREE:
			txType = indexer.IndexerChainedTxTypeTree
		case indexer_service.INDEXER_CHAINED_TX_TYPE_CHECKPOINT:
			txType = indexer.IndexerChainedTxTypeCheckpoint
		default:
			txType = indexer.IndexerChainedTxTypeUnspecified
		}
		chain = append(chain, indexer.ChainWithExpiry{
			Txid:      v.GetTxid(),
			ExpiresAt: v.GetExpiresAt(),
			Type:      txType,
			Spends:    v.GetSpends(),
		})
	}

	return &indexer.VtxoChainResponse{
		Chain: chain,
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *restClient) GetVirtualTxs(
	ctx context.Context, txids []string, opts ...indexer.RequestOption,
) (*indexer.VirtualTxsResponse, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetVirtualTxs(ctx, txids)
	if len(opts) > 0 {
		opt := opts[0]
		if opt.GetPage() != nil {
			req = req.PageIndex(opt.GetPage().Index).PageSize(opt.GetPage().Size)
		}
	}

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	return &indexer.VirtualTxsResponse{
		Txs:  resp.GetTxs(),
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *restClient) GetBatchSweepTxs(
	ctx context.Context, batchOutpoint types.Outpoint,
) ([]string, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceGetBatchSweepTransactions(
		ctx, batchOutpoint.Txid, int32(batchOutpoint.VOut),
	)

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	return resp.GetSweptBy(), nil
}

func (a *restClient) GetSubscription(
	ctx context.Context, subscriptionId string,
) (<-chan *indexer.ScriptEvent, func(), error) {
	eventsCh := make(chan *indexer.ScriptEvent)
	url := fmt.Sprintf("%s/v1/script/subscription/%s", a.serverURL, subscriptionId)

	sseClient := resty.NewEventSource().
		SetURL(url).
		SetHeader("Accept", "text/event-stream").
		OnMessage(func(e any) {
			ev := e.(*resty.Event)
			event := indexer_service.GetSubscriptionResponse{}

			if err := json.Unmarshal([]byte(ev.Data), &event); err != nil {
				eventsCh <- &indexer.ScriptEvent{Err: err}
				return
			}

			if event.GetHeartbeat() != nil {
				return
			}

			var checkpointTxs map[string]indexer.TxData
			if len(event.GetEvent().CheckpointTxs) > 0 {
				checkpointTxs = make(map[string]indexer.TxData)
				for k, v := range event.GetEvent().CheckpointTxs {
					checkpointTxs[k] = indexer.TxData{
						Txid: v.GetTxid(),
						Tx:   v.GetTx(),
					}
				}
			}

			eventsCh <- &indexer.ScriptEvent{
				Txid:          *event.GetEvent().Txid,
				Scripts:       event.GetEvent().Scripts,
				NewVtxos:      newIndexerVtxos(event.GetEvent().NewVtxos),
				SpentVtxos:    newIndexerVtxos(event.GetEvent().SpentVtxos),
				CheckpointTxs: checkpointTxs,
			}
		}, nil)

	if err := sseClient.Get(); err != nil {
		return nil, nil, err
	}

	return eventsCh, sseClient.Close, nil
}

func (a *restClient) SubscribeForScripts(
	ctx context.Context, subscriptionId string, scripts []string,
) (string, error) {
	req := a.svc.IndexerServiceAPI.IndexerServiceSubscribeForScripts(ctx)
	req.SubscribeForScriptsRequest(indexer_service.SubscribeForScriptsRequest{
		Scripts:        scripts,
		SubscriptionId: &subscriptionId,
	})

	resp, _, err := req.Execute()
	if err != nil {
		return "", err
	}

	return resp.GetSubscriptionId(), nil
}

func (a *restClient) UnsubscribeForScripts(
	ctx context.Context, subscriptionId string, scripts []string,
) error {
	req := a.svc.IndexerServiceAPI.IndexerServiceUnsubscribeForScripts(ctx)
	req.UnsubscribeForScriptsRequest(indexer_service.UnsubscribeForScriptsRequest{
		Scripts:        scripts,
		SubscriptionId: &subscriptionId,
	})

	_, _, err := req.Execute()
	return err
}

func (a *restClient) Close() {}

func newRestClient(serviceURL string) (*indexer_service.APIClient, error) {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, err
	}

	defaultHeaders := map[string]string{
		"Content-Type": "application/json",
	}

	cfg := &indexer_service.Configuration{
		Host:          parsedURL.Host,
		DefaultHeader: defaultHeaders,
		Scheme:        parsedURL.Scheme,
		Servers:       indexer_service.ServerConfigurations{{URL: serviceURL}},
	}

	return indexer_service.NewAPIClient(cfg), nil
}

func parsePage(page indexer_service.IndexerPageResponse) *indexer.PageResponse {
	if indexer_service.IsNil(page) {
		return nil
	}
	return &indexer.PageResponse{
		Current: page.GetCurrent(),
		Next:    page.GetNext(),
		Total:   page.GetTotal(),
	}
}

func newIndexerVtxos(restVtxos []indexer_service.IndexerVtxo) []types.Vtxo {
	vtxos := make([]types.Vtxo, 0, len(restVtxos))
	for _, vtxo := range restVtxos {
		vtxos = append(vtxos, newIndexerVtxo(vtxo))
	}
	return vtxos
}

func newIndexerVtxo(vtxo indexer_service.IndexerVtxo) types.Vtxo {
	return types.Vtxo{
		Outpoint: types.Outpoint{
			Txid: *vtxo.GetOutpoint().Txid,
			VOut: uint32(*vtxo.GetOutpoint().Vout),
		},
		Script:          vtxo.GetScript(),
		CommitmentTxids: vtxo.GetCommitmentTxids(),
		Amount:          uint64(vtxo.GetAmount()),
		CreatedAt:       time.Unix(vtxo.GetCreatedAt(), 0),
		ExpiresAt:       time.Unix(vtxo.GetExpiresAt(), 0),
		Preconfirmed:    vtxo.GetIsPreconfirmed(),
		Swept:           vtxo.GetIsSwept(),
		Unrolled:        vtxo.GetIsUnrolled(),
		Spent:           vtxo.GetIsSpent(),
		SpentBy:         vtxo.GetSpentBy(),
		SettledBy:       vtxo.GetSettledBy(),
		ArkTxid:         vtxo.GetArkTxid(),
	}
}
