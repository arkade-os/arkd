package indexer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	maxPageSize   = 1000
	maxReqsPerSec = 10
	maxPages      = 100
)

type grpcClient struct {
	conn   *grpc.ClientConn
	connMu *sync.RWMutex
	// TODO: drop me in https://github.com/arkade-os/arkd/pull/951
	scripts *scriptsCache
}

func NewClient(serverUrl string) (indexer.Indexer, error) {
	if len(serverUrl) <= 0 {
		return nil, fmt.Errorf("missing server url")
	}

	port := 80
	creds := insecure.NewCredentials()
	serverUrl = strings.TrimPrefix(serverUrl, "http://")
	if strings.HasPrefix(serverUrl, "https://") {
		serverUrl = strings.TrimPrefix(serverUrl, "https://")
		creds = credentials.NewTLS(nil)
		port = 443
	}
	if !strings.Contains(serverUrl, ":") {
		serverUrl = fmt.Sprintf("%s:%d", serverUrl, port)
	}

	options := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDisableServiceConfig(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   10 * time.Second,
			},
			MinConnectTimeout: 3 * time.Second,
		}),
	}

	conn, err := grpc.NewClient(serverUrl, options...)
	if err != nil {
		return nil, err
	}

	client := &grpcClient{
		conn:    conn,
		connMu:  &sync.RWMutex{},
		scripts: newScriptsCache(),
	}

	return client, nil
}

func (a *grpcClient) GetCommitmentTx(
	ctx context.Context, txid string,
) (*indexer.CommitmentTx, error) {
	req := &arkv1.GetCommitmentTxRequest{
		Txid: txid,
	}
	resp, err := a.svc().GetCommitmentTx(ctx, req)
	if err != nil {
		return nil, err
	}

	batches := make(map[uint32]*indexer.Batch)
	for vout, batch := range resp.GetBatches() {
		batches[vout] = &indexer.Batch{
			TotalOutputAmount: batch.GetTotalOutputAmount(),
			TotalOutputVtxos:  batch.GetTotalOutputVtxos(),
			ExpiresAt:         batch.GetExpiresAt(),
			Swept:             batch.GetSwept(),
		}
	}

	return &indexer.CommitmentTx{
		StartedAt:         resp.GetStartedAt(),
		EndedAt:           resp.GetEndedAt(),
		TotalInputAmount:  resp.GetTotalInputAmount(),
		TotalInputVtxos:   resp.GetTotalInputVtxos(),
		TotalOutputAmount: resp.GetTotalOutputAmount(),
		TotalOutputVtxos:  resp.GetTotalOutputVtxos(),
		Batches:           batches,
	}, nil
}

func (a *grpcClient) GetVtxoTree(
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.PageOption,
) (*indexer.VtxoTreeResponse, error) {
	o, err := indexer.ApplyPageOptions(opts...)
	if err != nil {
		return nil, err
	}
	var page *arkv1.IndexerPageRequest
	if o.Page != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  o.Page.Size,
			Index: o.Page.Index,
		}
	}

	req := &arkv1.GetVtxoTreeRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
		Page: page,
	}

	resp, err := a.svc().GetVtxoTree(ctx, req)
	if err != nil {
		return nil, err
	}

	nodes := make([]indexer.TxNode, 0, len(resp.GetVtxoTree()))
	for _, node := range resp.GetVtxoTree() {
		nodes = append(nodes, indexer.TxNode{
			Txid:     node.GetTxid(),
			Children: node.GetChildren(),
		})
	}

	return &indexer.VtxoTreeResponse{
		Tree: nodes,
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetFullVtxoTree(
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.PageOption,
) ([]tree.TxTreeNode, error) {
	o, err := indexer.ApplyPageOptions(opts...)
	if err != nil {
		return nil, err
	}

	resp, err := a.GetVtxoTree(ctx, batchOutpoint, opts...)
	if err != nil {
		return nil, err
	}

	var allTxs indexer.TxNodes = resp.Tree
	for resp.Page != nil && resp.Page.Next != resp.Page.Total {
		nextPage := &indexer.PageRequest{Index: resp.Page.Next}
		if o.Page != nil {
			nextPage.Size = o.Page.Size
		}
		resp, err = a.GetVtxoTree(ctx, batchOutpoint, indexer.WithPage(nextPage))
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

func (a *grpcClient) GetVtxoTreeLeaves(
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.PageOption,
) (*indexer.VtxoTreeLeavesResponse, error) {
	o, err := indexer.ApplyPageOptions(opts...)
	if err != nil {
		return nil, err
	}
	var page *arkv1.IndexerPageRequest
	if o.Page != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  o.Page.Size,
			Index: o.Page.Index,
		}
	}

	req := &arkv1.GetVtxoTreeLeavesRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
		Page: page,
	}

	resp, err := a.svc().GetVtxoTreeLeaves(ctx, req)
	if err != nil {
		return nil, err
	}

	leaves := make([]types.Outpoint, 0, len(resp.GetLeaves()))
	for _, leaf := range resp.GetLeaves() {
		leaves = append(leaves, types.Outpoint{
			Txid: leaf.GetTxid(),
			VOut: leaf.GetVout(),
		})
	}

	return &indexer.VtxoTreeLeavesResponse{
		Leaves: leaves,
		Page:   parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetForfeitTxs(
	ctx context.Context, txid string, opts ...indexer.PageOption,
) (*indexer.ForfeitTxsResponse, error) {
	o, err := indexer.ApplyPageOptions(opts...)
	if err != nil {
		return nil, err
	}
	var page *arkv1.IndexerPageRequest
	if o.Page != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  o.Page.Size,
			Index: o.Page.Index,
		}
	}

	req := &arkv1.GetForfeitTxsRequest{
		Txid: txid,
		Page: page,
	}

	resp, err := a.svc().GetForfeitTxs(ctx, req)
	if err != nil {
		return nil, err
	}

	return &indexer.ForfeitTxsResponse{
		Txids: resp.GetTxids(),
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetConnectors(
	ctx context.Context, txid string, opts ...indexer.PageOption,
) (*indexer.ConnectorsResponse, error) {
	o, err := indexer.ApplyPageOptions(opts...)
	if err != nil {
		return nil, err
	}
	var page *arkv1.IndexerPageRequest
	if o.Page != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  o.Page.Size,
			Index: o.Page.Index,
		}
	}

	req := &arkv1.GetConnectorsRequest{
		Txid: txid,
		Page: page,
	}

	resp, err := a.svc().GetConnectors(ctx, req)
	if err != nil {
		return nil, err
	}

	connectors := make([]indexer.TxNode, 0, len(resp.GetConnectors()))
	for _, connector := range resp.GetConnectors() {
		connectors = append(connectors, indexer.TxNode{
			Txid:     connector.GetTxid(),
			Children: connector.GetChildren(),
		})
	}

	return &indexer.ConnectorsResponse{
		Tree: connectors,
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVtxos(
	ctx context.Context, opts ...indexer.GetVtxosOption,
) (*indexer.VtxosResponse, error) {
	o, err := indexer.ApplyGetVtxosOptions(opts...)
	if err != nil {
		return nil, err
	}
	if len(o.Scripts) == 0 && len(o.Outpoints) == 0 {
		return nil, fmt.Errorf("missing opts")
	}

	if o.Page == nil && (len(o.Scripts)+len(o.Outpoints) > maxPageSize) {
		return a.paginatedGetVtxos(ctx, opts...)
	}

	var page *arkv1.IndexerPageRequest
	if o.Page != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  o.Page.Size,
			Index: o.Page.Index,
		}
	}

	req := &arkv1.GetVtxosRequest{
		Scripts:         o.Scripts,
		Outpoints:       o.FormattedOutpoints(),
		SpendableOnly:   o.SpendableOnly,
		SpentOnly:       o.SpentOnly,
		RecoverableOnly: o.RecoverableOnly,
		PendingOnly:     o.PendingOnly,
		After:           o.After,
		Before:          o.Before,
		Page:            page,
	}

	resp, err := a.svc().GetVtxos(ctx, req)
	if err != nil {
		return nil, err
	}

	return &indexer.VtxosResponse{
		Vtxos: newIndexerVtxos(resp.GetVtxos()),
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVtxoChain(
	ctx context.Context, outpoint types.Outpoint, opts ...indexer.PageOption,
) (*indexer.VtxoChainResponse, error) {
	o, err := indexer.ApplyPageOptions(opts...)
	if err != nil {
		return nil, err
	}
	var page *arkv1.IndexerPageRequest
	if o.Page != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  o.Page.Size,
			Index: o.Page.Index,
		}
	}

	req := &arkv1.GetVtxoChainRequest{
		Outpoint: &arkv1.IndexerOutpoint{
			Txid: outpoint.Txid,
			Vout: outpoint.VOut,
		},
		Page: page,
	}

	resp, err := a.svc().GetVtxoChain(ctx, req)
	if err != nil {
		return nil, err
	}

	chain := make([]indexer.ChainWithExpiry, 0, len(resp.GetChain()))
	for _, c := range resp.GetChain() {
		var txType indexer.IndexerChainedTxType
		switch c.GetType() {
		case arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_COMMITMENT:
			txType = indexer.IndexerChainedTxTypeCommitment
		case arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_ARK:
			txType = indexer.IndexerChainedTxTypeArk
		case arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_TREE:
			txType = indexer.IndexerChainedTxTypeTree
		case arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_CHECKPOINT:
			txType = indexer.IndexerChainedTxTypeCheckpoint
		default:
			txType = indexer.IndexerChainedTxTypeUnspecified
		}

		chain = append(chain, indexer.ChainWithExpiry{
			Txid:      c.GetTxid(),
			Type:      txType,
			ExpiresAt: c.GetExpiresAt(),
			Spends:    c.GetSpends(),
		})
	}

	return &indexer.VtxoChainResponse{
		Chain: chain,
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVirtualTxs(
	ctx context.Context, txids []string, opts ...indexer.PageOption,
) (*indexer.VirtualTxsResponse, error) {
	o, err := indexer.ApplyPageOptions(opts...)
	if err != nil {
		return nil, err
	}

	if o.Page == nil && len(txids) > maxPageSize {
		return a.paginatedGetVirtualTxs(ctx, txids)
	}

	var page *arkv1.IndexerPageRequest
	if o.Page != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  o.Page.Size,
			Index: o.Page.Index,
		}
	}

	req := &arkv1.GetVirtualTxsRequest{
		Txids: txids,
		Page:  page,
	}

	resp, err := a.svc().GetVirtualTxs(ctx, req)
	if err != nil {
		return nil, err
	}

	return &indexer.VirtualTxsResponse{
		Txs:  resp.GetTxs(),
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetBatchSweepTxs(
	ctx context.Context, batchOutpoint types.Outpoint,
) ([]string, error) {
	req := &arkv1.GetBatchSweepTransactionsRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
	}

	resp, err := a.svc().GetBatchSweepTransactions(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetSweptBy(), nil
}

func (a *grpcClient) NewSubscription(
	ctx context.Context, scripts []string,
) (string, <-chan indexer.ScriptEvent, func(), error) {
	resp, err := a.svc().SubscribeForScripts(ctx, &arkv1.SubscribeForScriptsRequest{
		Scripts: scripts,
	})
	if err != nil {
		return "", nil, nil, err
	}

	subscriptionId := resp.GetSubscriptionId()
	stream, closeFn, err := utils.StartReconnectingStream(ctx, utils.ReconnectingStreamConfig[
		arkv1.IndexerService_GetSubscriptionClient,
		*arkv1.GetSubscriptionResponse,
		indexer.ScriptEvent,
	]{
		Connect: func(ctx context.Context) (arkv1.IndexerService_GetSubscriptionClient, error) {
			return a.svc().GetSubscription(ctx, &arkv1.GetSubscriptionRequest{
				SubscriptionId: subscriptionId,
			})
		},
		Reconnect: func(
			ctx context.Context,
		) (string, arkv1.IndexerService_GetSubscriptionClient, error) {
			scripts := a.scripts.get(subscriptionId)
			resp, err := a.svc().SubscribeForScripts(ctx, &arkv1.SubscribeForScriptsRequest{
				Scripts: scripts,
			})
			if err != nil {
				return "", nil, err
			}
			newSubscriptionId := resp.GetSubscriptionId()
			stream, err := a.svc().GetSubscription(ctx, &arkv1.GetSubscriptionRequest{
				SubscriptionId: newSubscriptionId,
			})
			if err != nil {
				return "", nil, err
			}
			// Update the cache by replacing the subscription id for the watched scripts
			a.scripts.replace(subscriptionId, newSubscriptionId)
			return newSubscriptionId, stream, nil
		},
		Recv: func(
			stream arkv1.IndexerService_GetSubscriptionClient,
		) (**arkv1.GetSubscriptionResponse, error) {
			st, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			return &st, nil
		},
		HandleResp: func(
			ctx context.Context,
			eventsCh chan<- indexer.ScriptEvent,
			resp *arkv1.GetSubscriptionResponse,
		) error {
			var checkpointTxs map[string]indexer.TxData
			var event *arkv1.IndexerSubscriptionEvent
			switch data := resp.GetData().(type) {
			case *arkv1.GetSubscriptionResponse_Event:
				event = data.Event
				if len(event.GetCheckpointTxs()) > 0 {
					checkpointTxs = make(map[string]indexer.TxData)
					for k, v := range event.GetCheckpointTxs() {
						checkpointTxs[k] = indexer.TxData{
							Txid: v.GetTxid(),
							Tx:   v.GetTx(),
						}
					}
				}
			}
			if event == nil {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case eventsCh <- indexer.ScriptEvent{
				Data: &indexer.ScriptEventData{
					Txid:          event.GetTxid(),
					Tx:            event.GetTx(),
					Scripts:       event.GetScripts(),
					NewVtxos:      newIndexerVtxos(event.GetNewVtxos()),
					SpentVtxos:    newIndexerVtxos(event.GetSpentVtxos()),
					CheckpointTxs: checkpointTxs,
				},
			}:
				return nil
			}
		},
		ErrorEvent: func(err error) indexer.ScriptEvent {
			return indexer.ScriptEvent{Err: err}
		},
		ConnectionEvent: func(event utils.ReconnectingStreamStateEvent) indexer.ScriptEvent {
			return indexer.ScriptEvent{
				Connection: &types.StreamConnectionEvent{
					State:          toStreamConnectionState(event.State),
					At:             event.At,
					DisconnectedAt: event.DisconnectedAt,
					Err:            event.Err,
				},
			}
		},
	})
	if err != nil {
		return "", nil, nil, err
	}

	a.scripts.add(subscriptionId, scripts)

	cancelFn := func() {
		closeFn()
		a.scripts.removeSubscription(subscriptionId)
	}
	return subscriptionId, stream, cancelFn, nil
}

func (a *grpcClient) UpdateSubscription(
	ctx context.Context, subscriptionId string, scriptsToAdd, scriptsToRemove []string,
) error {
	if subscriptionId == "" {
		return fmt.Errorf("missing subscription id to update")
	}
	if len(scriptsToAdd) <= 0 && len(scriptsToRemove) <= 0 {
		return fmt.Errorf("missing scripts to add or remove")
	}

	if !a.scripts.exists(subscriptionId) {
		return fmt.Errorf("subscription not found with id %s", subscriptionId)
	}

	if len(scriptsToAdd) > 0 {
		if err := a.subscribeForScripts(ctx, subscriptionId, scriptsToAdd); err != nil {
			return err
		}
	}
	if len(scriptsToRemove) > 0 {
		if err := a.unsubscribeForScripts(ctx, subscriptionId, scriptsToRemove); err != nil {
			return err
		}
	}
	return nil
}

func (a *grpcClient) GetAsset(ctx context.Context, assetID string) (
	*indexer.AssetInfo, error,
) {
	req := &arkv1.GetAssetRequest{
		AssetId: assetID,
	}

	resp, err := a.svc().GetAsset(ctx, req)
	if err != nil {
		return nil, err
	}

	var metadata []asset.Metadata
	if md := resp.GetMetadata(); md != "" {
		metadata, err = asset.NewMetadataListFromString(md)
		if err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
	}

	return &indexer.AssetInfo{
		AssetId:        resp.GetAssetId(),
		Supply:         resp.GetSupply(),
		ControlAssetId: resp.GetControlAsset(),
		Metadata:       metadata,
	}, nil
}

func (a *grpcClient) Close() {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	// nolint:errcheck
	a.conn.Close()
}

func (a *grpcClient) svc() arkv1.IndexerServiceClient {
	a.connMu.RLock()
	defer a.connMu.RUnlock()
	return arkv1.NewIndexerServiceClient(a.conn)
}

func (a *grpcClient) subscribeForScripts(
	ctx context.Context, subscriptionId string, scripts []string,
) error {
	subId := a.scripts.resolveId(subscriptionId)

	req := &arkv1.SubscribeForScriptsRequest{
		Scripts:        scripts,
		SubscriptionId: subId,
	}

	if _, err := a.svc().SubscribeForScripts(ctx, req); err != nil {
		return err
	}

	a.scripts.add(subId, scripts)

	return nil
}

func (a *grpcClient) unsubscribeForScripts(
	ctx context.Context, subscriptionId string, scripts []string,
) error {
	subId := a.scripts.resolveId(subscriptionId)

	req := &arkv1.UnsubscribeForScriptsRequest{
		Scripts:        scripts,
		SubscriptionId: subId,
	}

	if _, err := a.svc().UnsubscribeForScripts(ctx, req); err != nil {
		return err
	}

	a.scripts.removeScripts(subId, scripts)

	return nil
}

func (a *grpcClient) paginatedGetVtxos(
	ctx context.Context, opts ...indexer.GetVtxosOption,
) (*indexer.VtxosResponse, error) {
	// nolint
	o, _ := indexer.ApplyGetVtxosOptions(opts...)
	svc := a.svc()

	vtxos, err := paginatedFetch(ctx, func(
		ctx context.Context, page *arkv1.IndexerPageRequest,
	) ([]types.Vtxo, *arkv1.IndexerPageResponse, error) {
		resp, err := svc.GetVtxos(ctx, &arkv1.GetVtxosRequest{
			Scripts:         o.Scripts,
			Outpoints:       o.FormattedOutpoints(),
			SpendableOnly:   o.SpendableOnly,
			SpentOnly:       o.SpentOnly,
			RecoverableOnly: o.RecoverableOnly,
			PendingOnly:     o.PendingOnly,
			After:           o.After,
			Before:          o.Before,
			Page:            page,
		})
		if err != nil {
			return nil, nil, err
		}
		return newIndexerVtxos(resp.GetVtxos()), resp.GetPage(), nil
	})
	if err != nil {
		return nil, err
	}
	return &indexer.VtxosResponse{Vtxos: vtxos}, nil
}

func (a *grpcClient) paginatedGetVirtualTxs(
	ctx context.Context, txids []string,
) (*indexer.VirtualTxsResponse, error) {
	svc := a.svc()

	txs, err := paginatedFetch(ctx, func(
		ctx context.Context, page *arkv1.IndexerPageRequest,
	) ([]string, *arkv1.IndexerPageResponse, error) {
		resp, err := svc.GetVirtualTxs(ctx, &arkv1.GetVirtualTxsRequest{
			Txids: txids,
			Page:  page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.GetTxs(), resp.GetPage(), nil
	})
	if err != nil {
		return nil, err
	}
	return &indexer.VirtualTxsResponse{Txs: txs}, nil
}

// paginatedFetch fetches all pages from a paginated endpoint, throttling
// requests to stay under the rate limit (20 req/sec).
func paginatedFetch[T any](
	ctx context.Context,
	fetch func(
		ctx context.Context, page *arkv1.IndexerPageRequest,
	) ([]T, *arkv1.IndexerPageResponse, error),
) ([]T, error) {
	var all []T
	pageIndex := int32(0)
	reqCount := 0
	for {
		items, page, err := fetch(ctx, &arkv1.IndexerPageRequest{
			Size:  maxPageSize,
			Index: pageIndex,
		})
		if err != nil {
			return nil, err
		}

		all = append(all, items...)
		reqCount++

		if page == nil || page.GetNext() >= page.GetTotal() {
			break
		}
		if reqCount >= maxPages {
			return nil, fmt.Errorf("too many pages (%d), aborting", maxPages)
		}
		pageIndex = page.GetNext()

		// Throttle to avoid hitting the rate limit (20 req/sec).
		if reqCount%maxReqsPerSec == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return all, nil
}

func toStreamConnectionState(
	state utils.ReconnectingStreamState,
) types.StreamConnectionState {
	switch state {
	case utils.ReconnectingStreamStateDisconnected:
		return types.StreamConnectionStateDisconnected
	case utils.ReconnectingStreamStateReconnected:
		return types.StreamConnectionStateReconnected
	default:
		return types.StreamConnectionState(state)
	}
}

func parsePage(page *arkv1.IndexerPageResponse) *indexer.PageResponse {
	if page == nil {
		return nil
	}
	return &indexer.PageResponse{
		Current: page.GetCurrent(),
		Next:    page.GetNext(),
		Total:   page.GetTotal(),
	}
}

func newIndexerVtxos(vtxos []*arkv1.IndexerVtxo) []types.Vtxo {
	res := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		res = append(res, newIndexerVtxo(vtxo))
	}
	return res
}

func newIndexerVtxo(vtxo *arkv1.IndexerVtxo) types.Vtxo {
	var assetLists []types.Asset
	for _, a := range vtxo.GetAssets() {
		if a != nil {
			assetLists = append(assetLists, types.Asset{
				AssetId: a.GetAssetId(),
				Amount:  a.GetAmount(),
			})
		}
	}

	return types.Vtxo{
		Outpoint: types.Outpoint{
			Txid: vtxo.GetOutpoint().GetTxid(),
			VOut: vtxo.GetOutpoint().GetVout(),
		},
		Script:          vtxo.GetScript(),
		CommitmentTxids: vtxo.GetCommitmentTxids(),
		Amount:          vtxo.GetAmount(),
		CreatedAt:       time.Unix(vtxo.GetCreatedAt(), 0),
		ExpiresAt:       time.Unix(vtxo.GetExpiresAt(), 0),
		Preconfirmed:    vtxo.GetIsPreconfirmed(),
		Swept:           vtxo.GetIsSwept(),
		Spent:           vtxo.GetIsSpent(),
		Unrolled:        vtxo.GetIsUnrolled(),
		SpentBy:         vtxo.GetSpentBy(),
		SettledBy:       vtxo.GetSettledBy(),
		ArkTxid:         vtxo.GetArkTxid(),
		Assets:          assetLists,
	}
}
