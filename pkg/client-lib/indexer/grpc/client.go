package indexer

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcClient struct {
	conn   *grpc.ClientConn
	connMu *sync.RWMutex
}

func NewClient(serverUrl string, _ bool) (indexer.Indexer, error) {
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
		conn:   conn,
		connMu: &sync.RWMutex{},
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
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
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

func (a *grpcClient) GetVtxoTreeLeaves(
	ctx context.Context, batchOutpoint types.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeLeavesResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
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
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ForfeitTxsResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
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
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ConnectorsResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
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
	ctx context.Context, opts ...indexer.GetVtxosRequestOption,
) (*indexer.VtxosResponse, error) {
	if len(opts) <= 0 {
		return nil, fmt.Errorf("missing opts")
	}
	opt := opts[0]

	var page *arkv1.IndexerPageRequest
	if opt.GetPage() != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	after, before := opt.GetTimeRange()
	req := &arkv1.GetVtxosRequest{
		Scripts:         opt.GetScripts(),
		Outpoints:       opt.GetOutpoints(),
		SpendableOnly:   opt.GetSpendableOnly(),
		SpentOnly:       opt.GetSpentOnly(),
		RecoverableOnly: opt.GetRecoverableOnly(),
		PendingOnly:     opt.GetPendingOnly(),
		After:           after,
		Before:          before,
		Page:            page,
	}

	resp, err := a.svc().GetVtxos(ctx, req)
	if err != nil {
		return nil, err
	}

	vtxos := make([]types.Vtxo, 0, len(resp.GetVtxos()))
	for _, vtxo := range resp.GetVtxos() {
		vtxos = append(vtxos, newIndexerVtxo(vtxo))
	}

	return &indexer.VtxosResponse{
		Vtxos: vtxos,
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVtxoChain(
	ctx context.Context, outpoint types.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoChainResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
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
	ctx context.Context, txids []string, opts ...indexer.RequestOption,
) (*indexer.VirtualTxsResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
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

func (a *grpcClient) GetSubscription(
	ctx context.Context, subscriptionId string,
) (<-chan *indexer.ScriptEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	req := &arkv1.GetSubscriptionRequest{
		SubscriptionId: subscriptionId,
	}

	stream, err := a.svc().GetSubscription(ctx, req)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	eventsCh := make(chan *indexer.ScriptEvent)
	streamMu := sync.Mutex{}

	go func() {
		defer close(eventsCh)
		backoffDelay := utils.GrpcReconnectConfig.InitialDelay

		for {
			streamMu.Lock()
			currentStream := stream
			streamMu.Unlock()

			resp, err := currentStream.Recv()
			if err != nil {
				shouldRetry, retryDelay := utils.ShouldReconnect(err)
				if !shouldRetry {
					select {
					case <-ctx.Done():
					case eventsCh <- &indexer.ScriptEvent{Err: err}:
					}
					return
				}

				if err == io.EOF {
					log.Debug("indexer subscription stream closed by server; reconnecting")
				}

				sleepDuration := max(retryDelay, backoffDelay)
				log.Debugf("subscription stream error, reconnecting in %v: %v", sleepDuration, err)

				select {
				case <-ctx.Done():
					return
				case <-time.After(sleepDuration):
				}

				newStream, dialErr := a.svc().GetSubscription(ctx, req)
				if dialErr != nil {
					shouldRetryDial, _ := utils.ShouldReconnect(dialErr)
					if !shouldRetryDial {
						select {
						case <-ctx.Done():
						case eventsCh <- &indexer.ScriptEvent{Err: dialErr}:
						}
						return
					}
					backoffDelay = min(
						time.Duration(float64(backoffDelay)*utils.GrpcReconnectConfig.Multiplier),
						utils.GrpcReconnectConfig.MaxDelay,
					)
					log.Debugf("subscription stream reconnect failed, retrying: %v", dialErr)
					continue
				}

				streamMu.Lock()
				stream = newStream
				streamMu.Unlock()
				backoffDelay = utils.GrpcReconnectConfig.InitialDelay
				continue
			}

			backoffDelay = utils.GrpcReconnectConfig.InitialDelay

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
			if event != nil {
				eventsCh <- &indexer.ScriptEvent{
					Txid:          event.GetTxid(),
					Tx:            event.GetTx(),
					Scripts:       event.GetScripts(),
					NewVtxos:      newIndexerVtxos(event.GetNewVtxos()),
					SpentVtxos:    newIndexerVtxos(event.GetSpentVtxos()),
					CheckpointTxs: checkpointTxs,
				}
			}

		}
	}()

	closeFn := func() {
		cancel()
		streamMu.Lock()
		defer streamMu.Unlock()
		if err := stream.CloseSend(); err != nil {
			log.Warnf("failed to close subscription stream: %v", err)
		}
	}

	return eventsCh, closeFn, nil
}

func (a *grpcClient) SubscribeForScripts(
	ctx context.Context, subscriptionId string, scripts []string,
) (string, error) {
	req := &arkv1.SubscribeForScriptsRequest{
		Scripts: scripts,
	}
	if len(subscriptionId) > 0 {
		req.SubscriptionId = subscriptionId
	}

	resp, err := a.svc().SubscribeForScripts(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetSubscriptionId(), nil
}

func (a *grpcClient) UnsubscribeForScripts(
	ctx context.Context, subscriptionId string, scripts []string,
) error {
	req := &arkv1.UnsubscribeForScriptsRequest{
		Scripts: scripts,
	}
	if len(subscriptionId) > 0 {
		req.SubscriptionId = subscriptionId
	}
	_, err := a.svc().UnsubscribeForScripts(ctx, req)
	if err != nil {
		return err
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
