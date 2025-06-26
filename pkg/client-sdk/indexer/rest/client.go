package indexer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/indexer"
	"github.com/ark-network/ark/pkg/client-sdk/indexer/rest/service/indexerservice"
	"github.com/ark-network/ark/pkg/client-sdk/indexer/rest/service/indexerservice/indexer_service"
	"github.com/ark-network/ark/pkg/client-sdk/indexer/rest/service/models"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type restClient struct {
	serverURL      string
	svc            indexer_service.ClientService
	requestTimeout time.Duration
}

// NewClient creates a new REST client for the Indexer service
func NewClient(serverURL string) (indexer.Indexer, error) {
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

func (a *restClient) GetCommitmentTx(ctx context.Context, txid string) (*indexer.CommitmentTx, error) {
	params := indexer_service.NewIndexerServiceGetCommitmentTxParams().WithTxid(txid)
	resp, err := a.svc.IndexerServiceGetCommitmentTx(params)
	if err != nil {
		return nil, err
	}

	batches := make(map[uint32]*indexer.Batch)
	for vout, batch := range resp.Payload.Batches {
		voutUint32, err := strconv.ParseUint(vout, 10, 32)
		if err != nil {
			return nil, err
		}

		totalOutputAmount, err := strconv.ParseUint(batch.TotalOutputAmount, 10, 64)
		if err != nil {
			return nil, err
		}
		totalOutputVtxos := int(batch.TotalOutputVtxos)

		expiresAt, err := strconv.ParseInt(batch.ExpiresAt, 10, 64)
		if err != nil {
			return nil, err
		}

		batches[uint32(voutUint32)] = &indexer.Batch{
			TotalOutputAmount: totalOutputAmount,
			TotalOutputVtxos:  int32(totalOutputVtxos),
			ExpiresAt:         expiresAt,
			Swept:             batch.Swept,
		}
	}

	startedAt, err := strconv.ParseInt(resp.Payload.StartedAt, 10, 64)
	if err != nil {
		return nil, err
	}

	endedAt, err := strconv.ParseInt(resp.Payload.EndedAt, 10, 64)
	if err != nil {
		return nil, err
	}

	totOutputAmount, err := strconv.ParseUint(resp.Payload.TotalOutputAmount, 10, 64)
	if err != nil {
		return nil, err
	}
	totInputAmount, err := strconv.ParseUint(resp.Payload.TotalInputAmount, 10, 64)
	if err != nil {
		return nil, err
	}

	return &indexer.CommitmentTx{
		StartedAt:         startedAt,
		EndedAt:           endedAt,
		Batches:           batches,
		TotalInputAmount:  totInputAmount,
		TotalInputVtxos:   resp.Payload.TotalInputVtxos,
		TotalOutputAmount: totOutputAmount,
		TotalOutputVtxos:  resp.Payload.TotalOutputVtxos,
	}, nil
}

func (a *restClient) GetCommitmentTxLeaves(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.CommitmentTxLeavesResponse, error) {
	params := indexer_service.NewIndexerServiceGetCommitmentTxLeavesParams().
		WithTxid(txid)

	if len(opts) > 0 {
		page := opts[0].GetPage()
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetCommitmentTxLeaves(params)
	if err != nil {
		return nil, err
	}

	leaves := make([]indexer.Outpoint, 0, len(resp.Payload.Leaves))
	for _, leaf := range resp.Payload.Leaves {
		leaves = append(leaves, indexer.Outpoint{
			Txid: leaf.Txid,
			VOut: uint32(leaf.Vout),
		})
	}

	return &indexer.CommitmentTxLeavesResponse{
		Leaves: leaves,
		Page:   parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetVtxoTree(
	ctx context.Context, batchOutpoint indexer.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeResponse, error) {
	params := indexer_service.NewIndexerServiceGetVtxoTreeParams().
		WithBatchOutpointTxid(batchOutpoint.Txid).
		WithBatchOutpointVout(int64(batchOutpoint.VOut))

	if len(opts) > 0 {
		page := opts[0].GetPage()
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetVtxoTree(params)
	if err != nil {
		return nil, err
	}

	nodes := make([]indexer.TxNode, 0, len(resp.Payload.VtxoTree))
	for _, node := range resp.Payload.VtxoTree {
		children := make(map[uint32]string)
		for k, v := range node.Children {
			vout, err := strconv.ParseUint(k, 10, 32)
			if err != nil {
				return nil, err
			}
			children[uint32(vout)] = v
		}
		nodes = append(nodes, indexer.TxNode{
			Txid:     node.Txid,
			Children: children,
		})
	}

	return &indexer.VtxoTreeResponse{
		Tree: nodes,
		Page: parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetFullVtxoTree(
	ctx context.Context, batchOutpoint indexer.Outpoint, opts ...indexer.RequestOption,
) ([]tree.TxGraphChunk, error) {
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
	ctx context.Context, batchOutpoint indexer.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeLeavesResponse, error) {
	params := indexer_service.NewIndexerServiceGetVtxoTreeLeavesParams().
		WithBatchOutpointTxid(batchOutpoint.Txid).
		WithBatchOutpointVout(int64(batchOutpoint.VOut))

	if len(opts) > 0 {
		page := opts[0].GetPage()
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetVtxoTreeLeaves(params)
	if err != nil {
		return nil, err
	}

	leaves := make([]indexer.Outpoint, 0, len(resp.Payload.Leaves))
	for _, leaf := range resp.Payload.Leaves {
		leaves = append(leaves, indexer.Outpoint{
			Txid: leaf.Txid,
			VOut: uint32(leaf.Vout),
		})
	}

	return &indexer.VtxoTreeLeavesResponse{
		Leaves: leaves,
		Page:   parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetForfeitTxs(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ForfeitTxsResponse, error) {
	params := indexer_service.NewIndexerServiceGetForfeitTxsParams().
		WithTxid(txid)

	if len(opts) > 0 {
		page := opts[0].GetPage()
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetForfeitTxs(params)
	if err != nil {
		return nil, err
	}

	return &indexer.ForfeitTxsResponse{
		Txids: resp.Payload.Txids,
		Page:  parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetConnectors(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ConnectorsResponse, error) {
	params := indexer_service.NewIndexerServiceGetConnectorsParams().
		WithTxid(txid)

	if len(opts) > 0 {
		page := opts[0].GetPage()
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetConnectors(params)
	if err != nil {
		return nil, err
	}

	connectors := make([]indexer.TxNode, 0, len(resp.Payload.Connectors))
	for _, connector := range resp.Payload.Connectors {
		children := make(map[uint32]string)
		for k, v := range connector.Children {
			vout, err := strconv.ParseUint(k, 10, 32)
			if err != nil {
				return nil, err
			}
			children[uint32(vout)] = v
		}

		connectors = append(connectors, indexer.TxNode{
			Txid:     connector.Txid,
			Children: children,
		})
	}

	return &indexer.ConnectorsResponse{
		Tree: connectors,
		Page: parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetVtxos(
	ctx context.Context, opts ...indexer.GetVtxosRequestOption,
) (*indexer.VtxosResponse, error) {
	if len(opts) <= 0 {
		return nil, fmt.Errorf("missing opts")
	}
	opt := opts[0]
	spentOnly := opt.GetSpentOnly()
	spendableOnly := opt.GetSpendableOnly()

	params := indexer_service.NewIndexerServiceGetVtxosParams().
		WithAddresses(opt.GetAddresses()).WithOutpoints(opt.GetOutpoints()).
		WithSpentOnly(&spentOnly).WithSpendableOnly(&spendableOnly)

	if page := opt.GetPage(); page != nil {
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetVtxos(params)
	if err != nil {
		return nil, err
	}

	vtxos, err := newIndexerVtxos(resp.Payload.Vtxos)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vtxos: %s", err)
	}

	return &indexer.VtxosResponse{
		Vtxos: vtxos,
		Page:  parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetTransactionHistory(
	ctx context.Context, address string, opts ...indexer.GetTxHistoryRequestOption,
) (*indexer.TxHistoryResponse, error) {
	params := indexer_service.NewIndexerServiceGetTransactionHistoryParams().
		WithAddress(address)

	if len(opts) > 0 {
		if page := opts[0].GetPage(); page != nil {
			params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
		}
		startTime := opts[0].GetStartTime()
		endTime := opts[0].GetEndTime()
		if !startTime.IsZero() && !endTime.IsZero() && startTime.After(endTime) {
			return nil, status.Errorf(codes.InvalidArgument, "start_time must be before end_time")
		}

		if !startTime.IsZero() {
			startTimeStr := strconv.FormatInt(startTime.Unix(), 10)
			params.WithStartTime(&startTimeStr)
		}
		if !endTime.IsZero() {
			endTimeStr := strconv.FormatInt(endTime.Unix(), 10)
			params.WithEndTime(&endTimeStr)
		}
	}

	resp, err := a.svc.IndexerServiceGetTransactionHistory(params)
	if err != nil {
		return nil, err
	}

	history := make([]types.Transaction, 0, len(resp.Payload.History))
	for _, record := range resp.Payload.History {
		amount, err := strconv.ParseUint(record.Amount, 10, 64)
		if err != nil {
			return nil, err
		}
		createdAt, err := strconv.ParseInt(record.CreatedAt, 10, 64)
		if err != nil {
			return nil, err
		}

		// Use a zero value for TxType if Type is nil, otherwise use a numeric conversion
		var txType types.TxType
		if record.Type != nil {
			// Convert the string enum to a numeric value
			typeStr := string(*record.Type)
			switch typeStr {
			case "INDEXER_TX_TYPE_RECEIVED":
				txType = types.TxReceived
			case "INDEXER_TX_TYPE_SENT":
				txType = types.TxSent
			}
		}

		history = append(history, types.Transaction{
			TransactionKey: types.TransactionKey{
				CommitmentTxid: record.CommitmentTxid,
				ArkTxid:        record.VirtualTxid,
			},
			Type:      txType,
			Amount:    amount,
			CreatedAt: time.Unix(createdAt, 0),
			Settled:   record.IsSettled,
		})
	}

	return &indexer.TxHistoryResponse{
		History: history,
		Page:    parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetVtxoChain(
	ctx context.Context, outpoint indexer.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoChainResponse, error) {
	params := indexer_service.NewIndexerServiceGetVtxoChainParams().
		WithOutpointTxid(outpoint.Txid).
		WithOutpointVout(int64(outpoint.VOut))

	if len(opts) > 0 {
		page := opts[0].GetPage()
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetVtxoChain(params)
	if err != nil {
		return nil, err
	}

	chain := make([]indexer.ChainWithExpiry, 0, len(resp.Payload.Chain))
	for _, v := range resp.Payload.Chain {
		expiresAt, err := strconv.ParseInt(v.ExpiresAt, 10, 64)
		if err != nil {
			return nil, err
		}

		var txType indexer.IndexerChainedTxType
		switch *v.Type {
		case models.V1IndexerChainedTxTypeINDEXERCHAINEDTXTYPECOMMITMENT:
			txType = indexer.IndexerChainedTxTypeCommitment
		case models.V1IndexerChainedTxTypeINDEXERCHAINEDTXTYPEARK:
			txType = indexer.IndexerChainedTxTypeArk
		case models.V1IndexerChainedTxTypeINDEXERCHAINEDTXTYPETREE:
			txType = indexer.IndexerChainedTxTypeTree
		case models.V1IndexerChainedTxTypeINDEXERCHAINEDTXTYPECHECKPOINT:
			txType = indexer.IndexerChainedTxTypeCheckpoint
		default:
			txType = indexer.IndexerChainedTxTypeUnspecified
		}
		chain = append(chain, indexer.ChainWithExpiry{
			Txid:      v.Txid,
			ExpiresAt: expiresAt,
			Type:      txType,
			Spends:    v.Spends,
		})
	}

	return &indexer.VtxoChainResponse{
		Chain: chain,
		Page:  parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetVirtualTxs(
	ctx context.Context, txids []string, opts ...indexer.RequestOption,
) (*indexer.VirtualTxsResponse, error) {
	params := indexer_service.NewIndexerServiceGetVirtualTxsParams().
		WithTxids(txids)

	if len(opts) > 0 {
		page := opts[0].GetPage()
		params.WithPageSize(&page.Size).WithPageIndex(&page.Index)
	}

	resp, err := a.svc.IndexerServiceGetVirtualTxs(params)
	if err != nil {
		return nil, err
	}

	return &indexer.VirtualTxsResponse{
		Txs:  resp.Payload.Txs,
		Page: parsePage(resp.Payload.Page),
	}, nil
}

func (a *restClient) GetSweptCommitmentTx(ctx context.Context, txid string) ([]string, error) {
	params := indexer_service.NewIndexerServiceGetSweptCommitmentTxParams().WithTxid(txid)

	resp, err := a.svc.IndexerServiceGetSweptCommitmentTx(params)
	if err != nil {
		return nil, err
	}

	return resp.Payload.SweptBy, nil
}

func (a *restClient) GetSubscription(ctx context.Context, subscriptionId string) (<-chan *indexer.ScriptEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	eventsCh := make(chan *indexer.ScriptEvent)
	chunkCh := make(chan chunk)
	url := fmt.Sprintf("%s/v1/script/subscription/%s", a.serverURL, subscriptionId)

	go listenToStream(url, chunkCh)

	go func(eventsCh chan *indexer.ScriptEvent, chunkCh chan chunk) {
		defer close(eventsCh)

		for {
			select {
			case <-ctx.Done():
				return
			case chunk := <-chunkCh:
				if chunk.err == nil && len(chunk.msg) == 0 {
					continue
				}

				if chunk.err != nil {
					eventsCh <- &indexer.ScriptEvent{Err: chunk.err}
					return
				}

				resp := indexer_service.IndexerServiceGetSubscriptionOKBody{}
				if err := json.Unmarshal(chunk.msg, &resp); err != nil {
					eventsCh <- &indexer.ScriptEvent{
						Err: fmt.Errorf("failed to parse message from address stream: %s", err),
					}
					return
				}

				emptyResp := indexer_service.IndexerServiceGetSubscriptionOKBody{}
				if resp == emptyResp {
					continue
				}

				if resp.Error != nil {
					eventsCh <- &indexer.ScriptEvent{
						Err: fmt.Errorf("received error from address stream: %s", resp.Error.Message),
					}
					return
				}

				newVtxos, err := newIndexerVtxos(resp.Result.NewVtxos)
				if err != nil {
					eventsCh <- &indexer.ScriptEvent{
						Err: fmt.Errorf("failed to parse new vtxos: %s", err),
					}
					return
				}

				spentVtxos, err := newIndexerVtxos(resp.Result.SpentVtxos)
				if err != nil {
					eventsCh <- &indexer.ScriptEvent{
						Err: fmt.Errorf("failed to parse spent vtxos: %s", err),
					}
					return
				}

				eventsCh <- &indexer.ScriptEvent{
					Txid:       resp.Result.Txid,
					Scripts:    resp.Result.Scripts,
					NewVtxos:   newVtxos,
					SpentVtxos: spentVtxos,
				}
			}
		}
	}(eventsCh, chunkCh)

	return eventsCh, cancel, nil
}

func (a *restClient) SubscribeForScripts(ctx context.Context, subscriptionId string, scripts []string) (string, error) {
	body := &models.V1SubscribeForScriptsRequest{
		Scripts: scripts,
	}

	if len(subscriptionId) > 0 {
		body.SubscriptionID = subscriptionId
	}

	params := indexer_service.NewIndexerServiceSubscribeForScriptsParams().WithDefaults().WithBody(body)
	resp, err := a.svc.IndexerServiceSubscribeForScripts(params)
	if err != nil {
		return "", err
	}

	return resp.Payload.SubscriptionID, nil
}

func (a *restClient) UnsubscribeForScripts(ctx context.Context, subscriptionId string, scripts []string) error {
	body := &models.V1UnsubscribeForScriptsRequest{
		Scripts: scripts,
	}

	params := indexer_service.NewIndexerServiceUnsubscribeForScriptsParams().WithDefaults().WithBody(body)
	_, err := a.svc.IndexerServiceUnsubscribeForScripts(params)
	if err != nil {
		return err
	}

	return nil
}

func (a *restClient) Close() {}

func newRestClient(
	serviceURL string,
) (indexer_service.ClientService, error) {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, err
	}

	schemes := []string{parsedURL.Scheme}
	host := parsedURL.Host
	basePath := parsedURL.Path

	if basePath == "" {
		basePath = indexerservice.DefaultBasePath
	}

	cfg := &indexerservice.TransportConfig{
		Host:     host,
		BasePath: basePath,
		Schemes:  schemes,
	}

	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	svc := indexerservice.New(transport, strfmt.Default)
	return svc.IndexerService, nil
}

func parsePage(page *models.V1IndexerPageResponse) *indexer.PageResponse {
	if page == nil {
		return nil
	}
	return &indexer.PageResponse{
		Current: page.Current,
		Next:    page.Next,
		Total:   page.Total,
	}
}

type chunk struct {
	msg []byte
	err error
}

func listenToStream(url string, chunkCh chan chunk) {
	defer close(chunkCh)

	httpClient := &http.Client{Timeout: time.Second * 0}

	resp, err := httpClient.Get(url)
	if err != nil {
		chunkCh <- chunk{err: err}
		return
	}
	// nolint:all
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		chunkCh <- chunk{err: fmt.Errorf(
			"got unexpected status %d code", resp.StatusCode,
		)}
		return
	}

	reader := bufio.NewReader(resp.Body)
	for {
		msg, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				err = client.ErrConnectionClosedByServer
			}
			chunkCh <- chunk{err: err}
			return
		}
		msg = bytes.Trim(msg, "\n")
		chunkCh <- chunk{msg: msg}
	}
}

func newIndexerVtxos(restVtxos []*models.V1IndexerVtxo) ([]types.Vtxo, error) {
	vtxos := make([]types.Vtxo, 0, len(restVtxos))
	for _, vtxo := range restVtxos {
		vtxo, err := newIndexerVtxo(vtxo)
		if err != nil {
			return nil, err
		}
		vtxos = append(vtxos, *vtxo)
	}
	return vtxos, nil
}

func newIndexerVtxo(vtxo *models.V1IndexerVtxo) (*types.Vtxo, error) {
	createdAt, err := strconv.ParseInt(vtxo.CreatedAt, 10, 64)
	if err != nil {
		return nil, err
	}

	expiresAt, err := strconv.ParseInt(vtxo.ExpiresAt, 10, 64)
	if err != nil {
		return nil, err
	}

	amount, err := strconv.ParseUint(vtxo.Amount, 10, 64)
	if err != nil {
		return nil, err
	}
	return &types.Vtxo{
		VtxoKey: types.VtxoKey{
			Txid: vtxo.Outpoint.Txid,
			VOut: uint32(vtxo.Outpoint.Vout),
		},
		Script:          vtxo.Script,
		CommitmentTxids: vtxo.CommitmentTxids,
		Amount:          amount,
		CreatedAt:       time.Unix(createdAt, 0),
		ExpiresAt:       time.Unix(expiresAt, 0),
		Preconfirmed:    vtxo.IsPreconfirmed,
		Swept:           vtxo.IsSwept,
		Redeemed:        vtxo.IsRedeemed,
		Spent:           vtxo.IsSpent,
		SpentBy:         vtxo.SpentBy,
	}, nil
}
