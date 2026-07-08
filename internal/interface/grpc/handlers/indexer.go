package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkdErrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type indexerService struct {
	indexerSvc application.IndexerService
	eventsCh   <-chan application.TransactionEvent

	scriptSubsHandler           *broker[*arkv1.GetSubscriptionResponse]
	subscriptionTimeoutDuration time.Duration

	heartbeat time.Duration
}

func NewIndexerService(
	indexerSvc application.IndexerService, eventsCh <-chan application.TransactionEvent,
	subscriptionTimeoutDuration time.Duration, heartbeat int64,
) arkv1.IndexerServiceServer {
	svc := &indexerService{
		indexerSvc:                  indexerSvc,
		eventsCh:                    eventsCh,
		scriptSubsHandler:           newBroker[*arkv1.GetSubscriptionResponse](),
		subscriptionTimeoutDuration: subscriptionTimeoutDuration,
		heartbeat:                   time.Duration(heartbeat) * time.Second,
	}

	go svc.listenToTxEvents()

	return svc
}

func (e *indexerService) GetAsset(ctx context.Context, request *arkv1.GetAssetRequest) (
	*arkv1.GetAssetResponse, error,
) {
	assetId := request.GetAssetId()
	if assetId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing asset id")
	}

	assets, err := e.indexerSvc.GetAsset(ctx, assetId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}
	if len(assets) <= 0 {
		return nil, status.Errorf(codes.NotFound, "asset %s not found", assetId)
	}
	ast := assets[0]
	var metadata string
	if len(ast.Metadata) > 0 {
		md, _ := asset.NewMetadataList(ast.Metadata)
		metadata = md.String()
	}

	return &arkv1.GetAssetResponse{
		AssetId:      assetId,
		Supply:       ast.Supply.String(),
		Metadata:     metadata,
		ControlAsset: ast.ControlAssetId,
	}, nil
}

func (e *indexerService) GetCommitmentTx(
	ctx context.Context, request *arkv1.GetCommitmentTxRequest,
) (*arkv1.GetCommitmentTxResponse, error) {
	txid, err := parseTxid(request.GetTxid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetCommitmentTxInfo(ctx, txid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	batches := make(map[uint32]*arkv1.IndexerBatch)
	for vout, batch := range resp.Batches {
		batches[uint32(vout)] = &arkv1.IndexerBatch{
			TotalOutputAmount: batch.TotalOutputAmount,
			TotalOutputVtxos:  batch.TotalOutputVtxos,
			ExpiresAt:         batch.ExpiresAt,
			Swept:             batch.Swept,
		}
	}

	return &arkv1.GetCommitmentTxResponse{
		StartedAt:         resp.StartedAt,
		EndedAt:           resp.EndAt,
		Batches:           batches,
		TotalInputAmount:  resp.TotalInputAmount,
		TotalInputVtxos:   resp.TotalInputVtxos,
		TotalOutputAmount: resp.TotalOutputAmount,
		TotalOutputVtxos:  resp.TotalOutputVtxos,
	}, nil
}

func (e *indexerService) GetVtxoTree(
	ctx context.Context, request *arkv1.GetVtxoTreeRequest,
) (*arkv1.GetVtxoTreeResponse, error) {
	batchOutpoint, err := parseOutpoint(request.GetBatchOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetVtxoTree(ctx, *batchOutpoint, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	nodes := make([]*arkv1.IndexerNode, len(resp.Txs))
	for i, node := range resp.Txs {
		nodes[i] = &arkv1.IndexerNode{
			Txid:     node.Txid,
			Children: node.Children,
		}
	}

	return &arkv1.GetVtxoTreeResponse{
		VtxoTree: nodes,
		Page:     protoPage(resp.Page),
	}, nil
}

func (e *indexerService) GetVtxoTreeLeaves(
	ctx context.Context, request *arkv1.GetVtxoTreeLeavesRequest,
) (*arkv1.GetVtxoTreeLeavesResponse, error) {
	outpoint, err := parseOutpoint(request.GetBatchOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetVtxoTreeLeaves(ctx, *outpoint, page)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	leaves := make([]*arkv1.IndexerOutpoint, 0, len(resp.Leaves))
	for _, leaf := range resp.Leaves {
		leaves = append(leaves, &arkv1.IndexerOutpoint{
			Txid: leaf.Txid,
			Vout: leaf.VOut,
		})
	}

	return &arkv1.GetVtxoTreeLeavesResponse{
		Leaves: leaves,
		Page:   protoPage(resp.Page),
	}, nil
}

func (e *indexerService) GetForfeitTxs(
	ctx context.Context, request *arkv1.GetForfeitTxsRequest,
) (*arkv1.GetForfeitTxsResponse, error) {
	txid, err := parseTxid(request.GetTxid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetForfeitTxs(ctx, txid, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetForfeitTxsResponse{
		Txids: resp.Txs,
		Page:  protoPage(resp.Page),
	}, nil
}

func (e *indexerService) GetConnectors(
	ctx context.Context, request *arkv1.GetConnectorsRequest,
) (*arkv1.GetConnectorsResponse, error) {
	txid, err := parseTxid(request.GetTxid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetConnectors(ctx, txid, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	connectors := make([]*arkv1.IndexerNode, len(resp.Txs))
	for i, connector := range resp.Txs {
		connectors[i] = &arkv1.IndexerNode{
			Txid:     connector.Txid,
			Children: connector.Children,
		}
	}

	return &arkv1.GetConnectorsResponse{
		Connectors: connectors,
		Page:       protoPage(resp.Page),
	}, nil
}

func (e *indexerService) GetVtxos(
	ctx context.Context, request *arkv1.GetVtxosRequest,
) (*arkv1.GetVtxosResponse, error) {
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	pubkeys := make([]string, 0, len(request.GetScripts()))
	for _, script := range request.GetScripts() {
		script, err := parseScript(script)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		pubkeys = append(pubkeys, script[4:])
	}

	outpoints, err := parseOutpoints(request.GetOutpoints())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if len(outpoints) == 0 && len(pubkeys) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing outpoints or scripts filter")
	}
	if len(outpoints) > 0 && len(pubkeys) > 0 {
		return nil, status.Error(
			codes.InvalidArgument, "outpoints and scripts filters are mutually exclusive",
		)
	}

	spendableOnly := request.GetSpendableOnly()
	spentOnly := request.GetSpentOnly()
	recoverableOnly := request.GetRecoverableOnly()
	pendingOnly := request.GetPendingOnly()

	var resp *application.GetVtxosResp

	if len(pubkeys) > 0 {
		// Validate filters
		// TODO: get rid of this and move to oneof in the protos
		options := []bool{spendableOnly, spentOnly, recoverableOnly, pendingOnly}

		count := 0
		for _, v := range options {
			if v {
				count++
			}
		}
		if count > 1 {
			return nil, status.Error(
				codes.InvalidArgument,
				"spendable, spent, recoverable and pending filters are mutually exclusive",
			)
		}

		after, before, err := parseTimeRange(request.GetAfter(), request.GetBefore())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		resp, err = e.indexerSvc.GetVtxos(
			ctx, pubkeys,
			spendableOnly, spentOnly, recoverableOnly, pendingOnly, after, before, page,
		)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%s", err.Error())
		}
	}
	if len(outpoints) > 0 {
		resp, err = e.indexerSvc.GetVtxosByOutpoint(ctx, outpoints, page)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	vtxos := make([]*arkv1.IndexerVtxo, 0, len(resp.Vtxos))
	for _, vtxo := range resp.Vtxos {
		vtxos = append(vtxos, newIndexerVtxo(vtxo))
	}

	return &arkv1.GetVtxosResponse{
		Vtxos: vtxos,
		Page:  protoPage(resp.Page),
	}, nil
}

func (e *indexerService) GetVtxoChain(
	ctx context.Context, request *arkv1.GetVtxoChainRequest,
) (*arkv1.GetVtxoChainResponse, error) {
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	var resp *application.VtxoChainResp

	if request.GetIntent() != nil {
		// Cursor pagination is continued via the auth_token returned by the
		// first call, not by re-submitting the intent proof. Reject page_token
		// here instead of silently ignoring it.
		if request.GetPageToken() != "" {
			return nil, status.Error(
				codes.InvalidArgument,
				"page_token is not supported with intent; "+
					"use the returned auth_token to paginate",
			)
		}
		intent, parseErr := parseIndexerIntent(request.GetIntent())
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, parseErr.Error())
		}
		resp, err = e.indexerSvc.GetVtxoChainByIntent(ctx, *intent, page)
	} else {
		outpoint, parseErr := parseOutpoint(request.GetOutpoint())
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, parseErr.Error())
		}
		resp, err = e.indexerSvc.GetVtxoChain(
			ctx, request.GetToken(), *outpoint, page, request.GetPageToken(),
		)
	}
	if err != nil {
		if errors.Is(err, application.ErrInvalidInput) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	chain := make([]*arkv1.IndexerChain, 0)
	for _, c := range resp.Chain {
		var txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_UNSPECIFIED
		switch c.Type {
		case application.IndexerChainedTxTypeCommitment:
			txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_COMMITMENT
		case application.IndexerChainedTxTypeArk:
			txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_ARK
		case application.IndexerChainedTxTypeTree:
			txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_TREE
		case application.IndexerChainedTxTypeCheckpoint:
			txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_CHECKPOINT
		}

		chain = append(chain, &arkv1.IndexerChain{
			Txid:      c.Txid,
			ExpiresAt: c.ExpiresAt,
			Type:      txType,
			Spends:    c.Spends,
		})
	}

	return &arkv1.GetVtxoChainResponse{
		Chain:         chain,
		Page:          protoPage(resp.Page),
		AuthToken:     resp.AuthToken,
		NextPageToken: resp.NextPageToken,
	}, nil
}

func (e *indexerService) GetVirtualTxs(
	ctx context.Context, request *arkv1.GetVirtualTxsRequest,
) (*arkv1.GetVirtualTxsResponse, error) {
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	var resp *application.VirtualTxsResp
	if request.GetIntent() != nil {
		intent, parseErr := parseIndexerIntent(request.GetIntent())
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, parseErr.Error())
		}
		resp, err = e.indexerSvc.GetVirtualTxsByIntent(ctx, *intent, page)
	} else {
		txids, parseErr := parseTxids(request.GetTxids())
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, parseErr.Error())
		}
		resp, err = e.indexerSvc.GetVirtualTxs(ctx, request.GetToken(), txids, page)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.GetVirtualTxsResponse{
		Txs:  resp.Txs,
		Page: protoPage(resp.Page),
	}, nil
}

func (e *indexerService) GetBatchSweepTransactions(
	ctx context.Context, request *arkv1.GetBatchSweepTransactionsRequest,
) (*arkv1.GetBatchSweepTransactionsResponse, error) {
	outpoint, err := parseOutpoint(request.GetBatchOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	sweepTxs, err := e.indexerSvc.GetBatchSweepTxs(ctx, *outpoint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetBatchSweepTransactionsResponse{
		SweptBy: sweepTxs,
	}, nil
}

func (h *indexerService) GetSubscription(
	request *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer,
) error {
	subscriptionId := request.GetSubscriptionId()

	isNew := len(subscriptionId) == 0
	if isNew {
		// New single-connection flow: create subscription inline.
		subscriptionId = uuid.NewString()
		h.scriptSubsHandler.pushListener(
			newListener[*arkv1.GetSubscriptionResponse](subscriptionId, nil),
		)
	}

	// Attach as the subscription's sole consumer. Reconnecting with the same
	// subscription id displaces the previous stream: an abandoned stream whose
	// disconnect the server never observed (e.g. behind a load balancer that
	// keeps the connection alive) is terminated instead of competing with the
	// new stream for events forever.
	listener, att, err := h.scriptSubsHandler.attach(subscriptionId)
	if err != nil {
		if isNew {
			// The listener we just pushed has no other owner; remove it so a
			// failed attach cannot leak it.
			h.scriptSubsHandler.removeListener(subscriptionId)
		}
		return subscriptionErr(subscriptionId, err)
	}
	defer func() {
		if !h.scriptSubsHandler.detach(subscriptionId, att) {
			// Displaced by a newer stream: the successor owns the
			// subscription's lifecycle now.
			return
		}
		if isNew {
			h.scriptSubsHandler.removeListener(subscriptionId)
			return
		}
		// Keep the listener alive on disconnect if either filter type is
		// non-empty, so the client can reconnect within the timeout window
		// without losing scripts or tx filters.
		topics := h.scriptSubsHandler.getTopics(subscriptionId)
		txFilters := h.scriptSubsHandler.getTxFilters(subscriptionId)
		if len(topics) > 0 || len(txFilters) > 0 {
			h.scriptSubsHandler.startTimeout(subscriptionId, h.subscriptionTimeoutDuration)
		} else {
			h.scriptSubsHandler.removeListener(subscriptionId)
		}
	}()

	if isNew {
		// Apply initial filter, if any, through the same machinery used by
		// UpdateSubscription. `scripts.remove` is ignored on creation
		// because the subscription has no scripts to remove yet.
		if filter := request.GetFilter(); filter != nil {
			if err := h.applyFilter(subscriptionId, filter, true); err != nil {
				return err
			}
		}

		// Send SubscriptionStartedEvent as first message.
		startedEvt := &arkv1.GetSubscriptionResponse{
			Data: &arkv1.GetSubscriptionResponse_SubscriptionStarted{
				SubscriptionStarted: &arkv1.SubscriptionStartedEvent{
					SubscriptionId: subscriptionId,
				},
			},
		}
		if err := stream.Send(startedEvt); err != nil {
			return err
		}
	}

	// create a Timer that will fire after one heartbeat interval
	timer := time.NewTimer(h.heartbeat)
	defer timer.Stop()

	// helper to safely reset the timer
	resetTimer := func() {
		if !timer.Stop() {
			// drain if it already fired
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(h.heartbeat)
	}

	for {
		// Two selects on purpose. A single select cannot express priority: Go
		// picks among ready cases at random, so with one combined select a
		// stream that was just displaced (or whose subscription was removed)
		// could still win `ev := <-listener.ch` and drain an event meant for
		// its successor, or push it to a client that is already gone.
		//
		// This first select is non-blocking (note the default): it returns
		// early when an exit signal is ALREADY pending, before the receive
		// below can run, leaving buffered events on the channel for the
		// successor.
		select {
		case <-stream.Context().Done():
			return nil
		case <-listener.done:
			return nil
		case <-att.displaced:
			return nil
		default:
		}

		// The blocking select does the actual work: it parks until an event, a
		// heartbeat, or an exit signal arrives. The exit cases are repeated here
		// (not only in the priority check above) so that a signal arriving WHILE
		// this select is blocked wakes the stream immediately, instead of
		// stalling until the next event or heartbeat.
		select {
		case <-stream.Context().Done():
			return nil
		case <-listener.done:
			// Subscription removed (unsubscribed, or reaped after the
			// reconnect window expired).
			return nil
		case <-att.displaced:
			// The client reconnected with the same subscription id on a new
			// stream; this stream is abandoned.
			return nil
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
			resetTimer()
		case <-timer.C:
			hb := &arkv1.GetSubscriptionResponse{
				Data: &arkv1.GetSubscriptionResponse_Heartbeat{
					Heartbeat: &arkv1.IndexerHeartbeat{},
				},
			}
			if err := stream.Send(hb); err != nil {
				return err
			}
			resetTimer()
		}
	}
}

func (h *indexerService) UpdateSubscription(
	ctx context.Context, req *arkv1.UpdateSubscriptionRequest,
) (*arkv1.UpdateSubscriptionResponse, error) {
	if req.GetSubscriptionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing subscription id")
	}

	filter := req.GetFilter()
	if filter == nil {
		return nil, status.Error(codes.InvalidArgument, "missing filter")
	}

	if err := h.applyFilter(req.GetSubscriptionId(), filter, false); err != nil {
		return nil, err
	}
	return &arkv1.UpdateSubscriptionResponse{}, nil
}

// applyFilter applies the expressions and script mutations carried by a
// SubscriptionFilter. Expressions are always overwritten as a whole
// (including with an empty list, which clears them). Scripts are mutated
// with the same semantics as SubscribeForScripts / UnsubscribeForScripts:
// if both `add` and `remove` are empty the call removes all scripts;
// otherwise `add` and `remove` apply independently. When initial is true
// the call is part of GetSubscription's stream-creation path, and
// `scripts.remove` is ignored since the subscription has no scripts yet.
//
// All inputs are validated (CEL compile + script parse) before any
// mutation, so an InvalidArgument response guarantees the listener state
// is untouched.
func (h *indexerService) applyFilter(
	subscriptionID string, filter *arkv1.SubscriptionFilter, initial bool,
) error {
	exprs := filter.GetExpressions()
	scripts := filter.GetScripts()

	// Validate all inputs upfront before any mutation. Cap enforcement on
	// the compiled set is the broker's responsibility (see installTxFilters
	// below); we still surface it as InvalidArgument when it fires.
	compiledExprs, err := compileTxFilters(exprs)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	var parsedAdd, parsedRemove []string
	if scripts != nil {
		if len(scripts.GetAdd()) > 0 {
			parsedAdd, err = parseScripts(scripts.GetAdd())
			if err != nil {
				return status.Error(codes.InvalidArgument, err.Error())
			}
		}
		if !initial && len(scripts.GetRemove()) > 0 {
			parsedRemove, err = parseScripts(scripts.GetRemove())
			if err != nil {
				return status.Error(codes.InvalidArgument, err.Error())
			}
		}
	}

	// Mutate: expressions first (literal overwrite), then scripts.
	if err := h.scriptSubsHandler.installTxFilters(subscriptionID, compiledExprs); err != nil {
		if errors.Is(err, ErrTxFiltersLimitExceeded) {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		return subscriptionErr(subscriptionID, err)
	}

	if len(parsedAdd) > 0 {
		if err := h.scriptSubsHandler.addTopics(subscriptionID, parsedAdd); err != nil {
			return subscriptionErr(subscriptionID, err)
		}
	}

	if initial || scripts == nil {
		return nil
	}

	switch {
	case len(parsedRemove) > 0:
		if err := h.scriptSubsHandler.removeTopics(subscriptionID, parsedRemove); err != nil {
			return subscriptionErr(subscriptionID, err)
		}
	case len(parsedAdd) == 0:
		// Both add and remove empty: mirror UnsubscribeForScripts and clear all.
		if err := h.scriptSubsHandler.removeAllTopics(subscriptionID); err != nil {
			return subscriptionErr(subscriptionID, err)
		}
	}

	return nil
}

func (h *indexerService) UnsubscribeForScripts(
	ctx context.Context, request *arkv1.UnsubscribeForScriptsRequest,
) (*arkv1.UnsubscribeForScriptsResponse, error) {
	subscriptionId := request.GetSubscriptionId()
	if len(subscriptionId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing subscription id")
	}

	scripts := request.GetScripts()
	if len(scripts) == 0 {
		// remove all topics
		if err := h.scriptSubsHandler.removeAllTopics(subscriptionId); err != nil {
			return nil, subscriptionErr(subscriptionId, err)
		}
		// Only tear down the listener if no tx filters remain on it, otherwise
		// tx-only subscriptions would be silently dropped.
		if len(h.scriptSubsHandler.getTxFilters(subscriptionId)) == 0 {
			h.scriptSubsHandler.removeListener(subscriptionId)
		}
		return &arkv1.UnsubscribeForScriptsResponse{}, nil
	}

	if err := h.scriptSubsHandler.removeTopics(subscriptionId, scripts); err != nil {
		return nil, subscriptionErr(subscriptionId, err)
	}

	return &arkv1.UnsubscribeForScriptsResponse{}, nil
}

// subscriptionErr maps an error returned by the script-subscription broker
// onto the error surfaced to the client. A missing subscription becomes the
// structured SUBSCRIPTION_NOT_FOUND code (gRPC NotFound); any other error is
// reported as Internal. The message keeps the legacy
// "subscription <id> not found" phrasing so SDKs that still match on the error
// string keep detecting stale subscriptions (see ts-sdk#600), while the
// structured code lets clients detect it without parsing the message.
func subscriptionErr(id string, err error) error {
	if errors.Is(err, ErrSubscriptionNotFound) {
		return arkdErrors.SUBSCRIPTION_NOT_FOUND.
			New("subscription %s not found", id).
			WithMetadata(arkdErrors.SubscriptionMetadata{SubscriptionId: id})
	}
	return status.Error(codes.Internal, err.Error())
}

func (h *indexerService) SubscribeForScripts(
	ctx context.Context, req *arkv1.SubscribeForScriptsRequest,
) (*arkv1.SubscribeForScriptsResponse, error) {
	subscriptionId := req.GetSubscriptionId()
	scripts, err := parseScripts(req.GetScripts())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if len(subscriptionId) == 0 {
		// create new listener
		subscriptionId = uuid.NewString()

		listener := newListener[*arkv1.GetSubscriptionResponse](subscriptionId, scripts)

		h.scriptSubsHandler.pushListener(listener)
		h.scriptSubsHandler.startTimeout(subscriptionId, h.subscriptionTimeoutDuration)
	} else {
		// update listener topic
		if err := h.scriptSubsHandler.addTopics(subscriptionId, scripts); err != nil {
			return nil, subscriptionErr(subscriptionId, err)
		}
	}
	return &arkv1.SubscribeForScriptsResponse{
		SubscriptionId: subscriptionId,
	}, nil
}

func (h *indexerService) listenToTxEvents() {
	for event := range h.eventsCh {
		if !h.scriptSubsHandler.hasListeners() {
			continue
		}

		allSpendableVtxos := make(map[string][]*arkv1.IndexerVtxo)
		allSpentVtxos := make(map[string][]*arkv1.IndexerVtxo)
		sweptVtxos := make([]*arkv1.IndexerVtxo, 0)
		for _, vtxo := range event.SweptVtxos {
			sweptVtxos = append(sweptVtxos, &arkv1.IndexerVtxo{
				Outpoint: &arkv1.IndexerOutpoint{
					Txid: vtxo.Txid,
					Vout: vtxo.VOut,
				},
			})
		}

		for _, vtxo := range event.SpendableVtxos {
			vtxoScript := toP2TR(vtxo.PubKey)
			allSpendableVtxos[vtxoScript] = append(
				allSpendableVtxos[vtxoScript], newIndexerVtxo(vtxo),
			)
		}
		for _, vtxo := range event.SpentVtxos {
			vtxoScript := toP2TR(vtxo.PubKey)
			allSpentVtxos[vtxoScript] = append(allSpentVtxos[vtxoScript], newIndexerVtxo(vtxo))
		}

		var checkpointTxs map[string]*arkv1.IndexerTxData
		if len(event.CheckpointTxs) > 0 {
			checkpointTxs = make(map[string]*arkv1.IndexerTxData)
			for k, v := range event.CheckpointTxs {
				checkpointTxs[k] = &arkv1.IndexerTxData{
					Txid: v.Txid,
					Tx:   v.Tx,
				}
			}
		}

		// Lazily decode the tx for CEL evaluation. The closure is passed into
		// matchesTx so the decode only runs once we know a listener actually
		// has at least one tx filter, and only once per event regardless of
		// how many listeners need it.
		//
		// event.Tx may be either a base64-encoded PSBT (commitment txs,
		// ark txs, checkpoint txs all use this format) or a hex-encoded raw
		// signed tx (sweep txs). We try PSBT first because it is the more
		// common shape; on parse failure we fall back to hex.
		var parsedTx *wire.MsgTx
		var parsedTxAttempted bool
		parseTxOnce := func() *wire.MsgTx {
			if parsedTxAttempted {
				return parsedTx
			}
			parsedTxAttempted = true
			if event.Tx == "" {
				return nil
			}
			if ptx, err := psbt.NewFromRawBytes(
				strings.NewReader(event.Tx), true,
			); err == nil {
				parsedTx = ptx.UnsignedTx
				return parsedTx
			}
			if txBytes, err := hex.DecodeString(event.Tx); err == nil {
				msg := wire.NewMsgTx(2)
				if err := msg.Deserialize(bytes.NewReader(txBytes)); err == nil {
					parsedTx = msg
					return parsedTx
				}
			}
			return nil
		}

		listenersCopy := h.scriptSubsHandler.getListenersCopy()
		for _, l := range listenersCopy {
			spendableVtxos := make([]*arkv1.IndexerVtxo, 0)
			spentVtxos := make([]*arkv1.IndexerVtxo, 0)
			involvedScripts := make([]string, 0)

			for vtxoScript := range l.topics {
				spendableVtxosForScript := allSpendableVtxos[vtxoScript]
				spentVtxosForScript := allSpentVtxos[vtxoScript]
				spendableVtxos = append(spendableVtxos, spendableVtxosForScript...)
				spentVtxos = append(spentVtxos, spentVtxosForScript...)
				if len(spendableVtxosForScript) > 0 || len(spentVtxosForScript) > 0 {
					involvedScripts = append(involvedScripts, vtxoScript)
				}
			}

			scriptMatch := len(spendableVtxos) > 0 || len(spentVtxos) > 0
			txMatch := l.matchesTx(parseTxOnce)

			if scriptMatch || txMatch {
				go func(listener *listener[*arkv1.GetSubscriptionResponse]) {
					select {
					case listener.ch <- &arkv1.GetSubscriptionResponse{
						Data: &arkv1.GetSubscriptionResponse_Event{
							Event: &arkv1.IndexerSubscriptionEvent{
								Txid:          event.Txid,
								Scripts:       involvedScripts,
								NewVtxos:      spendableVtxos,
								SpentVtxos:    spentVtxos,
								SweptVtxos:    sweptVtxos,
								Tx:            event.Tx,
								CheckpointTxs: checkpointTxs,
							},
						},
					}:
					default:
						// channel is full, skip this message to prevent blocking
					}
				}(l)
			}
		}
	}
}

func parseTxid(txid string) (string, error) {
	if txid == "" {
		return "", fmt.Errorf("missing txid")
	}
	buf, err := hex.DecodeString(txid)
	if err != nil {
		return "", fmt.Errorf("invalid txid format")
	}
	if len(buf) != 32 {
		return "", fmt.Errorf("invalid txid length")
	}
	return txid, nil
}

func parseOutpoints(outpoints []string) ([]application.Outpoint, error) {
	outs := make([]application.Outpoint, 0, len(outpoints))
	for _, outpoint := range outpoints {
		parts := strings.Split(outpoint, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid outpoint format")
		}
		txid, err := parseTxid(parts[0])
		if err != nil {
			return nil, err
		}
		vout, err := strconv.Atoi(parts[1])
		if err != nil || vout < 0 {
			return nil, fmt.Errorf("invalid vout %s", parts[1])
		}
		outs = append(outs, application.Outpoint{
			Txid: txid,
			VOut: uint32(vout),
		})
	}
	return outs, nil
}

func parseOutpoint(outpoint *arkv1.IndexerOutpoint) (*application.Outpoint, error) {
	if outpoint == nil {
		return nil, fmt.Errorf("missing outpoint")
	}
	txid, err := parseTxid(outpoint.Txid)
	if err != nil {
		return nil, err
	}
	return &application.Outpoint{
		Txid: txid,
		VOut: outpoint.GetVout(),
	}, nil
}

func parsePage(page *arkv1.IndexerPageRequest) (*application.Page, error) {
	if page == nil {
		return nil, nil
	}
	if page.Size <= 0 {
		return nil, fmt.Errorf("invalid page size")
	}
	if page.Index < 0 {
		return nil, fmt.Errorf("invalid page index")
	}
	return &application.Page{
		PageSize: page.Size,
		PageNum:  page.Index,
	}, nil
}

func parseTxids(txids []string) ([]string, error) {
	if len(txids) == 0 {
		return nil, fmt.Errorf("missing txids")
	}
	for _, txid := range txids {
		if _, err := parseTxid(txid); err != nil {
			return nil, err
		}
	}
	return txids, nil
}

func protoPage(page application.PageResp) *arkv1.IndexerPageResponse {
	emptyPage := application.PageResp{}
	if page == emptyPage {
		return nil
	}
	return &arkv1.IndexerPageResponse{
		Current: page.Current,
		Next:    page.Next,
		Total:   page.Total,
	}
}

func parseScripts(scripts []string) ([]string, error) {
	if len(scripts) <= 0 {
		return nil, fmt.Errorf("missing scripts")
	}

	for _, script := range scripts {
		if _, err := parseScript(script); err != nil {
			return nil, err
		}
	}
	return scripts, nil
}

func parseScript(script string) (string, error) {
	if len(script) <= 0 {
		return "", fmt.Errorf("missing script")
	}
	buf, err := hex.DecodeString(script)
	if err != nil {
		return "", fmt.Errorf("invalid script format, must be hex")
	}
	if !txscript.IsPayToTaproot(buf) {
		return "", fmt.Errorf("invalid script, must be P2TR")
	}
	if _, err := schnorr.ParsePubKey(buf[2:]); err != nil {
		return "", fmt.Errorf("invalid script, failed to extract tapkey: %s", err)
	}
	return script, nil
}

func parseTimeRange(after, before int64) (int64, int64, error) {
	if after < 0 || before < 0 {
		return -1, -1, fmt.Errorf("after and before must be greater than or equal to 0")
	}
	if before > 0 && after > 0 && before <= after {
		return -1, -1, fmt.Errorf("before must be greater than after")
	}
	return after, before, nil
}

func newIndexerVtxo(vtxo domain.Vtxo) *arkv1.IndexerVtxo {
	assets := make([]*arkv1.IndexerAsset, 0, len(vtxo.Assets))
	for _, asset := range vtxo.Assets {
		assets = append(assets, &arkv1.IndexerAsset{
			AssetId: asset.AssetId,
			Amount:  asset.Amount,
		})
	}

	return &arkv1.IndexerVtxo{
		Outpoint: &arkv1.IndexerOutpoint{
			Txid: vtxo.Txid,
			Vout: vtxo.VOut,
		},
		CreatedAt:       vtxo.CreatedAt,
		ExpiresAt:       vtxo.ExpiresAt,
		Amount:          vtxo.Amount,
		Script:          toP2TR(vtxo.PubKey),
		IsPreconfirmed:  vtxo.Preconfirmed,
		IsSwept:         vtxo.Swept,
		IsUnrolled:      vtxo.Unrolled,
		IsSpent:         vtxo.Spent,
		SpentBy:         vtxo.SpentBy,
		CommitmentTxids: vtxo.CommitmentTxids,
		SettledBy:       vtxo.SettledBy,
		ArkTxid:         vtxo.ArkTxid,
		Assets:          assets,
	}
}

func parseIndexerIntent(i *arkv1.IndexerIntent) (*application.Intent, error) {
	if i == nil {
		return nil, nil
	}
	proof := i.GetProof()
	if len(proof) <= 0 {
		return nil, fmt.Errorf("missing intent proof")
	}
	if _, err := psbt.NewFromRawBytes(strings.NewReader(proof), true); err != nil {
		return nil, fmt.Errorf("failed to parse intent proof tx: %s", err)
	}
	message := i.GetMessage()
	if len(message) <= 0 {
		return nil, fmt.Errorf("missing intent message")
	}
	intentMessage := intent.GetDataMessage{}
	if err := intentMessage.Decode(message); err != nil {
		return nil, err
	}
	return &application.Intent{Proof: proof, Message: message}, nil
}
