package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type indexerService struct {
	indexerSvc application.IndexerService
	eventsCh   <-chan application.TransactionEvent

	scriptSubsHandler           *broker[*arkv1.GetSubscriptionResponse]
	teleportSubsHandler         *broker[*arkv1.GetSubscriptionResponse]
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
		teleportSubsHandler:         newBroker[*arkv1.GetSubscriptionResponse](),
		subscriptionTimeoutDuration: subscriptionTimeoutDuration,
		heartbeat:                   time.Duration(heartbeat) * time.Second,
	}

	go svc.listenToTxEvents()

	return svc
}

func (e *indexerService) GetAssetGroup(ctx context.Context, request *arkv1.GetAssetGroupRequest,
) (*arkv1.GetAssetGroupResponse, error) {
	assetId := request.GetAssetId()
	if assetId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing asset id")
	}

	resp, err := e.indexerSvc.GetAssetGroup(ctx, assetId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	assetMetadata := make([]*arkv1.AssetMetadata, 0)
	for _, metadata := range resp.AssetGroup.Metadata {
		assetMetadata = append(assetMetadata, &arkv1.AssetMetadata{
			Key:   metadata.Key,
			Value: metadata.Value,
		})
	}

	return &arkv1.GetAssetGroupResponse{
		AssetId: assetId,
		AssetGroup: &arkv1.AssetGroup{
			Id:        resp.AssetGroup.ID,
			Quantity:  resp.AssetGroup.Quantity,
			Immutable: resp.AssetGroup.Immutable,
			Metadata:  assetMetadata,
		},
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
	if len(pubkeys) > 0 {
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
	}

	var resp *application.GetVtxosResp
	if len(pubkeys) > 0 {
		resp, err = e.indexerSvc.GetVtxos(
			ctx, pubkeys, spendableOnly, spentOnly, recoverableOnly, pendingOnly, page,
		)
	}
	if len(outpoints) > 0 {
		resp, err = e.indexerSvc.GetVtxosByOutpoint(ctx, outpoints, page)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
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
	outpoint, err := parseOutpoint(request.GetOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetVtxoChain(ctx, *outpoint, page)
	if err != nil {
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
		Chain: chain,
		Page:  protoPage(resp.Page),
	}, nil
}

func (e *indexerService) GetVirtualTxs(
	ctx context.Context, request *arkv1.GetVirtualTxsRequest,
) (*arkv1.GetVirtualTxsResponse, error) {
	txids, err := parseTxids(request.GetTxids())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetVirtualTxs(ctx, txids, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
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

func (h *indexerService) UnsubscribeForTeleportHash(
	ctx context.Context, request *arkv1.UnsubscribeForTeleportHashRequest,
) (*arkv1.UnsubscribeForTeleportHashResponse, error) {
	subscriptionId := request.GetSubscriptionId()
	if len(subscriptionId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing subscription id")
	}

	hashes := request.GetTeleportHashes()
	if len(hashes) == 0 {
		// remove all topics
		if err := h.teleportSubsHandler.removeAllTopics(subscriptionId); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		h.teleportSubsHandler.removeListener(subscriptionId)
		return &arkv1.UnsubscribeForTeleportHashResponse{}, nil
	}

	if err := h.teleportSubsHandler.removeTopics(subscriptionId, hashes); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.UnsubscribeForTeleportHashResponse{}, nil
}

func (h *indexerService) SubscribeForTeleportHash(
	ctx context.Context, req *arkv1.SubscribeForTeleportHashRequest,
) (*arkv1.SubscribeForTeleportHashResponse, error) {
	subscriptionId := req.GetSubscriptionId()
	hashes := req.GetTeleportHashes()
	if len(hashes) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing teleport hashes")
	}

	if len(subscriptionId) == 0 {
		// create new listener
		subscriptionId = uuid.NewString()

		listener := newListener[*arkv1.GetSubscriptionResponse](subscriptionId, hashes)

		h.teleportSubsHandler.pushListener(listener)
		h.teleportSubsHandler.startTimeout(subscriptionId, h.subscriptionTimeoutDuration)
	} else {
		// update listener topic
		if err := h.teleportSubsHandler.addTopics(subscriptionId, hashes); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &arkv1.SubscribeForTeleportHashResponse{
		SubscriptionId: subscriptionId,
	}, nil
}

func (h *indexerService) GetSubscription(
	request *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer,
) error {
	subscriptionId := request.GetSubscriptionId()
	if len(subscriptionId) == 0 {
		return status.Error(codes.InvalidArgument, "missing subscription id")
	}

	h.scriptSubsHandler.stopTimeout(subscriptionId)
	h.teleportSubsHandler.stopTimeout(subscriptionId)
	defer func() {
		topics := h.scriptSubsHandler.getTopics(subscriptionId)
		if len(topics) > 0 {
			h.scriptSubsHandler.startTimeout(subscriptionId, h.subscriptionTimeoutDuration)
		} else {
			h.scriptSubsHandler.removeListener(subscriptionId)
		}

		teleportTopics := h.teleportSubsHandler.getTopics(subscriptionId)
		if len(teleportTopics) > 0 {
			h.teleportSubsHandler.startTimeout(subscriptionId, h.subscriptionTimeoutDuration)
		} else {
			h.teleportSubsHandler.removeListener(subscriptionId)
		}
	}()

	scriptCh, err := h.scriptSubsHandler.getListenerChannel(subscriptionId)
	if err != nil && !strings.Contains(err.Error(), "listener not found") {
		return status.Error(codes.Internal, err.Error())
	}

	teleportCh, err := h.teleportSubsHandler.getListenerChannel(subscriptionId)
	if err != nil && !strings.Contains(err.Error(), "listener not found") {
		return status.Error(codes.Internal, err.Error())
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
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-scriptCh:
			if err := stream.Send(ev); err != nil {
				return err
			}
			resetTimer()
		case ev := <-teleportCh:
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
			return nil, status.Error(codes.Internal, err.Error())
		}
		h.scriptSubsHandler.removeListener(subscriptionId)
		return &arkv1.UnsubscribeForScriptsResponse{}, nil
	}

	if err := h.scriptSubsHandler.removeTopics(subscriptionId, scripts); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.UnsubscribeForScriptsResponse{}, nil
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
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &arkv1.SubscribeForScriptsResponse{
		SubscriptionId: subscriptionId,
	}, nil
}

func (h *indexerService) listenToTxEvents() {
	for event := range h.eventsCh {
		if !h.scriptSubsHandler.hasListeners() && !h.teleportSubsHandler.hasListeners() {
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

			if len(spendableVtxos) > 0 || len(spentVtxos) > 0 {
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

		teleportListenersCopy := h.teleportSubsHandler.getListenersCopy()
		if len(teleportListenersCopy) > 0 {
			parsedTeleportEvents := make([]*arkv1.TeleportEvent, 0)
			for _, te := range event.TeleportAssets {
				parsedTeleportEvents = append(parsedTeleportEvents, &arkv1.TeleportEvent{
					TeleportHash:   te.TeleportHash,
					AnchorOutpoint: te.AnchorOutpoint.String(),
					AssetId:        te.AssetID,
					Amount:         te.Amount,
					OutputVout:     te.OutputVout,
					CreatedAt:      te.CreatedAt,
					ExpiresAt:      te.ExpiresAt,
				})
			}

			for _, l := range teleportListenersCopy {
				teleportEvents := make([]*arkv1.TeleportEvent, 0)
				involvedHashes := make([]string, 0)

				for _, tpEvent := range parsedTeleportEvents {
					if _, ok := l.topics[tpEvent.TeleportHash]; ok {
						involvedHashes = append(involvedHashes, tpEvent.TeleportHash)
						teleportEvents = append(teleportEvents, tpEvent)
					}
				}

				if len(teleportEvents) > 0 {
					go func(listener *listener[*arkv1.GetSubscriptionResponse]) {
						select {
						case listener.ch <- &arkv1.GetSubscriptionResponse{
							Data: &arkv1.GetSubscriptionResponse_Event{
								Event: &arkv1.IndexerSubscriptionEvent{
									Txid:           event.Txid,
									TeleportEvents: teleportEvents,
									TeleportHashes: involvedHashes,
									Tx:             event.Tx,
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

func newIndexerVtxo(vtxo domain.Vtxo) *arkv1.IndexerVtxo {
	var asst *arkv1.IndexerAsset
	if vtxo.AssetGroup != nil {
		asst = &arkv1.IndexerAsset{
			AssetId: vtxo.AssetGroup.AssetID,
			Amount:  vtxo.AssetGroup.Amount,
		}
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
		Asset:           asst,
	}
}
