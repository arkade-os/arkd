package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service interface {
	arkv1.ArkServiceServer
}

type handler struct {
	version   string
	heartbeat time.Duration

	svc application.Service

	eventsListenerHandler       *broker[*arkv1.GetEventStreamResponse]
	transactionsListenerHandler *broker[*arkv1.GetTransactionsStreamResponse]
}

func NewAppServiceHandler(version string, service application.Service, heartbeat int64) service {
	h := &handler{
		version:                     version,
		heartbeat:                   time.Duration(heartbeat) * time.Second,
		svc:                         service,
		eventsListenerHandler:       newBroker[*arkv1.GetEventStreamResponse](),
		transactionsListenerHandler: newBroker[*arkv1.GetTransactionsStreamResponse](),
	}

	go h.listenToEvents()
	go h.listenToTxEvents()

	return h
}

func (h *handler) GetInfo(
	ctx context.Context, _ *arkv1.GetInfoRequest,
) (*arkv1.GetInfoResponse, error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	resp := &arkv1.GetInfoResponse{
		SignerPubkey:        info.SignerPubKey,
		ForfeitPubkey:       info.ForfeitPubKey,
		UnilateralExitDelay: info.UnilateralExitDelay,
		BoardingExitDelay:   info.BoardingExitDelay,
		SessionDuration:     info.SessionDuration,
		Network:             info.Network,
		Dust:                int64(info.Dust),
		ForfeitAddress:      info.ForfeitAddress,
		Version:             h.version,
		UtxoMinAmount:       info.UtxoMinAmount,
		UtxoMaxAmount:       info.UtxoMaxAmount,
		VtxoMinAmount:       info.VtxoMinAmount,
		VtxoMaxAmount:       info.VtxoMaxAmount,
		CheckpointTapscript: info.CheckpointTapscript,
		Fees:                fees(info.Fees).toProto(),
	}
	buf, errJSON := json.Marshal(resp)
	if errJSON != nil {
		log.WithError(errJSON).Warn("failed to marshal get info response")
		return resp, nil
	}

	digest := sha256.Sum256(buf)
	resp.Digest = hex.EncodeToString(digest[:])
	resp.ScheduledSession = scheduledSession{info.NextScheduledSession}.toProto()

	return resp, nil
}

func (h *handler) RegisterIntent(
	ctx context.Context, req *arkv1.RegisterIntentRequest,
) (*arkv1.RegisterIntentResponse, error) {
	proof, message, err := parseRegisterIntent(req.GetIntent())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	intentId, err := h.svc.RegisterIntent(ctx, *proof, *message)
	if err != nil {
		return nil, err
	}

	return &arkv1.RegisterIntentResponse{IntentId: intentId}, nil
}

func (h *handler) EstimateIntentFee(
	ctx context.Context, req *arkv1.EstimateIntentFeeRequest,
) (*arkv1.EstimateIntentFeeResponse, error) {
	proof, message, err := parseEstimateFeeIntent(req.GetIntent())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	fee, err := h.svc.EstimateIntentFee(ctx, *proof, *message)
	if err != nil {
		return nil, err
	}

	return &arkv1.EstimateIntentFeeResponse{Fee: fee}, nil
}

func (h *handler) DeleteIntent(
	ctx context.Context, req *arkv1.DeleteIntentRequest,
) (*arkv1.DeleteIntentResponse, error) {
	proof, message, err := parseDeleteIntent(req.GetIntent())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.DeleteIntentsByProof(ctx, *proof, *message); err != nil {
		return nil, err
	}

	return &arkv1.DeleteIntentResponse{}, nil
}

func (h *handler) ConfirmRegistration(
	ctx context.Context, req *arkv1.ConfirmRegistrationRequest,
) (*arkv1.ConfirmRegistrationResponse, error) {
	intentId, err := parseIntentId(req.GetIntentId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.ConfirmRegistration(ctx, intentId); err != nil {
		return nil, err
	}

	return &arkv1.ConfirmRegistrationResponse{}, nil
}

func (h *handler) SubmitTreeNonces(
	ctx context.Context, req *arkv1.SubmitTreeNoncesRequest,
) (*arkv1.SubmitTreeNoncesResponse, error) {
	batchId, err := parseBatchId(req.GetBatchId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	nonces, err := parseNonces(req.GetTreeNonces())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	pubkey, err := parseECPubkey(req.GetPubkey())
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument, fmt.Sprintf("invalid cosigner pubkey %s", err),
		)
	}

	if err := h.svc.RegisterCosignerNonces(ctx, batchId, pubkey, nonces); err != nil {
		return nil, err
	}

	return &arkv1.SubmitTreeNoncesResponse{}, nil
}

func (h *handler) SubmitTreeSignatures(
	ctx context.Context, req *arkv1.SubmitTreeSignaturesRequest,
) (*arkv1.SubmitTreeSignaturesResponse, error) {
	batchId, err := parseBatchId(req.GetBatchId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	pubkey, err := parseECPubkey(req.GetPubkey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	signatures, err := parseSignatures(req.GetTreeSignatures())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.RegisterCosignerSignatures(ctx, batchId, pubkey, signatures); err != nil {
		return nil, err
	}

	return &arkv1.SubmitTreeSignaturesResponse{}, nil
}

func (h *handler) SubmitSignedForfeitTxs(
	ctx context.Context, req *arkv1.SubmitSignedForfeitTxsRequest,
) (*arkv1.SubmitSignedForfeitTxsResponse, error) {
	forfeitTxs := req.GetSignedForfeitTxs()
	commitmentTx := req.GetSignedCommitmentTx()
	if len(forfeitTxs) <= 0 && len(commitmentTx) <= 0 {
		return nil, status.Error(
			codes.InvalidArgument, "either forfeit txs or commitment tx must be set",
		)
	}

	if len(forfeitTxs) > 0 {
		if err := h.svc.SubmitForfeitTxs(ctx, forfeitTxs); err != nil {
			return nil, err
		}
	}

	if len(commitmentTx) > 0 {
		if err := h.svc.SignCommitmentTx(ctx, commitmentTx); err != nil {
			return nil, err
		}
	}

	return &arkv1.SubmitSignedForfeitTxsResponse{}, nil
}

func (h *handler) GetEventStream(
	req *arkv1.GetEventStreamRequest, stream arkv1.ArkService_GetEventStreamServer,
) error {
	topics := req.GetTopics()
	listener := newListener[*arkv1.GetEventStreamResponse](uuid.NewString(), topics)

	h.eventsListenerHandler.pushListener(listener)
	defer h.eventsListenerHandler.removeListener(listener.id)
	defer close(listener.ch)

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
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
			resetTimer()
		case <-timer.C:
			hb := &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_Heartbeat{
					Heartbeat: &arkv1.Heartbeat{},
				},
			}
			if err := stream.Send(hb); err != nil {
				return err
			}
			resetTimer()
		}
	}
}

func (h *handler) SubmitTx(
	ctx context.Context, req *arkv1.SubmitTxRequest,
) (*arkv1.SubmitTxResponse, error) {
	if len(req.GetSignedArkTx()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing signed ark tx")
	}

	if len(req.GetCheckpointTxs()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}

	tx, err := h.svc.SubmitOffchainTx(
		ctx, req.GetCheckpointTxs(), req.GetSignedArkTx(),
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.SubmitTxResponse{
		ArkTxid:             tx.TxId,
		FinalArkTx:          tx.FinalArkTx,
		SignedCheckpointTxs: tx.SignedCheckpointTxs,
	}, nil
}

func (h *handler) FinalizeTx(
	ctx context.Context, req *arkv1.FinalizeTxRequest,
) (*arkv1.FinalizeTxResponse, error) {
	if req.GetArkTxid() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing ark txid")
	}

	if len(req.GetFinalCheckpointTxs()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing final checkpoint txs")
	}

	if err := h.svc.FinalizeOffchainTx(
		ctx, req.GetArkTxid(), req.GetFinalCheckpointTxs(),
	); err != nil {
		return nil, err
	}

	return &arkv1.FinalizeTxResponse{}, nil
}

func (h *handler) GetPendingTx(
	ctx context.Context, req *arkv1.GetPendingTxRequest,
) (*arkv1.GetPendingTxResponse, error) {
	if req.GetIdentifier() == nil {
		return nil, status.Error(codes.InvalidArgument, "missing identifier")
	}

	intent := req.GetIntent()
	if intent == nil {
		return nil, status.Error(codes.InvalidArgument, "missing intent")
	}

	proof, message, err := parseGetPendingTxIntent(intent)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	pendingTxs, err := h.svc.GetPendingOffchainTxs(ctx, *proof, *message)
	if err != nil {
		return nil, err
	}

	pendingTxsProto := make([]*arkv1.PendingTx, 0, len(pendingTxs))
	for _, tx := range pendingTxs {
		pendingTxsProto = append(pendingTxsProto, &arkv1.PendingTx{
			ArkTxid:             tx.TxId,
			FinalArkTx:          tx.FinalArkTx,
			SignedCheckpointTxs: tx.SignedCheckpointTxs,
		})
	}

	return &arkv1.GetPendingTxResponse{PendingTxs: pendingTxsProto}, nil
}

func (h *handler) GetTransactionsStream(
	_ *arkv1.GetTransactionsStreamRequest,
	stream arkv1.ArkService_GetTransactionsStreamServer,
) error {
	listener := newListener[*arkv1.GetTransactionsStreamResponse](uuid.NewString(), []string{})

	h.transactionsListenerHandler.pushListener(listener)

	defer func() {
		h.transactionsListenerHandler.removeListener(listener.id)
		close(listener.ch)
	}()

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
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
			resetTimer()
		case <-timer.C:
			hb := &arkv1.GetTransactionsStreamResponse{
				Data: &arkv1.GetTransactionsStreamResponse_Heartbeat{
					Heartbeat: &arkv1.Heartbeat{},
				},
			}
			if err := stream.Send(hb); err != nil {
				return err
			}
			resetTimer()
		}
	}
}

// listenToEvents forwards events from the application layer to the set of listeners
func (h *handler) listenToEvents() {
	channel := h.svc.GetEventsChannel(context.Background())
	for events := range channel {
		evs := make([]eventWithTopics, 0, len(events))

		for _, event := range events {
			switch e := event.(type) {
			case domain.RoundFinalizationStarted:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFinalization{
						BatchFinalization: &arkv1.BatchFinalizationEvent{
							Id:           e.Id,
							CommitmentTx: e.CommitmentTx,
						},
					},
				}

				evs = append(evs, eventWithTopics{event: ev})

			case application.RoundFinalized:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFinalized{
						BatchFinalized: &arkv1.BatchFinalizedEvent{
							Id:             e.Id,
							CommitmentTxid: e.Txid,
						},
					},
				}

				evs = append(evs, eventWithTopics{event: ev})
			case application.RoundFailed:
				log.WithError(errors.New(e.Reason)).Error("round failed")

				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFailed{
						BatchFailed: &arkv1.BatchFailedEvent{
							Id:     e.Id,
							Reason: e.Reason,
						},
					},
				}

				evs = append(evs, eventWithTopics{event: ev, topics: e.Topic})
			case application.BatchStarted:
				hashes := make([]string, 0, len(e.IntentIdsHashes))
				for _, hash := range e.IntentIdsHashes {
					hashes = append(hashes, hex.EncodeToString(hash[:]))
				}

				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchStarted{
						BatchStarted: &arkv1.BatchStartedEvent{
							Id:             e.Id,
							IntentIdHashes: hashes,
							BatchExpiry:    int64(e.BatchExpiry),
						},
					},
				}

				evs = append(evs, eventWithTopics{event: ev})
			case application.RoundSigningStarted:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeSigningStarted{
						TreeSigningStarted: &arkv1.TreeSigningStartedEvent{
							Id:                   e.Id,
							UnsignedCommitmentTx: e.UnsignedCommitmentTx,
							CosignersPubkeys:     e.CosignersPubkeys,
						},
					},
				}

				evs = append(evs, eventWithTopics{event: ev})
			case application.TreeTxNoncesEvent:
				nonces := make(map[string]string)
				for pubkey, nonce := range e.Nonces {
					nonces[pubkey] = hex.EncodeToString(nonce.PubNonce[:])
				}

				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeNonces{
						TreeNonces: &arkv1.TreeNoncesEvent{
							Id:     e.Id,
							Txid:   e.Txid,
							Topic:  e.Topic,
							Nonces: nonces,
						},
					},
				}

				evs = append(evs, eventWithTopics{event: ev, topics: e.Topic})
			case application.TreeNoncesAggregated:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeNoncesAggregated{
						TreeNoncesAggregated: &arkv1.TreeNoncesAggregatedEvent{
							Id:         e.Id,
							TreeNonces: e.Nonces.ToMap(),
						},
					},
				}

				evs = append(evs, eventWithTopics{event: ev})
			case application.TreeTxMessage:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeTx{
						TreeTx: &arkv1.TreeTxEvent{
							Id:         e.Id,
							Topic:      e.Topic,
							BatchIndex: e.BatchIndex,
							Tx:         e.Node.Tx,
							Children:   e.Node.Children,
						},
					},
				}

				evs = append(evs, eventWithTopics{topics: e.Topic, event: ev})
			case application.TreeSignatureMessage:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeSignature{
						TreeSignature: &arkv1.TreeSignatureEvent{
							Id:         e.Id,
							Topic:      e.Topic,
							BatchIndex: e.BatchIndex,
							Txid:       e.Txid,
							Signature:  e.Signature,
						},
					},
				}

				evs = append(evs, eventWithTopics{topics: e.Topic, event: ev})
			}
		}

		// forward all events in the same routine in order to preserve the ordering
		if len(evs) > 0 {
			for _, l := range h.eventsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetEventStreamResponse]) {
					count := 0
					for _, ev := range evs {
						if l.includesAny(ev.topics) {
							l.ch <- ev.event
							count++
						}
					}
					log.Debugf("forwarded event to %d listeners", count)
				}(l)
			}
		}
	}

}

func (h *handler) listenToTxEvents() {
	eventsCh := h.svc.GetTxEventsChannel(context.Background())
	for event := range eventsCh {
		var msg *arkv1.GetTransactionsStreamResponse

		switch event.Type {
		case application.CommitmentTxType:
			msg = &arkv1.GetTransactionsStreamResponse{
				Data: &arkv1.GetTransactionsStreamResponse_CommitmentTx{
					CommitmentTx: txEvent(event).toProto(),
				},
			}
		case application.ArkTxType:
			msg = &arkv1.GetTransactionsStreamResponse{
				Data: &arkv1.GetTransactionsStreamResponse_ArkTx{
					ArkTx: txEvent(event).toProto(),
				},
			}
		}

		if msg != nil {
			for _, l := range h.transactionsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetTransactionsStreamResponse]) {
					l.ch <- msg
				}(l)
			}
			log.Debugf(
				"forwarded tx event to %d listeners", len(h.transactionsListenerHandler.listeners),
			)
		}
	}
}

func (h *handler) GetIntent(
	ctx context.Context, req *arkv1.GetIntentRequest,
) (*arkv1.GetIntentResponse, error) {
	var err error
	var intents []domain.Intent

	switch filter := req.GetFilter().(type) {
	case *arkv1.GetIntentRequest_Txid:
		intents, err = h.svc.GetIntentsByTxid(ctx, filter.Txid)
		if err != nil {
			return nil, err
		}
		if len(intents) == 0 {
			return nil, status.Error(codes.NotFound, "intents not found for provided txid")
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown intent filter provided")
	}

	arkv1Intents := make([]*arkv1.Intent, 0, len(intents))
	for _, intent := range intents {
		arkv1Intents = append(arkv1Intents, &arkv1.Intent{
			Proof:   intent.Proof,
			Message: intent.Message,
		})
	}

	return &arkv1.GetIntentResponse{Intents: arkv1Intents}, nil
}

type eventWithTopics struct {
	topics []string
	event  *arkv1.GetEventStreamResponse
}
