package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service interface {
	arkv1.ArkServiceServer
}

type handler struct {
	version string

	svc application.Service

	eventsListenerHandler       *broker[*arkv1.GetEventStreamResponse]
	transactionsListenerHandler *broker[*arkv1.GetTransactionsStreamResponse]
}

func NewHandler(version string, service application.Service) service {
	h := &handler{
		version:                     version,
		svc:                         service,
		eventsListenerHandler:       newBroker[*arkv1.GetEventStreamResponse](),
		transactionsListenerHandler: newBroker[*arkv1.GetTransactionsStreamResponse](),
	}

	go h.listenToEvents()
	go h.listenToTxEvents()

	return h
}

func (h *handler) GetInfo(
	ctx context.Context, req *arkv1.GetInfoRequest,
) (*arkv1.GetInfoResponse, error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.GetInfoResponse{
		SignerPubkey:        info.PubKey,
		VtxoTreeExpiry:      info.VtxoTreeExpiry,
		UnilateralExitDelay: info.UnilateralExitDelay,
		BoardingExitDelay:   info.BoardingExitDelay,
		RoundInterval:       info.RoundInterval,
		Network:             info.Network,
		Dust:                int64(info.Dust),
		ForfeitAddress:      info.ForfeitAddress,
		MarketHour: &arkv1.MarketHour{
			NextStartTime: info.NextMarketHour.StartTime.Unix(),
			NextEndTime:   info.NextMarketHour.EndTime.Unix(),
			Period:        int64(info.NextMarketHour.Period.Seconds()),
			RoundInterval: int64(info.NextMarketHour.RoundInterval.Seconds()),
		},
		Version:       h.version,
		UtxoMinAmount: info.UtxoMinAmount,
		UtxoMaxAmount: info.UtxoMaxAmount,
		VtxoMinAmount: info.VtxoMinAmount,
		VtxoMaxAmount: info.VtxoMaxAmount,
	}, nil
}

func (h *handler) RegisterIntent(
	ctx context.Context, req *arkv1.RegisterIntentRequest,
) (*arkv1.RegisterIntentResponse, error) {
	bip322Signature := req.GetIntent()

	if bip322Signature == nil {
		return nil, status.Error(codes.InvalidArgument, "missing intent")
	}

	signature, err := bip322.DecodeSignature(bip322Signature.GetSignature())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 signature")
	}

	intentMessage := bip322Signature.GetMessage()

	if len(intentMessage) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing message")
	}

	var message tree.IntentMessage
	if err := message.Decode(intentMessage); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 message")
	}

	intentId, err := h.svc.RegisterIntent(ctx, *signature, message)
	if err != nil {
		return nil, err
	}

	return &arkv1.RegisterIntentResponse{IntentId: intentId}, nil
}

func (h *handler) DeleteIntent(
	ctx context.Context, req *arkv1.DeleteIntentRequest,
) (*arkv1.DeleteIntentResponse, error) {
	proof := req.GetProof()

	if proof == nil {
		return nil, status.Error(codes.InvalidArgument, "missing request id or bip322 signature")
	}

	signature, err := bip322.DecodeSignature(proof.GetSignature())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 signature")
	}

	intentMessage := proof.GetMessage()
	if len(intentMessage) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing BIP0322 message")
	}

	var message tree.DeleteIntentMessage
	if err := message.Decode(intentMessage); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 message")
	}

	if err := h.svc.DeleteTxRequestsByProof(ctx, *signature, message); err != nil {
		return nil, err
	}

	return &arkv1.DeleteIntentResponse{}, nil
}

func (h *handler) ConfirmRegistration(
	ctx context.Context, req *arkv1.ConfirmRegistrationRequest,
) (*arkv1.ConfirmRegistrationResponse, error) {
	intentId := req.GetIntentId()
	if len(intentId) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing intent id")
	}

	if err := h.svc.ConfirmRegistration(ctx, intentId); err != nil {
		return nil, err
	}

	return &arkv1.ConfirmRegistrationResponse{}, nil
}

func (h *handler) SubmitTreeNonces(
	ctx context.Context, req *arkv1.SubmitTreeNoncesRequest,
) (*arkv1.SubmitTreeNoncesResponse, error) {
	pubkey := req.GetPubkey()
	encodedNonces := req.GetTreeNonces()
	batchId := req.GetBatchId()

	if len(pubkey) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing cosigner public key")
	}

	if len(encodedNonces) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tree nonces")
	}

	if len(batchId) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing batch id")
	}

	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key format, expected hex")
	}
	if len(pubkeyBytes) != 33 {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key length, expected 33 bytes")
	}
	if _, err := secp256k1.ParsePubKey(pubkeyBytes); err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid cosigner public key %s", err))
	}

	nonces := make(tree.TreeNonces)
	if err := json.Unmarshal([]byte(encodedNonces), &nonces); err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid tree nonces %s", err))
	}

	if err := h.svc.RegisterCosignerNonces(ctx, batchId, pubkey, nonces); err != nil {
		return nil, err
	}

	return &arkv1.SubmitTreeNoncesResponse{}, nil
}

func (h *handler) SubmitTreeSignatures(
	ctx context.Context, req *arkv1.SubmitTreeSignaturesRequest,
) (*arkv1.SubmitTreeSignaturesResponse, error) {
	batchId := req.GetBatchId()
	pubkey := req.GetPubkey()
	encodedSignatures := req.GetTreeSignatures()

	if len(pubkey) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing cosigner public key")
	}

	if len(encodedSignatures) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tree signatures")
	}

	if len(batchId) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing round id")
	}

	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key format, expected hex")
	}
	if len(pubkeyBytes) != 33 {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key length, expected 33 bytes")
	}
	if _, err := secp256k1.ParsePubKey(pubkeyBytes); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key length, expected 33 bytes")
	}

	signatures := make(tree.TreePartialSigs)
	if err := json.Unmarshal([]byte(encodedSignatures), &signatures); err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid tree signatures %s", err))
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

	if len(forfeitTxs) > 0 {
		if err := h.svc.SignVtxos(ctx, forfeitTxs); err != nil {
			return nil, err
		}
	}

	if len(commitmentTx) > 0 {
		if err := h.svc.SignRoundTx(ctx, commitmentTx); err != nil {
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

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (h *handler) SubmitTx(
	ctx context.Context, req *arkv1.SubmitTxRequest,
) (*arkv1.SubmitTxResponse, error) {
	if req.GetSignedArkTx() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing signed ark tx")
	}

	if len(req.GetCheckpointTxs()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}

	signedCheckpoints, signedVirtualTx, virtualTxid, err := h.svc.SubmitOffchainTx(
		ctx, req.GetCheckpointTxs(), req.GetSignedArkTx(),
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.SubmitTxResponse{
		FinalArkTx:          signedVirtualTx,
		ArkTxid:             virtualTxid,
		SignedCheckpointTxs: signedCheckpoints,
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

	if err := h.svc.FinalizeOffchainTx(ctx, req.GetArkTxid(), req.GetFinalCheckpointTxs()); err != nil {
		return nil, err
	}

	return &arkv1.FinalizeTxResponse{}, nil
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

	for {
		select {
		// case <-h.stopTransactionEventsCh:
		// 	return nil
		case <-stream.Context().Done():
			return nil
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
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
							CommitmentTx: e.RoundTx,
						},
					},
				}

				evs = append(evs, eventWithTopics{
					topics: nil,
					event:  ev,
				})

			case application.RoundFinalized:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFinalized{
						BatchFinalized: &arkv1.BatchFinalizedEvent{
							Id:             e.Id,
							CommitmentTxid: e.Txid,
						},
					},
				}

				evs = append(evs, eventWithTopics{
					topics: nil,
					event:  ev,
				})
			case domain.RoundFailed:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFailed{
						BatchFailed: &arkv1.BatchFailed{
							Id:     e.Id,
							Reason: e.Err,
						},
					},
				}

				evs = append(evs, eventWithTopics{
					topics: nil,
					event:  ev,
				})
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

				evs = append(evs, eventWithTopics{
					topics: nil,
					event:  ev,
				})
			case application.RoundSigningStarted:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeSigningStarted{
						TreeSigningStarted: &arkv1.TreeSigningStartedEvent{
							Id:                   e.Id,
							UnsignedCommitmentTx: e.UnsignedRoundTx,
							CosignersPubkeys:     e.CosignersPubkeys,
						},
					},
				}

				evs = append(evs, eventWithTopics{
					topics: nil,
					event:  ev,
				})
			case application.RoundSigningNoncesGenerated:
				serialized, err := json.Marshal(e.Nonces)
				if err != nil {
					logrus.WithError(err).Error("failed to serialize nonces")
					continue
				}

				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeNoncesAggregated{
						TreeNoncesAggregated: &arkv1.TreeNoncesAggregatedEvent{
							Id:         e.Id,
							TreeNonces: string(serialized),
						},
					},
				}

				evs = append(evs, eventWithTopics{
					topics: nil,
					event:  ev,
				})
			case application.BatchTree:
				ev := &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeTx{
						TreeTx: &arkv1.TreeTxEvent{
							Id:         e.Id,
							Topic:      e.Topic,
							BatchIndex: e.BatchIndex,
							Tx:         e.Chunk.Tx,
							Children:   e.Chunk.Children,
						},
					},
				}

				evs = append(evs, eventWithTopics{
					topics: e.Topic,
					event:  ev,
				})
			case application.BatchTreeSignature:
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

				evs = append(evs, eventWithTopics{
					topics: e.Topic,
					event:  ev,
				})
			}
		}

		// forward all events in the same routine in order to preserve the ordering
		if len(evs) > 0 {
			logrus.Debugf("forwarding event to %d listeners", len(h.eventsListenerHandler.listeners))
			for _, l := range h.eventsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetEventStreamResponse]) {
					sentEventsCount := 0
					for _, ev := range evs {
						if l.includesAny(ev.topics) {
							l.ch <- ev.event
							sentEventsCount++
						}
					}
					logrus.Debugf("forwarded %d events to listener %s", sentEventsCount, l.id)
				}(l)
			}
		}
	}

}

func (h *handler) listenToTxEvents() {
	eventsCh := h.svc.GetTransactionEventsChannel(context.Background())
	for event := range eventsCh {
		var msg *arkv1.GetTransactionsStreamResponse

		switch event.Type {
		case application.CommitmentTxType:
			msg = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_CommitmentTx{
					CommitmentTx: txEvent(event).toProto(),
				},
			}
		case application.ArkTxType:
			msg = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_ArkTx{
					ArkTx: txEvent(event).toProto(),
				},
			}
		}

		if msg != nil {
			logrus.Debugf("forwarding event to %d listeners", len(h.transactionsListenerHandler.listeners))
			for _, l := range h.transactionsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetTransactionsStreamResponse]) {
					l.ch <- msg
				}(l)
			}
		}
	}
}

type eventWithTopics struct {
	topics []string
	event  *arkv1.GetEventStreamResponse
}
