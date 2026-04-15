package grpcclient

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcClient struct {
	conn       *grpc.ClientConn
	connMu     *sync.RWMutex
	listenerMu *sync.RWMutex
	listenerId string
}

func NewClient(serverUrl string) (client.TransportClient, error) {
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
		conn:       conn,
		connMu:     &sync.RWMutex{},
		listenerMu: &sync.RWMutex{},
		listenerId: "",
	}

	return client, nil
}

func (a *grpcClient) GetInfo(ctx context.Context) (*client.Info, error) {
	req := &arkv1.GetInfoRequest{}
	resp, err := a.svc().GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	fees, err := parseFees(resp.GetFees())
	if err != nil {
		return nil, err
	}
	var (
		ssStartTime, ssEndTime, ssPeriod, ssDuration int64
		ssFees                                       types.FeeInfo
	)
	if ss := resp.GetScheduledSession(); ss != nil {
		ssStartTime = ss.GetNextStartTime()
		ssEndTime = ss.GetNextEndTime()
		ssPeriod = ss.GetPeriod()
		ssDuration = ss.GetDuration()
		ssFees, err = parseFees(ss.GetFees())
		if err != nil {
			return nil, err
		}
	}
	var deprecatedSigners []client.DeprecatedSigner
	for _, s := range resp.GetDeprecatedSigners() {
		if s == nil {
			continue
		}
		deprecatedSigners = append(deprecatedSigners, client.DeprecatedSigner{
			PubKey:     s.GetPubkey(),
			CutoffDate: s.GetCutoffDate(),
		})
	}
	return &client.Info{
		SignerPubKey:              resp.GetSignerPubkey(),
		ForfeitPubKey:             resp.GetForfeitPubkey(),
		UnilateralExitDelay:       resp.GetUnilateralExitDelay(),
		SessionDuration:           resp.GetSessionDuration(),
		Network:                   resp.GetNetwork(),
		Dust:                      uint64(resp.GetDust()),
		BoardingExitDelay:         resp.GetBoardingExitDelay(),
		ForfeitAddress:            resp.GetForfeitAddress(),
		Version:                   resp.GetVersion(),
		ScheduledSessionStartTime: ssStartTime,
		ScheduledSessionEndTime:   ssEndTime,
		ScheduledSessionPeriod:    ssPeriod,
		ScheduledSessionDuration:  ssDuration,
		ScheduledSessionFees:      ssFees,
		UtxoMinAmount:             resp.GetUtxoMinAmount(),
		UtxoMaxAmount:             resp.GetUtxoMaxAmount(),
		VtxoMinAmount:             resp.GetVtxoMinAmount(),
		VtxoMaxAmount:             resp.GetVtxoMaxAmount(),
		CheckpointTapscript:       resp.GetCheckpointTapscript(),
		DeprecatedSignerPubKeys:   deprecatedSigners,
		MaxTxWeight:               resp.GetMaxTxWeight(),
		MaxOpReturnOutputs:        resp.GetMaxOpReturnOutputs(),
		Fees:                      fees,
		ServiceStatus:             resp.GetServiceStatus(),
		Digest:                    resp.GetDigest(),
	}, nil
}

func (a *grpcClient) RegisterIntent(
	ctx context.Context,
	proof, message string,
) (string, error) {
	req := &arkv1.RegisterIntentRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}

	resp, err := a.svc().RegisterIntent(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetIntentId(), nil
}

func (a *grpcClient) DeleteIntent(ctx context.Context, proof, message string) error {
	req := &arkv1.DeleteIntentRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}
	_, err := a.svc().DeleteIntent(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (a *grpcClient) EstimateIntentFee(ctx context.Context, proof, message string) (int64, error) {
	req := &arkv1.EstimateIntentFeeRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}
	resp, err := a.svc().EstimateIntentFee(ctx, req)
	if err != nil {
		return -1, err
	}
	return resp.GetFee(), nil
}

func (a *grpcClient) ConfirmRegistration(ctx context.Context, intentID string) error {
	req := &arkv1.ConfirmRegistrationRequest{
		IntentId: intentID,
	}
	_, err := a.svc().ConfirmRegistration(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (a *grpcClient) SubmitTreeNonces(
	ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces,
) error {
	req := &arkv1.SubmitTreeNoncesRequest{
		BatchId:    batchId,
		Pubkey:     cosignerPubkey,
		TreeNonces: nonces.ToMap(),
	}

	if _, err := a.svc().SubmitTreeNonces(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitTreeSignatures(
	ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs,
) error {
	sigs, err := signatures.ToMap()
	if err != nil {
		return err
	}

	req := &arkv1.SubmitTreeSignaturesRequest{
		BatchId:        batchId,
		Pubkey:         cosignerPubkey,
		TreeSignatures: sigs,
	}

	if _, err := a.svc().SubmitTreeSignatures(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
) error {
	req := &arkv1.SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs:   signedForfeitTxs,
		SignedCommitmentTx: signedCommitmentTx,
	}

	_, err := a.svc().SubmitSignedForfeitTxs(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (a *grpcClient) GetEventStream(
	ctx context.Context, topics []string,
) (<-chan client.BatchEventChannel, func(), error) {
	req := &arkv1.GetEventStreamRequest{Topics: topics}

	return utils.StartReconnectingStream(ctx, utils.ReconnectingStreamConfig[
		arkv1.ArkService_GetEventStreamClient,
		*arkv1.GetEventStreamResponse,
		client.BatchEventChannel,
	]{
		Connect: func(ctx context.Context) (arkv1.ArkService_GetEventStreamClient, error) {
			return a.svc().GetEventStream(ctx, req)
		},
		Reconnect: func(ctx context.Context) (string, arkv1.ArkService_GetEventStreamClient, error) {
			stream, err := a.svc().GetEventStream(ctx, req)
			return "", stream, err
		},
		Recv: func(stream arkv1.ArkService_GetEventStreamClient) (**arkv1.GetEventStreamResponse, error) {
			str, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			return &str, nil
		},
		HandleResp: func(
			ctx context.Context,
			eventsCh chan<- client.BatchEventChannel,
			resp *arkv1.GetEventStreamResponse,
		) error {
			if started := resp.GetStreamStarted(); started != nil {
				a.setListenerID(started.GetId())
			}

			ev, err := event{resp}.toBatchEvent()
			if err != nil {
				return err
			}
			if ev == nil {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case eventsCh <- client.BatchEventChannel{Event: ev}:
				return nil
			}
		},
		ErrorEvent: func(err error) client.BatchEventChannel {
			return client.BatchEventChannel{Err: err}
		},
		ConnectionEvent: func(event utils.ReconnectingStreamStateEvent) client.BatchEventChannel {
			return client.BatchEventChannel{
				Connection: &types.StreamConnectionEvent{
					State:          toClientStreamConnectionState(event.State),
					At:             event.At,
					DisconnectedAt: event.DisconnectedAt,
					Err:            event.Err,
				},
			}
		},
		OnDisconnect: func(error) {
			a.setListenerID("")
		},
	})
}

func (a *grpcClient) SubmitTx(
	ctx context.Context, signedArkTx string, checkpointTxs []string,
) (string, string, []string, error) {
	req := &arkv1.SubmitTxRequest{
		SignedArkTx:   signedArkTx,
		CheckpointTxs: checkpointTxs,
	}

	resp, err := a.svc().SubmitTx(ctx, req)
	if err != nil {
		return "", "", nil, err
	}

	return resp.GetArkTxid(), resp.GetFinalArkTx(), resp.GetSignedCheckpointTxs(), nil
}

func (a *grpcClient) FinalizeTx(
	ctx context.Context, arkTxid string, finalCheckpointTxs []string,
) error {
	req := &arkv1.FinalizeTxRequest{
		ArkTxid:            arkTxid,
		FinalCheckpointTxs: finalCheckpointTxs,
	}

	_, err := a.svc().FinalizeTx(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (a *grpcClient) GetPendingTx(
	ctx context.Context,
	proof, message string,
) ([]client.AcceptedOffchainTx, error) {
	req := &arkv1.GetPendingTxRequest{
		Identifier: &arkv1.GetPendingTxRequest_Intent{
			Intent: &arkv1.Intent{
				Message: message,
				Proof:   proof,
			},
		},
	}

	resp, err := a.svc().GetPendingTx(ctx, req)
	if err != nil {
		return nil, err
	}

	pendingTxs := make([]client.AcceptedOffchainTx, 0, len(resp.GetPendingTxs()))
	for _, tx := range resp.GetPendingTxs() {
		pendingTxs = append(pendingTxs, client.AcceptedOffchainTx{
			Txid:                tx.GetArkTxid(),
			FinalArkTx:          tx.GetFinalArkTx(),
			SignedCheckpointTxs: tx.GetSignedCheckpointTxs(),
		})
	}
	return pendingTxs, nil
}

func (c *grpcClient) GetTransactionsStream(
	ctx context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	req := &arkv1.GetTransactionsStreamRequest{}

	return utils.StartReconnectingStream(ctx, utils.ReconnectingStreamConfig[
		arkv1.ArkService_GetTransactionsStreamClient,
		*arkv1.GetTransactionsStreamResponse,
		client.TransactionEvent,
	]{
		Connect: func(ctx context.Context) (arkv1.ArkService_GetTransactionsStreamClient, error) {
			return c.svc().GetTransactionsStream(ctx, req)
		},
		Reconnect: func(
			ctx context.Context,
		) (string, arkv1.ArkService_GetTransactionsStreamClient, error) {
			stream, err := c.svc().GetTransactionsStream(ctx, req)
			return "", stream, err
		},
		Recv: func(
			stream arkv1.ArkService_GetTransactionsStreamClient,
		) (**arkv1.GetTransactionsStreamResponse, error) {
			str, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			return &str, nil
		},
		HandleResp: func(
			ctx context.Context,
			eventsCh chan<- client.TransactionEvent,
			resp *arkv1.GetTransactionsStreamResponse,
		) error {
			switch tx := resp.GetData().(type) {
			case *arkv1.GetTransactionsStreamResponse_CommitmentTx:
				select {
				case <-ctx.Done():
					return ctx.Err()
				case eventsCh <- client.TransactionEvent{
					CommitmentTx: &client.TxNotification{
						TxData: client.TxData{
							Txid: tx.CommitmentTx.GetTxid(),
							Tx:   tx.CommitmentTx.GetTx(),
						},
						SpentVtxos:     vtxos(tx.CommitmentTx.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.CommitmentTx.SpendableVtxos).toVtxos(),
					},
				}:
					return nil
				}
			case *arkv1.GetTransactionsStreamResponse_ArkTx:
				checkpointTxs := make(map[types.Outpoint]client.TxData)
				for k, v := range tx.ArkTx.CheckpointTxs {
					out, parseErr := wire.NewOutPointFromString(k)
					if parseErr != nil {
						return fmt.Errorf("invalid checkpoint outpoint %q: %w", k, parseErr)
					}
					checkpointTxs[types.Outpoint{
						Txid: out.Hash.String(),
						VOut: out.Index,
					}] = client.TxData{
						Txid: v.GetTxid(),
						Tx:   v.GetTx(),
					}
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case eventsCh <- client.TransactionEvent{
					ArkTx: &client.TxNotification{
						TxData: client.TxData{
							Txid: tx.ArkTx.GetTxid(),
							Tx:   tx.ArkTx.GetTx(),
						},
						SpentVtxos:     vtxos(tx.ArkTx.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.ArkTx.SpendableVtxos).toVtxos(),
						CheckpointTxs:  checkpointTxs,
					},
				}:
					return nil
				}
			case *arkv1.GetTransactionsStreamResponse_SweepTx:
				sweptVtxos := make([]types.Outpoint, 0, len(tx.SweepTx.SweptVtxos))
				for _, o := range tx.SweepTx.SweptVtxos {
					sweptVtxos = append(sweptVtxos, types.Outpoint{
						Txid: o.GetTxid(),
						VOut: o.GetVout(),
					})
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case eventsCh <- client.TransactionEvent{
					SweepTx: &client.TxNotification{
						TxData: client.TxData{
							Txid: tx.SweepTx.GetTxid(),
							Tx:   tx.SweepTx.GetTx(),
						},
						SpentVtxos:     vtxos(tx.SweepTx.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.SweepTx.SpendableVtxos).toVtxos(),
						SweptVtxos:     sweptVtxos,
					},
				}:
					return nil
				}
			default:
				return nil
			}
		},
		ErrorEvent: func(err error) client.TransactionEvent {
			return client.TransactionEvent{Err: err}
		},
		ConnectionEvent: func(event utils.ReconnectingStreamStateEvent) client.TransactionEvent {
			return client.TransactionEvent{
				Connection: &types.StreamConnectionEvent{
					State:          toClientStreamConnectionState(event.State),
					At:             event.At,
					DisconnectedAt: event.DisconnectedAt,
					Err:            event.Err,
				},
			}
		},
	})
}

func (c *grpcClient) ModifyStreamTopics(
	ctx context.Context, addTopics, removeTopics []string,
) (addedTopics, removedTopics, allTopics []string, err error) {
	listenerID := c.getListenerID()
	if listenerID == "" {
		return nil, nil, nil, fmt.Errorf("listenerId is not set; cannot modify stream topics")
	}

	req := &arkv1.UpdateStreamTopicsRequest{
		StreamId: listenerID,
		TopicsChange: &arkv1.UpdateStreamTopicsRequest_Modify{
			Modify: &arkv1.ModifyTopics{
				AddTopics:    addTopics,
				RemoveTopics: removeTopics,
			},
		},
	}
	updateRes, err := c.svc().UpdateStreamTopics(ctx, req)
	if err != nil {
		return nil, nil, nil, err
	}

	return updateRes.GetTopicsAdded(), updateRes.GetTopicsRemoved(), updateRes.GetAllTopics(), nil
}

func (c *grpcClient) OverwriteStreamTopics(
	ctx context.Context, topics []string,
) (addedTopics, removedTopics, allTopics []string, err error) {
	listenerID := c.getListenerID()
	if listenerID == "" {
		return nil, nil, nil, fmt.Errorf("listenerId is not set; cannot overwrite stream topics")
	}

	req := &arkv1.UpdateStreamTopicsRequest{
		StreamId: listenerID,
		TopicsChange: &arkv1.UpdateStreamTopicsRequest_Overwrite{
			Overwrite: &arkv1.OverwriteTopics{
				Topics: topics,
			},
		},
	}
	updateRes, err := c.svc().UpdateStreamTopics(ctx, req)
	if err != nil {
		return nil, nil, nil, err
	}

	return updateRes.GetTopicsAdded(), updateRes.GetTopicsRemoved(), updateRes.GetAllTopics(), nil
}

func (c *grpcClient) Close() {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	// nolint:errcheck
	c.conn.Close()
}

func (a *grpcClient) svc() arkv1.ArkServiceClient {
	a.connMu.RLock()
	defer a.connMu.RUnlock()

	return arkv1.NewArkServiceClient(a.conn)
}

func (a *grpcClient) getListenerID() string {
	a.listenerMu.RLock()
	defer a.listenerMu.RUnlock()

	return a.listenerId
}

func (a *grpcClient) setListenerID(id string) {
	a.listenerMu.Lock()
	defer a.listenerMu.Unlock()

	a.listenerId = id
}

func toClientStreamConnectionState(
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

func parseFees(fees *arkv1.FeeInfo) (types.FeeInfo, error) {
	if fees == nil {
		return types.FeeInfo{}, nil
	}

	var (
		err       error
		txFeeRate float64
	)
	if fees.GetTxFeeRate() != "" {
		txFeeRate, err = strconv.ParseFloat(fees.GetTxFeeRate(), 64)
		if err != nil {
			return types.FeeInfo{}, err
		}
	}

	var intentFees arkfee.Config
	if f := fees.GetIntentFee(); f != nil {
		intentFees = arkfee.Config{
			IntentOffchainInputProgram:  f.GetOffchainInput(),
			IntentOffchainOutputProgram: f.GetOffchainOutput(),
			IntentOnchainInputProgram:   f.GetOnchainInput(),
			IntentOnchainOutputProgram:  f.GetOnchainOutput(),
		}
	}

	return types.FeeInfo{
		TxFeeRate:  txFeeRate,
		IntentFees: intentFees,
	}, nil
}
