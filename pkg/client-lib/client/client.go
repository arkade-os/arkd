package client

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
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/btcsuite/btcd/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// testDialOptions is a test-only seam appended to the dial options in
// NewClient. It is nil in production builds (zero effect) and is set by tests
// to inject a bufconn dialer so the real NewClient path — including the
// build-version interceptors registered above — can be exercised in-process.
var testDialOptions []grpc.DialOption

type grpcClient struct {
	conn       *grpc.ClientConn
	connMu     *sync.Mutex
	svc        arkv1.ArkServiceClient
	listenerMu *sync.RWMutex
	listenerId string
	infoMu     *sync.RWMutex
	digest     string
}

func NewClient(serverUrl string) (clientlib.Client, error) {
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

	client := &grpcClient{
		connMu:     &sync.Mutex{},
		listenerMu: &sync.RWMutex{},
		infoMu:     &sync.RWMutex{},
	}

	options := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDisableServiceConfig(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(20 << 20)),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   10 * time.Second,
			},
			MinConnectTimeout: 3 * time.Second,
		}),
		grpc.WithChainUnaryInterceptor(
			unaryVersionInterceptor(), unaryDigestInterceptor(client.getDigest),
		),
		grpc.WithChainStreamInterceptor(
			streamVersionInterceptor(), streamDigestInterceptor(client.getDigest),
		),
	}
	options = append(options, testDialOptions...)

	conn, err := grpc.NewClient(serverUrl, options...)
	if err != nil {
		return nil, err
	}
	client.conn = conn
	client.svc = arkv1.NewArkServiceClient(conn)

	return client, nil
}

func (c *grpcClient) GetInfo(ctx context.Context) (*clientlib.Info, error) {
	req := &arkv1.GetInfoRequest{}
	resp, err := c.svc.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	fees, err := parseFees(resp.GetFees())
	if err != nil {
		return nil, err
	}
	var (
		ssStartTime, ssEndTime, ssPeriod, ssDuration int64
		ssFees                                       clientlib.FeeInfo
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
	var deprecatedSigners []clientlib.DeprecatedSignerInfo
	for _, s := range resp.GetDeprecatedSigners() {
		if s == nil {
			continue
		}
		deprecatedSigners = append(deprecatedSigners, clientlib.DeprecatedSignerInfo{
			PubKey:     s.GetPubkey(),
			CutoffDate: s.GetCutoffDate(),
		})
	}

	// Cache the latest digest under the lock. This must NOT wrap the RPC above:
	// the digest interceptor reads a.digest under the same mutex, so holding it
	// across the call would self-deadlock the RWMutex.
	c.infoMu.Lock()
	c.digest = resp.GetDigest()
	c.infoMu.Unlock()

	return &clientlib.Info{
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

func (c *grpcClient) RegisterIntent(ctx context.Context, proof, message string) (string, error) {
	req := &arkv1.RegisterIntentRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}

	resp, err := withDigestRefresh(c, ctx, func() (*arkv1.RegisterIntentResponse, error) {
		return c.svc.RegisterIntent(ctx, req)
	})
	if err != nil {
		return "", err
	}
	return resp.GetIntentId(), nil
}

func (c *grpcClient) DeleteIntent(ctx context.Context, proof, message string) error {
	req := &arkv1.DeleteIntentRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}
	_, err := withDigestRefresh(c, ctx, func() (*arkv1.DeleteIntentResponse, error) {
		return c.svc.DeleteIntent(ctx, req)
	})
	return err
}

func (c *grpcClient) EstimateIntentFee(ctx context.Context, proof, message string) (int64, error) {
	req := &arkv1.EstimateIntentFeeRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}
	resp, err := withDigestRefresh(c, ctx, func() (*arkv1.EstimateIntentFeeResponse, error) {
		return c.svc.EstimateIntentFee(ctx, req)
	})
	if err != nil {
		return -1, err
	}
	return resp.GetFee(), nil
}

func (c *grpcClient) ConfirmRegistration(ctx context.Context, intentID string) error {
	req := &arkv1.ConfirmRegistrationRequest{
		IntentId: intentID,
	}
	_, err := c.svc.ConfirmRegistration(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (c *grpcClient) SubmitTreeNonces(
	ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces,
) error {
	req := &arkv1.SubmitTreeNoncesRequest{
		BatchId:    batchId,
		Pubkey:     cosignerPubkey,
		TreeNonces: nonces.ToMap(),
	}

	if _, err := c.svc.SubmitTreeNonces(ctx, req); err != nil {
		return err
	}

	return nil
}

func (c *grpcClient) SubmitTreeSignatures(
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

	if _, err := c.svc.SubmitTreeSignatures(ctx, req); err != nil {
		return err
	}

	return nil
}

func (c *grpcClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
) error {
	req := &arkv1.SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs:   signedForfeitTxs,
		SignedCommitmentTx: signedCommitmentTx,
	}

	_, err := c.svc.SubmitSignedForfeitTxs(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (c *grpcClient) GetEventStream(
	ctx context.Context, topics []string,
) (<-chan clientlib.BatchEventChannel, func(), error) {
	req := &arkv1.GetEventStreamRequest{Topics: topics}

	return utils.StartReconnectingStream(ctx, utils.ReconnectingStreamConfig[
		arkv1.ArkService_GetEventStreamClient,
		*arkv1.GetEventStreamResponse,
		clientlib.BatchEventChannel,
	]{
		Connect: func(ctx context.Context) (arkv1.ArkService_GetEventStreamClient, error) {
			return withDigestRefresh(c, ctx, func() (arkv1.ArkService_GetEventStreamClient, error) {
				return c.svc.GetEventStream(ctx, req)
			})
		},
		Reconnect: func(ctx context.Context) (string, arkv1.ArkService_GetEventStreamClient, error) {
			stream, err := c.svc.GetEventStream(ctx, req)
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
			eventsCh chan<- clientlib.BatchEventChannel,
			resp *arkv1.GetEventStreamResponse,
		) error {
			if started := resp.GetStreamStarted(); started != nil {
				c.setListenerID(started.GetId())
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
			case eventsCh <- clientlib.BatchEventChannel{Event: ev}:
				return nil
			}
		},
		ErrorEvent: func(err error) clientlib.BatchEventChannel {
			return clientlib.BatchEventChannel{Err: err}
		},
		ConnectionEvent: func(event utils.ReconnectingStreamStateEvent) clientlib.BatchEventChannel {
			return clientlib.BatchEventChannel{
				Connection: &clientlib.StreamConnectionEvent{
					State:          toClientStreamConnectionState(event.State),
					At:             event.At,
					DisconnectedAt: event.DisconnectedAt,
					Err:            event.Err,
				},
			}
		},
		OnDisconnect: func(error) {
			c.setListenerID("")
		},
	})
}

func (c *grpcClient) SubmitTx(
	ctx context.Context, signedArkTx string, checkpointTxs []string,
) (string, string, []string, error) {
	req := &arkv1.SubmitTxRequest{
		SignedArkTx:   signedArkTx,
		CheckpointTxs: checkpointTxs,
	}

	resp, err := withDigestRefresh(c, ctx, func() (*arkv1.SubmitTxResponse, error) {
		return c.svc.SubmitTx(ctx, req)
	})
	if err != nil {
		return "", "", nil, err
	}

	return resp.GetArkTxid(), resp.GetFinalArkTx(), resp.GetSignedCheckpointTxs(), nil
}

func (c *grpcClient) FinalizeTx(
	ctx context.Context, arkTxid string, finalCheckpointTxs []string,
) error {
	req := &arkv1.FinalizeTxRequest{
		ArkTxid:            arkTxid,
		FinalCheckpointTxs: finalCheckpointTxs,
	}

	_, err := withDigestRefresh(c, ctx, func() (*arkv1.FinalizeTxResponse, error) {
		return c.svc.FinalizeTx(ctx, req)
	})
	return err
}

func (c *grpcClient) GetPendingTx(
	ctx context.Context, proof, message string,
) ([]clientlib.AcceptedOffchainTx, error) {
	req := &arkv1.GetPendingTxRequest{
		Identifier: &arkv1.GetPendingTxRequest_Intent{
			Intent: &arkv1.Intent{
				Message: message,
				Proof:   proof,
			},
		},
	}

	resp, err := withDigestRefresh(c, ctx, func() (*arkv1.GetPendingTxResponse, error) {
		return c.svc.GetPendingTx(ctx, req)
	})
	if err != nil {
		return nil, err
	}

	pendingTxs := make([]clientlib.AcceptedOffchainTx, 0, len(resp.GetPendingTxs()))
	for _, tx := range resp.GetPendingTxs() {
		pendingTxs = append(pendingTxs, clientlib.AcceptedOffchainTx{
			Txid:                tx.GetArkTxid(),
			FinalArkTx:          tx.GetFinalArkTx(),
			SignedCheckpointTxs: tx.GetSignedCheckpointTxs(),
		})
	}
	return pendingTxs, nil
}

func (c *grpcClient) GetTransactionsStream(
	ctx context.Context,
) (<-chan clientlib.TransactionEvent, func(), error) {
	req := &arkv1.GetTransactionsStreamRequest{}

	return utils.StartReconnectingStream(ctx, utils.ReconnectingStreamConfig[
		arkv1.ArkService_GetTransactionsStreamClient,
		*arkv1.GetTransactionsStreamResponse,
		clientlib.TransactionEvent,
	]{
		Connect: func(ctx context.Context) (arkv1.ArkService_GetTransactionsStreamClient, error) {
			return withDigestRefresh(c, ctx, func() (arkv1.ArkService_GetTransactionsStreamClient, error) {
				return c.svc.GetTransactionsStream(ctx, req)
			})
		},
		Reconnect: func(
			ctx context.Context,
		) (string, arkv1.ArkService_GetTransactionsStreamClient, error) {
			reconnect := func() (string, arkv1.ArkService_GetTransactionsStreamClient, error) {
				stream, err := withDigestRefresh(c, ctx, func() (arkv1.ArkService_GetTransactionsStreamClient, error) {
					return c.svc.GetTransactionsStream(ctx, req)
				})
				return "", stream, err
			}
			return reconnect()
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
			eventsCh chan<- clientlib.TransactionEvent,
			resp *arkv1.GetTransactionsStreamResponse,
		) error {
			switch tx := resp.GetData().(type) {
			case *arkv1.GetTransactionsStreamResponse_CommitmentTx:
				select {
				case <-ctx.Done():
					return ctx.Err()
				case eventsCh <- clientlib.TransactionEvent{
					CommitmentTx: &clientlib.TxNotification{
						TxData: clientlib.TxData{
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
				checkpointTxs := make(map[clientlib.Outpoint]clientlib.TxData)
				for k, v := range tx.ArkTx.CheckpointTxs {
					out, parseErr := wire.NewOutPointFromString(k)
					if parseErr != nil {
						return fmt.Errorf("invalid checkpoint outpoint %q: %w", k, parseErr)
					}
					checkpointTxs[clientlib.Outpoint{
						Txid: out.Hash.String(),
						VOut: out.Index,
					}] = clientlib.TxData{
						Txid: v.GetTxid(),
						Tx:   v.GetTx(),
					}
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case eventsCh <- clientlib.TransactionEvent{
					ArkTx: &clientlib.TxNotification{
						TxData: clientlib.TxData{
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
				sweptVtxos := make([]clientlib.Outpoint, 0, len(tx.SweepTx.SweptVtxos))
				for _, o := range tx.SweepTx.SweptVtxos {
					sweptVtxos = append(sweptVtxos, clientlib.Outpoint{
						Txid: o.GetTxid(),
						VOut: o.GetVout(),
					})
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case eventsCh <- clientlib.TransactionEvent{
					SweepTx: &clientlib.TxNotification{
						TxData: clientlib.TxData{
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
		ErrorEvent: func(err error) clientlib.TransactionEvent {
			return clientlib.TransactionEvent{Err: err}
		},
		ConnectionEvent: func(event utils.ReconnectingStreamStateEvent) clientlib.TransactionEvent {
			return clientlib.TransactionEvent{
				Connection: &clientlib.StreamConnectionEvent{
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
	updateRes, err := c.svc.UpdateStreamTopics(ctx, req)
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
	updateRes, err := c.svc.UpdateStreamTopics(ctx, req)
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

func (c *grpcClient) getListenerID() string {
	c.listenerMu.RLock()
	defer c.listenerMu.RUnlock()

	return c.listenerId
}

func (c *grpcClient) setListenerID(id string) {
	c.listenerMu.Lock()
	defer c.listenerMu.Unlock()

	c.listenerId = id
}

func (c *grpcClient) getDigest() string {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.digest
}

func toClientStreamConnectionState(
	state utils.ReconnectingStreamState,
) clientlib.StreamConnectionState {
	switch state {
	case utils.ReconnectingStreamStateDisconnected:
		return clientlib.StreamConnectionStateDisconnected
	case utils.ReconnectingStreamStateReconnected:
		return clientlib.StreamConnectionStateReconnected
	default:
		return clientlib.StreamConnectionState(state)
	}
}

func parseFees(fees *arkv1.FeeInfo) (clientlib.FeeInfo, error) {
	if fees == nil {
		return clientlib.FeeInfo{}, nil
	}

	var (
		err       error
		txFeeRate float64
	)
	if fees.GetTxFeeRate() != "" {
		txFeeRate, err = strconv.ParseFloat(fees.GetTxFeeRate(), 64)
		if err != nil {
			return clientlib.FeeInfo{}, err
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

	return clientlib.FeeInfo{
		TxFeeRate:  txFeeRate,
		IntentFees: intentFees,
	}, nil
}
