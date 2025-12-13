package restclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	ark_service "github.com/arkade-os/arkd/pkg/client-lib/client/rest/service"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/wire"
	"resty.dev/v3"
)

// restClient implements the TransportClient interface for REST communication
type restClient struct {
	serverURL      string
	svc            *ark_service.APIClient
	requestTimeout time.Duration
}

// NewClient creates a new REST client for the Ark service
func NewClient(serverURL string) (client.TransportClient, error) {
	if len(serverURL) <= 0 {
		return nil, fmt.Errorf("missing server url")
	}
	svc, err := newRestArkClient(serverURL)
	if err != nil {
		return nil, err
	}

	// TODO: use twice the round interval.
	reqTimeout := 15 * time.Second

	return &restClient{serverURL, svc, reqTimeout}, nil
}

func (a *restClient) GetInfo(
	ctx context.Context,
) (*client.Info, error) {
	req := a.svc.ArkServiceAPI.ArkServiceGetInfo(ctx)

	resp, _, err := req.Execute()
	if err != nil {
		return nil, err
	}

	fees, err := parseFees(resp.GetFees())
	if err != nil {
		return nil, err
	}
	scheduledSession := resp.GetScheduledSession()
	scheduledSessionFees, err := parseFees(scheduledSession.GetFees())
	if err != nil {
		return nil, err
	}
	deprecatedSigners := make([]client.DeprecatedSigner, 0, len(resp.GetDeprecatedSigners()))
	for _, s := range resp.GetDeprecatedSigners() {
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
		ScheduledSessionStartTime: scheduledSession.GetNextStartTime(),
		ScheduledSessionEndTime:   scheduledSession.GetNextEndTime(),
		ScheduledSessionPeriod:    scheduledSession.GetPeriod(),
		ScheduledSessionDuration:  scheduledSession.GetDuration(),
		ScheduledSessionFees:      scheduledSessionFees,
		UtxoMinAmount:             resp.GetUtxoMinAmount(),
		UtxoMaxAmount:             resp.GetUtxoMaxAmount(),
		VtxoMinAmount:             resp.GetVtxoMinAmount(),
		VtxoMaxAmount:             resp.GetVtxoMaxAmount(),
		CheckpointTapscript:       resp.GetCheckpointTapscript(),
		DeprecatedSignerPubKeys:   deprecatedSigners,
		Fees:                      fees,
		ServiceStatus:             resp.GetServiceStatus(),
		Digest:                    resp.GetDigest(),
	}, nil
}

func (a *restClient) RegisterIntent(
	ctx context.Context, proof, message string,
) (string, error) {
	req := a.svc.ArkServiceAPI.ArkServiceRegisterIntent(ctx).
		RegisterIntentRequest(ark_service.RegisterIntentRequest{
			Intent: &ark_service.Intent{
				Message: &message,
				Proof:   &proof,
			},
		})

	resp, _, err := req.Execute()
	if err != nil {
		return "", err
	}

	return resp.GetIntentId(), nil
}

func (a *restClient) DeleteIntent(ctx context.Context, proof, message string) error {
	req := a.svc.ArkServiceAPI.ArkServiceDeleteIntent(ctx).
		DeleteIntentRequest(ark_service.DeleteIntentRequest{
			Intent: &ark_service.Intent{
				Message: &message,
				Proof:   &proof,
			},
		})

	_, _, err := req.Execute()
	return err
}

func (a *restClient) ConfirmRegistration(ctx context.Context, intentId string) error {
	req := a.svc.ArkServiceAPI.ArkServiceConfirmRegistration(ctx).
		ConfirmRegistrationRequest(ark_service.ConfirmRegistrationRequest{
			IntentId: &intentId,
		})

	_, _, err := req.Execute()
	return err
}

func (a *restClient) SubmitTreeNonces(
	ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces,
) error {
	req := a.svc.ArkServiceAPI.ArkServiceSubmitTreeNonces(ctx).
		SubmitTreeNoncesRequest(ark_service.SubmitTreeNoncesRequest{
			BatchId:    &batchId,
			Pubkey:     &cosignerPubkey,
			TreeNonces: nonces.ToMap(),
		})

	_, _, err := req.Execute()
	return err
}

func (a *restClient) SubmitTreeSignatures(
	ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs,
) error {
	sigs, err := signatures.ToMap()
	if err != nil {
		return err
	}

	req := a.svc.ArkServiceAPI.ArkServiceSubmitTreeSignatures(ctx).
		SubmitTreeSignaturesRequest(ark_service.SubmitTreeSignaturesRequest{
			BatchId:        &batchId,
			Pubkey:         &cosignerPubkey,
			TreeSignatures: sigs,
		})

	_, _, err = req.Execute()
	return err
}

func (a *restClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
) error {
	req := a.svc.ArkServiceAPI.ArkServiceSubmitSignedForfeitTxs(ctx).
		SubmitSignedForfeitTxsRequest(ark_service.SubmitSignedForfeitTxsRequest{
			SignedForfeitTxs:   signedForfeitTxs,
			SignedCommitmentTx: &signedCommitmentTx,
		})

	_, _, err := req.Execute()
	return err
}

func (c *restClient) GetEventStream(
	ctx context.Context, topics []string,
) (<-chan client.BatchEventChannel, func(), error) {
	eventsCh := make(chan client.BatchEventChannel)

	// Construct the URL with proper multi-format topics parameter
	url := fmt.Sprintf("%s/v1/batch/events", c.serverURL)
	if len(topics) > 0 {
		queryParams := make([]string, 0, len(topics))
		for _, topic := range topics {
			queryParams = append(queryParams, fmt.Sprintf("topics=%s", topic))
		}
		url += "?" + strings.Join(queryParams, "&")
	}

	sseClient := resty.NewEventSource().
		SetURL(url).
		SetHeader("Accept", "text/event-stream").
		OnMessage(func(e any) {
			ev := e.(*resty.Event)
			event := ark_service.GetEventStreamResponse{}
			if err := json.Unmarshal([]byte(ev.Data), &event); err != nil {
				eventsCh <- client.BatchEventChannel{Err: err}
				return
			}

			if event.GetHeartbeat() != nil {
				return
			}

			var batchEvent any
			var err error
			switch {
			case !ark_service.IsNil(event.GetBatchFailed()):
				e := event.GetBatchFailed()
				batchEvent = client.BatchFailedEvent{
					Id:     e.GetId(),
					Reason: e.GetReason(),
				}
			case !ark_service.IsNil(event.GetBatchStarted()):
				e := event.GetBatchStarted()
				batchEvent = client.BatchStartedEvent{
					Id:              e.GetId(),
					HashedIntentIds: e.GetIntentIdHashes(),
					BatchExpiry:     e.GetBatchExpiry(),
				}
			case !ark_service.IsNil(event.GetBatchFinalization()):
				e := event.GetBatchFinalization()

				batchEvent = client.BatchFinalizationEvent{
					Id: e.GetId(),
					Tx: e.GetCommitmentTx(),
				}
			case !ark_service.IsNil(event.GetBatchFinalized()):
				e := event.GetBatchFinalized()
				batchEvent = client.BatchFinalizedEvent{
					Id:   e.GetId(),
					Txid: e.GetCommitmentTxid(),
				}
			case !ark_service.IsNil(event.GetTreeSigningStarted()):
				e := event.GetTreeSigningStarted()
				batchEvent = client.TreeSigningStartedEvent{
					Id:                   e.GetId(),
					UnsignedCommitmentTx: e.GetUnsignedCommitmentTx(),
					CosignersPubkeys:     e.GetCosignersPubkeys(),
				}
			case !ark_service.IsNil(event.GetTreeNoncesAggregated()):
				e := event.GetTreeNoncesAggregated()
				nonces, err := tree.NewTreeNonces(e.GetTreeNonces())
				if err != nil {
					break
				}
				batchEvent = client.TreeNoncesAggregatedEvent{
					Id:     e.GetId(),
					Nonces: nonces,
				}
			case !ark_service.IsNil(event.GetTreeTx()):
				e := event.GetTreeTx()
				children := make(map[uint32]string)
				for k, v := range e.GetChildren() {
					var kInt uint64
					kInt, err = strconv.ParseUint(k, 10, 32)
					if err != nil {
						break
					}
					children[uint32(kInt)] = v
				}
				batchEvent = client.TreeTxEvent{
					Id:         e.GetId(),
					Topic:      e.GetTopic(),
					BatchIndex: e.GetBatchIndex(),
					Node: tree.TxTreeNode{
						Txid:     e.GetTxid(),
						Tx:       e.GetTx(),
						Children: children,
					},
				}
			case !ark_service.IsNil(event.GetTreeSignature()):
				e := event.GetTreeSignature()
				batchEvent = client.TreeSignatureEvent{
					Id:         e.GetId(),
					Topic:      e.GetTopic(),
					BatchIndex: e.GetBatchIndex(),
					Txid:       e.GetTxid(),
					Signature:  e.GetSignature(),
				}
			case !ark_service.IsNil(event.GetTreeNonces()):
				e := event.GetTreeNonces()
				nonces := make(map[string]*tree.Musig2Nonce)
				var _err error
				var mustBreak bool
				for pubkey, nonce := range e.Nonces {
					pubnonce, err := hex.DecodeString(nonce)
					if err != nil {
						mustBreak = true
						_err = err
						break
					}
					if len(pubnonce) != 66 {
						_err = fmt.Errorf(
							"invalid nonce length expected 66 bytes got %d",
							len(pubnonce),
						)
						mustBreak = true
						break
					}
					nonces[pubkey] = &tree.Musig2Nonce{
						PubNonce: [66]byte(pubnonce),
					}
				}
				if mustBreak {
					err = _err
					break
				}
				batchEvent = client.TreeNoncesEvent{
					Id:     e.GetId(),
					Topic:  e.GetTopic(),
					Txid:   e.GetTxid(),
					Nonces: nonces,
				}
			case !ark_service.IsNil(event.GetTreeSignature()):
				e := event.GetTreeSignature()
				batchEvent = client.TreeSignatureEvent{
					Id:         e.GetId(),
					Topic:      e.GetTopic(),
					BatchIndex: e.GetBatchIndex(),
					Txid:       e.GetTxid(),
					Signature:  e.GetSignature(),
				}
			}

			eventsCh <- client.BatchEventChannel{
				Event: batchEvent,
				Err:   err,
			}

		}, nil)

	if err := sseClient.Get(); err != nil {
		return nil, nil, err
	}

	return eventsCh, sseClient.Close, nil
}

func (a *restClient) SubmitTx(
	ctx context.Context, signedArkTx string, checkpointTxs []string,
) (string, string, []string, error) {
	req := a.svc.ArkServiceAPI.ArkServiceSubmitTx(ctx).
		SubmitTxRequest(ark_service.SubmitTxRequest{
			SignedArkTx:   &signedArkTx,
			CheckpointTxs: checkpointTxs,
		})

	resp, _, err := a.svc.ArkServiceAPI.ArkServiceSubmitTxExecute(req)
	if err != nil {
		return "", "", nil, err
	}
	return resp.GetArkTxid(), resp.GetFinalArkTx(), resp.GetSignedCheckpointTxs(), nil
}

func (a *restClient) FinalizeTx(
	ctx context.Context, arkTxid string, finalCheckpointTxs []string,
) error {
	req := a.svc.ArkServiceAPI.ArkServiceFinalizeTx(ctx).
		FinalizeTxRequest(ark_service.FinalizeTxRequest{
			ArkTxid:            &arkTxid,
			FinalCheckpointTxs: finalCheckpointTxs,
		})

	_, _, err := a.svc.ArkServiceAPI.ArkServiceFinalizeTxExecute(req)
	return err
}

func (a *restClient) GetPendingTx(
	ctx context.Context,
	proof, message string,
) ([]client.AcceptedOffchainTx, error) {
	req := a.svc.ArkServiceAPI.ArkServiceGetPendingTx(ctx).
		GetPendingTxRequest(ark_service.GetPendingTxRequest{
			Intent: &ark_service.Intent{
				Message: &message,
				Proof:   &proof,
			},
		})

	resp, _, err := a.svc.ArkServiceAPI.ArkServiceGetPendingTxExecute(req)
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

func (c *restClient) GetTransactionsStream(
	ctx context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	eventsCh := make(chan client.TransactionEvent)
	url := fmt.Sprintf("%s/v1/txs", c.serverURL)
	sseClient := resty.NewEventSource().
		SetURL(url).
		SetHeader("Accept", "text/event-stream").
		OnMessage(func(e any) {
			ev := e.(*resty.Event)
			event := ark_service.GetTransactionsStreamResponse{}
			if err := json.Unmarshal([]byte(ev.Data), &event); err != nil {
				eventsCh <- client.TransactionEvent{Err: err}
				return
			}

			if event.GetHeartbeat() != nil {
				return
			}

			var txEvent client.TransactionEvent
			if commitmentTx := event.GetCommitmentTx(); !ark_service.IsNil(event.CommitmentTx) {
				txEvent = client.TransactionEvent{
					CommitmentTx: &client.TxNotification{
						TxData: client.TxData{
							Txid: commitmentTx.GetTxid(),
							Tx:   commitmentTx.GetTx(),
						},
						SpentVtxos:     vtxosFromRest(commitmentTx.GetSpentVtxos()),
						SpendableVtxos: vtxosFromRest(commitmentTx.GetSpendableVtxos()),
					},
				}
			} else if arkTx := event.GetArkTx(); !ark_service.IsNil(event.ArkTx) {
				checkpointTxs := make(map[types.Outpoint]client.TxData)
				for k, v := range arkTx.GetCheckpointTxs() {
					// nolint
					out, _ := wire.NewOutPointFromString(k)
					checkpointTxs[types.Outpoint{
						Txid: out.Hash.String(),
						VOut: out.Index,
					}] = client.TxData{
						Txid: v.GetTxid(),
						Tx:   v.GetTx(),
					}
				}
				txEvent = client.TransactionEvent{
					ArkTx: &client.TxNotification{
						TxData: client.TxData{
							Txid: arkTx.GetTxid(),
							Tx:   arkTx.GetTx(),
						},
						SpentVtxos:     vtxosFromRest(arkTx.GetSpentVtxos()),
						SpendableVtxos: vtxosFromRest(arkTx.GetSpendableVtxos()),
						CheckpointTxs:  checkpointTxs,
					},
				}
			}

			eventsCh <- txEvent
		}, nil)

	if err := sseClient.Get(); err != nil {
		return nil, nil, err
	}

	return eventsCh, sseClient.Close, nil
}

func (c *restClient) Close() {}

func newRestArkClient(serviceURL string) (*ark_service.APIClient, error) {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, err
	}

	defaultHeaders := map[string]string{
		"Content-Type": "application/json",
	}

	cfg := &ark_service.Configuration{
		Host:          parsedURL.Host,
		DefaultHeader: defaultHeaders,
		Scheme:        parsedURL.Scheme,
		Servers:       ark_service.ServerConfigurations{{URL: serviceURL}},
	}
	return ark_service.NewAPIClient(cfg), nil
}

func vtxosFromRest(restVtxos []ark_service.Vtxo) []types.Vtxo {
	vtxos := make([]types.Vtxo, len(restVtxos))
	for i, v := range restVtxos {
		var expiresAt, createdAt time.Time
		if v.GetExpiresAt() > 0 {
			expiresAt = time.Unix(v.GetExpiresAt(), 0)
		}

		if v.GetCreatedAt() > 0 {
			createdAt = time.Unix(v.GetCreatedAt(), 0)
		}
		vtxos[i] = types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: *v.GetOutpoint().Txid,
				VOut: uint32(*v.GetOutpoint().Vout),
			},
			Script:          v.GetScript(),
			Amount:          uint64(v.GetAmount()),
			CommitmentTxids: v.GetCommitmentTxids(),
			ExpiresAt:       expiresAt,
			CreatedAt:       createdAt,
			Preconfirmed:    v.GetIsPreconfirmed(),
			Swept:           v.GetIsSwept(),
			Unrolled:        v.GetIsUnrolled(),
			Spent:           v.GetIsSpent(),
			SpentBy:         v.GetSpentBy(),
			SettledBy:       v.GetSettledBy(),
			ArkTxid:         v.GetArkTxid(),
		}
	}
	return vtxos
}

func parseFees(fees ark_service.FeeInfo) (types.FeeInfo, error) {
	var (
		err                               error
		txFeeRate                         float64
		onchainInputFee, onchainOutputFee uint64
	)
	if fees.GetTxFeeRate() != "" {
		txFeeRate, err = strconv.ParseFloat(fees.GetTxFeeRate(), 64)
		if err != nil {
			return types.FeeInfo{}, err
		}
	}
	intentFee := fees.GetIntentFee()
	if intentFee.GetOnchainInput() != "" {
		onchainInputFee, err = strconv.ParseUint(intentFee.GetOnchainInput(), 10, 64)
		if err != nil {
			return types.FeeInfo{}, err
		}
	}
	if intentFee.GetOnchainOutput() != "" {
		onchainOutputFee, err = strconv.ParseUint(intentFee.GetOnchainOutput(), 10, 64)
		if err != nil {
			return types.FeeInfo{}, err
		}
	}
	return types.FeeInfo{
		TxFeeRate: txFeeRate,
		IntentFees: types.IntentFeeInfo{
			OffchainInput:  intentFee.GetOffchainInput(),
			OffchainOutput: intentFee.GetOffchainOutput(),
			OnchainInput:   onchainInputFee,
			OnchainOutput:  onchainOutputFee,
		},
	}, nil
}
