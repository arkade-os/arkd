package handlers

import (
	"context"
	"encoding/hex"
	"errors"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	application "github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type walletHandler struct {
	wallet         application.WalletService
	scanner        application.BlockchainScanner
	readyListeners *broker[*arkwalletv1.GetReadyUpdateResponse]
}

func NewWalletServiceHandler(
	ctx context.Context, walletSvc application.WalletService, scanner application.BlockchainScanner,
) arkwalletv1.WalletServiceServer {
	svc := &walletHandler{
		wallet:         walletSvc,
		scanner:        scanner,
		readyListeners: newBroker[*arkwalletv1.GetReadyUpdateResponse](),
	}
	go svc.listenToReadyUpdate(ctx)
	return svc
}

func (h *walletHandler) GenSeed(
	ctx context.Context, _ *arkwalletv1.GenSeedRequest,
) (*arkwalletv1.GenSeedResponse, error) {
	seed, err := h.wallet.GenSeed(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GenSeedResponse{Seed: seed}, nil
}

func (h *walletHandler) Create(
	ctx context.Context, req *arkwalletv1.CreateRequest,
) (*arkwalletv1.CreateResponse, error) {
	if err := h.wallet.Create(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, err
	}
	return &arkwalletv1.CreateResponse{}, nil
}

func (h *walletHandler) Restore(
	ctx context.Context, req *arkwalletv1.RestoreRequest,
) (*arkwalletv1.RestoreResponse, error) {
	if err := h.wallet.Restore(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, err
	}
	return &arkwalletv1.RestoreResponse{}, nil
}

func (h *walletHandler) Unlock(
	ctx context.Context, req *arkwalletv1.UnlockRequest,
) (*arkwalletv1.UnlockResponse, error) {
	if err := h.wallet.Unlock(ctx, req.GetPassword()); err != nil {
		return nil, err
	}
	return &arkwalletv1.UnlockResponse{}, nil
}

func (h *walletHandler) Lock(
	ctx context.Context, req *arkwalletv1.LockRequest,
) (*arkwalletv1.LockResponse, error) {
	if err := h.wallet.Lock(ctx); err != nil {
		return nil, err
	}
	return &arkwalletv1.LockResponse{}, nil
}

func (h *walletHandler) Status(
	ctx context.Context, _ *arkwalletv1.StatusRequest,
) (*arkwalletv1.StatusResponse, error) {
	status := h.wallet.Status(ctx)

	return &arkwalletv1.StatusResponse{
		Initialized: status.IsInitialized,
		Unlocked:    status.IsUnlocked,
		Synced:      status.IsSynced,
	}, nil
}

func (h *walletHandler) GetNetwork(
	ctx context.Context, _ *arkwalletv1.GetNetworkRequest,
) (*arkwalletv1.GetNetworkResponse, error) {
	network := h.wallet.GetNetwork(ctx)
	return &arkwalletv1.GetNetworkResponse{Network: network}, nil
}

func (h *walletHandler) GetForfeitPubkey(
	ctx context.Context, req *arkwalletv1.GetForfeitPubkeyRequest,
) (*arkwalletv1.GetForfeitPubkeyResponse, error) {
	pubkey, err := h.wallet.GetForfeitPubkey(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GetForfeitPubkeyResponse{Pubkey: pubkey}, nil
}

func (h *walletHandler) WatchScripts(
	ctx context.Context, request *arkwalletv1.WatchScriptsRequest,
) (*arkwalletv1.WatchScriptsResponse, error) {
	if err := h.scanner.WatchScripts(ctx, request.Scripts); err != nil {
		return nil, err
	}
	return &arkwalletv1.WatchScriptsResponse{}, nil
}

func (h *walletHandler) UnwatchScripts(
	ctx context.Context, request *arkwalletv1.UnwatchScriptsRequest,
) (*arkwalletv1.UnwatchScriptsResponse, error) {
	if err := h.scanner.UnwatchScripts(ctx, request.Scripts); err != nil {
		return nil, err
	}
	return &arkwalletv1.UnwatchScriptsResponse{}, nil
}

func (h *walletHandler) DeriveConnectorAddress(
	ctx context.Context, _ *arkwalletv1.DeriveConnectorAddressRequest,
) (*arkwalletv1.DeriveConnectorAddressResponse, error) {
	addr, err := h.wallet.DeriveConnectorAddress(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.DeriveConnectorAddressResponse{Address: addr}, nil
}

func (h *walletHandler) DeriveAddresses(
	ctx context.Context, req *arkwalletv1.DeriveAddressesRequest,
) (*arkwalletv1.DeriveAddressesResponse, error) {
	addresses, err := h.wallet.DeriveAddresses(ctx, int(req.Num))
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.DeriveAddressesResponse{Addresses: addresses}, nil
}

func (h *walletHandler) SignTransaction(
	ctx context.Context, req *arkwalletv1.SignTransactionRequest,
) (*arkwalletv1.SignTransactionResponse, error) {
	signMode := application.SignModeLiquidityProvider
	tx, err := h.wallet.SignTransaction(ctx, signMode, req.PartialTx, req.ExtractRawTx, nil)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.SignTransactionResponse{SignedTx: tx}, nil
}

func (h *walletHandler) SignTransactionTapscript(
	ctx context.Context, req *arkwalletv1.SignTransactionTapscriptRequest,
) (*arkwalletv1.SignTransactionTapscriptResponse, error) {
	signMode := application.SignModeLiquidityProvider
	inIndexes := make([]int, 0, len(req.GetInputIndexes()))
	for _, v := range req.GetInputIndexes() {
		inIndexes = append(inIndexes, int(v))
	}
	tx, err := h.wallet.SignTransaction(ctx, signMode, req.GetPartialTx(), false, inIndexes)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.SignTransactionTapscriptResponse{SignedTx: tx}, nil
}

func (h *walletHandler) SelectUtxos(
	ctx context.Context, req *arkwalletv1.SelectUtxosRequest,
) (*arkwalletv1.SelectUtxosResponse, error) {
	utxos, total, err := h.wallet.SelectUtxos(ctx, req.GetAmount(), req.GetConfirmedOnly())
	if err != nil {
		return nil, err
	}
	var respUtxos []*arkwalletv1.TxInput
	for _, u := range utxos {
		respUtxos = append(respUtxos, toTxInput(u))
	}
	return &arkwalletv1.SelectUtxosResponse{Utxos: respUtxos, TotalAmount: total}, nil
}

func (h *walletHandler) BroadcastTransaction(
	ctx context.Context, req *arkwalletv1.BroadcastTransactionRequest,
) (*arkwalletv1.BroadcastTransactionResponse, error) {
	txid, err := h.wallet.BroadcastTransaction(ctx, req.GetTxs()...)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.BroadcastTransactionResponse{Txid: txid}, nil
}

func (h *walletHandler) EstimateFees(
	ctx context.Context, req *arkwalletv1.EstimateFeesRequest,
) (*arkwalletv1.EstimateFeesResponse, error) {
	fee, err := h.wallet.EstimateFees(ctx, req.GetPsbt())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.EstimateFeesResponse{Fee: fee}, nil
}

func (h *walletHandler) FeeRate(
	ctx context.Context, _ *arkwalletv1.FeeRateRequest,
) (*arkwalletv1.FeeRateResponse, error) {
	feeRate, err := h.wallet.FeeRate(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.FeeRateResponse{SatPerKvbyte: uint64(feeRate)}, nil
}

func (h *walletHandler) ListConnectorUtxos(
	ctx context.Context, req *arkwalletv1.ListConnectorUtxosRequest,
) (*arkwalletv1.ListConnectorUtxosResponse, error) {
	utxos, err := h.wallet.ListConnectorUtxos(ctx, req.GetConnectorAddress())
	if err != nil {
		return nil, err
	}
	respUtxos := make([]*arkwalletv1.TxInput, 0, len(utxos))
	for _, u := range utxos {
		respUtxos = append(respUtxos, toTxInput(u))
	}
	return &arkwalletv1.ListConnectorUtxosResponse{Utxos: respUtxos}, nil
}

func (h *walletHandler) MainAccountBalance(
	ctx context.Context, _ *arkwalletv1.MainAccountBalanceRequest,
) (*arkwalletv1.MainAccountBalanceResponse, error) {
	confirmed, unconfirmed, err := h.wallet.MainAccountBalance(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.MainAccountBalanceResponse{Confirmed: confirmed, Unconfirmed: unconfirmed}, nil
}

func (h *walletHandler) ConnectorsAccountBalance(
	ctx context.Context, _ *arkwalletv1.ConnectorsAccountBalanceRequest,
) (*arkwalletv1.ConnectorsAccountBalanceResponse, error) {
	confirmed, unconfirmed, err := h.wallet.ConnectorsAccountBalance(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.ConnectorsAccountBalanceResponse{Confirmed: confirmed, Unconfirmed: unconfirmed}, nil
}

func (h *walletHandler) LockConnectorUtxos(
	ctx context.Context, req *arkwalletv1.LockConnectorUtxosRequest,
) (*arkwalletv1.LockConnectorUtxosResponse, error) {
	utxos := make([]wire.OutPoint, 0, len(req.GetUtxos()))
	for _, u := range req.Utxos {
		txhash, err := chainhash.NewHashFromStr(u.GetTxid())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid txid: %v", err)
		}

		utxos = append(utxos, wire.OutPoint{
			Hash:  *txhash,
			Index: u.GetIndex(),
		})
	}
	if err := h.wallet.LockConnectorUtxos(ctx, utxos); err != nil {
		return nil, err
	}
	return &arkwalletv1.LockConnectorUtxosResponse{}, nil
}

func (h *walletHandler) GetDustAmount(
	ctx context.Context, _ *arkwalletv1.GetDustAmountRequest,
) (*arkwalletv1.GetDustAmountResponse, error) {
	dust := h.wallet.GetDustAmount(ctx)
	return &arkwalletv1.GetDustAmountResponse{DustAmount: dust}, nil
}

func (h *walletHandler) GetTransaction(
	ctx context.Context, req *arkwalletv1.GetTransactionRequest,
) (*arkwalletv1.GetTransactionResponse, error) {
	tx, err := h.wallet.GetTransaction(ctx, req.GetTxid())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GetTransactionResponse{TxHex: tx}, nil
}

func (h *walletHandler) SignMessage(
	ctx context.Context, req *arkwalletv1.SignMessageRequest,
) (*arkwalletv1.SignMessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignMessage not implemented")
}

func (h *walletHandler) VerifyMessageSignature(
	ctx context.Context, req *arkwalletv1.VerifyMessageSignatureRequest,
) (*arkwalletv1.VerifyMessageSignatureResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyMessageSignature not implemented")
}

func (h *walletHandler) GetCurrentBlockTime(
	ctx context.Context, _ *arkwalletv1.GetCurrentBlockTimeRequest,
) (*arkwalletv1.GetCurrentBlockTimeResponse, error) {
	ts, err := h.wallet.GetCurrentBlockTime(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GetCurrentBlockTimeResponse{
		Timestamp: &arkwalletv1.BlockTimestamp{
			Height: ts.Height,
			Time:   ts.Time,
		},
	}, nil
}

// IsTransactionConfirmed returns confirmation status, blocknumber, and blocktime for a txid.
func (h *walletHandler) IsTransactionConfirmed(
	ctx context.Context, req *arkwalletv1.IsTransactionConfirmedRequest,
) (*arkwalletv1.IsTransactionConfirmedResponse, error) {
	confirmed, blocknumber, blocktime, err := h.scanner.IsTransactionConfirmed(ctx, req.GetTxid())
	if err != nil {
		if errors.Is(err, application.ErrTransactionNotFound) {
			return &arkwalletv1.IsTransactionConfirmedResponse{
				Confirmed:   false,
				Blocknumber: 0,
				Blocktime:   0,
			}, nil
		}
		return nil, err
	}
	return &arkwalletv1.IsTransactionConfirmedResponse{
		Confirmed:   confirmed,
		Blocknumber: blocknumber,
		Blocktime:   blocktime,
	}, nil
}

func (h *walletHandler) GetOutpointStatus(
	ctx context.Context, req *arkwalletv1.GetOutpointStatusRequest,
) (*arkwalletv1.GetOutpointStatusResponse, error) {
	txid := req.GetTxid()
	vout := req.GetVout()

	if len(txid) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "txid is required")
	}

	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid txid: %v", err)
	}

	spent, err := h.scanner.GetOutpointStatus(ctx, wire.OutPoint{
		Hash:  *txhash,
		Index: vout,
	})
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GetOutpointStatusResponse{Spent: spent}, nil
}

// GetReadyUpdate streams an empty response when the wallet is unlocker and synced.
func (h *walletHandler) GetReadyUpdate(
	_ *arkwalletv1.GetReadyUpdateRequest, stream arkwalletv1.WalletService_GetReadyUpdateServer,
) error {
	id := uuid.NewString()
	listener := newListener[*arkwalletv1.GetReadyUpdateResponse](id)
	h.readyListeners.pushListener(listener)

	log.Debugf("added new listener %s for ready update", id)

	if status := h.wallet.Status(stream.Context()); status.IsInitialized &&
		status.IsSynced && status.IsUnlocked {
		if err := stream.Send(&arkwalletv1.GetReadyUpdateResponse{Ready: true}); err != nil {
			return err
		}
	}

	for {
		select {
		case <-stream.Context().Done():
			h.readyListeners.removeListener(id)
			log.Debugf("removed listener %s", id)
			return stream.Context().Err()
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// NotificationStream streams notifications to the client.
func (h *walletHandler) NotificationStream(
	_ *arkwalletv1.NotificationStreamRequest, stream arkwalletv1.WalletService_NotificationStreamServer,
) error {
	ctx := stream.Context()
	ch := h.scanner.GetNotificationChannel(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case notification, ok := <-ch:
			if !ok {
				return nil
			}

			entries := make([]*arkwalletv1.VtoxsPerScript, 0, len(notification))
			for script, vtxos := range notification {
				entry := &arkwalletv1.VtoxsPerScript{
					Script: script,
					Vtxos:  make([]*arkwalletv1.VtxoWithKey, 0, len(vtxos)),
				}
				for _, v := range vtxos {
					entry.Vtxos = append(entry.Vtxos, &arkwalletv1.VtxoWithKey{
						Txid:  v.Txid,
						Vout:  v.Index,
						Value: v.Value,
					})
				}
				entries = append(entries, entry)
			}

			resp := &arkwalletv1.NotificationStreamResponse{
				Entries: entries,
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

func (h *walletHandler) Withdraw(
	ctx context.Context, req *arkwalletv1.WithdrawRequest,
) (*arkwalletv1.WithdrawResponse, error) {
	address := req.GetAddress()
	if len(address) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "address is required")
	}

	if req.GetAll() {
		txid, err := h.wallet.WithdrawAll(ctx, address)
		if err != nil {
			return nil, err
		}
		return &arkwalletv1.WithdrawResponse{Txid: txid}, nil
	}

	amount := req.GetAmount()
	if amount <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "amount must be greater than 0")
	}

	txid, err := h.wallet.Withdraw(ctx, address, amount)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.WithdrawResponse{Txid: txid}, nil
}

func (h *walletHandler) LoadSignerKey(
	ctx context.Context, req *arkwalletv1.LoadSignerKeyRequest,
) (*arkwalletv1.LoadSignerKeyResponse, error) {
	key := req.GetPrivateKey()
	if len(key) <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "missing private key")
	}
	buf, err := hex.DecodeString(key)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid private key format, must be hex")
	}
	prvkey, _ := btcec.PrivKeyFromBytes(buf)
	if err := h.wallet.LoadSignerKey(ctx, prvkey); err != nil {
		return nil, err
	}
	return &arkwalletv1.LoadSignerKeyResponse{}, nil
}
func (h *walletHandler) RescanUtxos(
	ctx context.Context, req *arkwalletv1.RescanUtxosRequest,
) (*arkwalletv1.RescanUtxosResponse, error) {
	outs := make([]wire.OutPoint, 0, len(req.Outpoints))
	for _, out := range req.Outpoints {
		o, err := wire.NewOutPointFromString(out)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		outs = append(outs, *o)
	}
	if err := h.scanner.RescanUtxos(ctx, outs); err != nil {
		return nil, err
	}
	return &arkwalletv1.RescanUtxosResponse{}, nil
}

func (h *walletHandler) listenToReadyUpdate(ctx context.Context) {
	ch := h.wallet.GetReadyUpdate(ctx)
	for {
		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.Canceled) {
				log.WithError(ctx.Err()).Error("ready update channel closed unexpectedly")
			}
			return
		case <-ch:
			for _, l := range h.readyListeners.getListenersCopy() {
				go func(listener *listener[*arkwalletv1.GetReadyUpdateResponse]) {
					select {
					case listener.ch <- &arkwalletv1.GetReadyUpdateResponse{Ready: true}:
					default:
						log.Warnf("could not forward ready update to listener %s", listener.id)
					}
				}(l)
			}
		}
	}
}

// toTxInput converts a UTXO to a TxInput protobuf message
func toTxInput(u application.Utxo) *arkwalletv1.TxInput {
	return &arkwalletv1.TxInput{
		Txid:   u.Txid,
		Index:  u.Index,
		Script: u.Script,
		Value:  u.Value,
	}
}
