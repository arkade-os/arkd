package handlers

import (
	"context"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	application "github.com/arkade-os/arkd/pkg/arkd-wallet/core"
)

type WalletServiceHandler struct {
	walletSvc application.WalletService
}

func NewWalletServiceHandler(walletSvc application.WalletService) arkwalletv1.WalletServiceServer {
	return &WalletServiceHandler{walletSvc: walletSvc}
}

func (h *WalletServiceHandler) GenSeed(ctx context.Context, _ *arkwalletv1.GenSeedRequest) (*arkwalletv1.GenSeedResponse, error) {
	seed, err := h.walletSvc.GenSeed(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GenSeedResponse{Seed: seed}, nil
}

func (h *WalletServiceHandler) Create(ctx context.Context, req *arkwalletv1.CreateRequest) (*arkwalletv1.CreateResponse, error) {
	if err := h.walletSvc.Create(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, err
	}
	return &arkwalletv1.CreateResponse{}, nil
}

func (h *WalletServiceHandler) Restore(ctx context.Context, req *arkwalletv1.RestoreRequest) (*arkwalletv1.RestoreResponse, error) {
	if err := h.walletSvc.Restore(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, err
	}
	return &arkwalletv1.RestoreResponse{}, nil
}

func (h *WalletServiceHandler) Unlock(ctx context.Context, req *arkwalletv1.UnlockRequest) (*arkwalletv1.UnlockResponse, error) {
	if err := h.walletSvc.Unlock(ctx, req.GetPassword()); err != nil {
		return nil, err
	}
	return &arkwalletv1.UnlockResponse{}, nil
}

func (h *WalletServiceHandler) Lock(ctx context.Context, req *arkwalletv1.LockRequest) (*arkwalletv1.LockResponse, error) {
	if err := h.walletSvc.Lock(ctx); err != nil {
		return nil, err
	}
	return &arkwalletv1.LockResponse{}, nil
}

func (h *WalletServiceHandler) Status(ctx context.Context, _ *arkwalletv1.StatusRequest) (*arkwalletv1.StatusResponse, error) {
	status, err := h.walletSvc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.StatusResponse{
		Initialized: status.IsInitialized,
		Unlocked:    status.IsUnlocked,
		Synced:      status.IsSynced,
	}, nil
}

func (h *WalletServiceHandler) GetPubkey(ctx context.Context, _ *arkwalletv1.GetPubkeyRequest) (*arkwalletv1.GetPubkeyResponse, error) {
	pubkey, err := h.walletSvc.GetPubkey(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GetPubkeyResponse{Pubkey: pubkey.SerializeCompressed()}, nil
}

func (h *WalletServiceHandler) GetNetwork(ctx context.Context, _ *arkwalletv1.GetNetworkRequest) (*arkwalletv1.GetNetworkResponse, error) {
	network := h.walletSvc.GetNetwork(ctx)
	return &arkwalletv1.GetNetworkResponse{Network: network}, nil
}

func (h *WalletServiceHandler) GetForfeitAddress(
	ctx context.Context, req *arkwalletv1.GetForfeitAddressRequest,
) (*arkwalletv1.GetForfeitAddressResponse, error) {
	addr, err := h.walletSvc.GetForfeitAddress(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GetForfeitAddressResponse{Address: addr}, nil
}

func (h *WalletServiceHandler) WatchScripts(
	ctx context.Context, request *arkwalletv1.WatchScriptsRequest,
) (*arkwalletv1.WatchScriptsResponse, error) {
	if err := h.walletSvc.WatchScripts(ctx, request.Scripts); err != nil {
		return nil, err
	}
	return &arkwalletv1.WatchScriptsResponse{}, nil
}

func (h *WalletServiceHandler) UnwatchScripts(
	ctx context.Context, request *arkwalletv1.UnwatchScriptsRequest,
) (*arkwalletv1.UnwatchScriptsResponse, error) {
	if err := h.walletSvc.UnwatchScripts(ctx, request.Scripts); err != nil {
		return nil, err
	}
	return &arkwalletv1.UnwatchScriptsResponse{}, nil
}

func (h *WalletServiceHandler) DeriveConnectorAddress(
	ctx context.Context, _ *arkwalletv1.DeriveConnectorAddressRequest,
) (*arkwalletv1.DeriveConnectorAddressResponse, error) {
	addr, err := h.walletSvc.DeriveConnectorAddress(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.DeriveConnectorAddressResponse{Address: addr}, nil
}

func (h *WalletServiceHandler) DeriveAddresses(
	ctx context.Context, req *arkwalletv1.DeriveAddressesRequest,
) (*arkwalletv1.DeriveAddressesResponse, error) {
	addresses, err := h.walletSvc.DeriveAddresses(ctx, int(req.Num))
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.DeriveAddressesResponse{Addresses: addresses}, nil
}

func (h *WalletServiceHandler) SignTransaction(
	ctx context.Context, req *arkwalletv1.SignTransactionRequest,
) (*arkwalletv1.SignTransactionResponse, error) {
	tx, err := h.walletSvc.SignTransaction(ctx, req.PartialTx, req.ExtractRawTx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.SignTransactionResponse{SignedTx: tx}, nil
}

func (h *WalletServiceHandler) SignTransactionTapscript(
	ctx context.Context, req *arkwalletv1.SignTransactionTapscriptRequest,
) (*arkwalletv1.SignTransactionTapscriptResponse, error) {
	inIndexes := make([]int, 0, len(req.GetInputIndexes()))
	for _, v := range req.GetInputIndexes() {
		inIndexes = append(inIndexes, int(v))
	}
	tx, err := h.walletSvc.SignTransactionTapscript(ctx, req.GetPartialTx(), inIndexes)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.SignTransactionTapscriptResponse{SignedTx: tx}, nil
}

func (h *WalletServiceHandler) SelectUtxos(
	ctx context.Context, req *arkwalletv1.SelectUtxosRequest,
) (*arkwalletv1.SelectUtxosResponse, error) {
	utxos, total, err := h.walletSvc.SelectUtxos(ctx, req.GetAsset(), req.GetAmount(), req.GetConfirmedOnly())
	if err != nil {
		return nil, err
	}
	var respUtxos []*arkwalletv1.TxInput
	for _, u := range utxos {
		respUtxos = append(respUtxos, &arkwalletv1.TxInput{
			Txid:   u.Txid,
			Index:  u.Index,
			Script: u.Script,
			Value:  u.Value,
		})
	}
	return &arkwalletv1.SelectUtxosResponse{Utxos: respUtxos, TotalAmount: total}, nil
}

func (h *WalletServiceHandler) BroadcastTransaction(
	ctx context.Context, req *arkwalletv1.BroadcastTransactionRequest,
) (*arkwalletv1.BroadcastTransactionResponse, error) {
	txid, err := h.walletSvc.BroadcastTransaction(ctx, req.GetTxs()...)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.BroadcastTransactionResponse{Txid: txid}, nil
}

func (h *WalletServiceHandler) WaitForSync(
	ctx context.Context, req *arkwalletv1.WaitForSyncRequest,
) (*arkwalletv1.WaitForSyncResponse, error) {
	if err := h.walletSvc.WaitForSync(ctx, req.GetTxid()); err != nil {
		return nil, err
	}
	return &arkwalletv1.WaitForSyncResponse{}, nil
}

func (h *WalletServiceHandler) EstimateFees(
	ctx context.Context, req *arkwalletv1.EstimateFeesRequest,
) (*arkwalletv1.EstimateFeesResponse, error) {
	fee, err := h.walletSvc.EstimateFees(ctx, req.GetPsbt())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.EstimateFeesResponse{Fee: fee}, nil
}

func (h *WalletServiceHandler) FeeRate(
	ctx context.Context, _ *arkwalletv1.FeeRateRequest,
) (*arkwalletv1.FeeRateResponse, error) {
	feeRate, err := h.walletSvc.FeeRate(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.FeeRateResponse{SatPerKvbyte: uint64(feeRate)}, nil
}

func (h *WalletServiceHandler) ListConnectorUtxos(
	ctx context.Context, req *arkwalletv1.ListConnectorUtxosRequest,
) (*arkwalletv1.ListConnectorUtxosResponse, error) {
	utxos, err := h.walletSvc.ListConnectorUtxos(ctx, req.GetConnectorAddress())
	if err != nil {
		return nil, err
	}
	respUtxos := make([]*arkwalletv1.TxInput, 0, len(utxos))
	for _, u := range utxos {
		respUtxos = append(respUtxos, &arkwalletv1.TxInput{
			Txid:   u.Txid,
			Index:  u.Index,
			Script: u.Script,
			Value:  u.Value,
		})
	}
	return &arkwalletv1.ListConnectorUtxosResponse{Utxos: respUtxos}, nil
}

func (h *WalletServiceHandler) MainAccountBalance(
	ctx context.Context, _ *arkwalletv1.MainAccountBalanceRequest,
) (*arkwalletv1.MainAccountBalanceResponse, error) {
	confirmed, unconfirmed, err := h.walletSvc.MainAccountBalance(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.MainAccountBalanceResponse{Confirmed: confirmed, Unconfirmed: unconfirmed}, nil
}

func (h *WalletServiceHandler) ConnectorsAccountBalance(
	ctx context.Context, _ *arkwalletv1.ConnectorsAccountBalanceRequest,
) (*arkwalletv1.ConnectorsAccountBalanceResponse, error) {
	confirmed, unconfirmed, err := h.walletSvc.ConnectorsAccountBalance(ctx)
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.ConnectorsAccountBalanceResponse{Confirmed: confirmed, Unconfirmed: unconfirmed}, nil
}

func (h *WalletServiceHandler) LockConnectorUtxos(
	ctx context.Context, req *arkwalletv1.LockConnectorUtxosRequest,
) (*arkwalletv1.LockConnectorUtxosResponse, error) {
	utxos := make([]application.TxOutpoint, 0, len(req.GetUtxos()))
	for _, u := range req.Utxos {
		utxos = append(utxos, application.TxOutpoint{
			Txid:  u.GetTxid(),
			Index: u.GetIndex(),
		})
	}
	if err := h.walletSvc.LockConnectorUtxos(ctx, utxos); err != nil {
		return nil, err
	}
	return &arkwalletv1.LockConnectorUtxosResponse{}, nil
}

func (h *WalletServiceHandler) GetDustAmount(
	ctx context.Context, _ *arkwalletv1.GetDustAmountRequest,
) (*arkwalletv1.GetDustAmountResponse, error) {
	dust := h.walletSvc.GetDustAmount(ctx)
	return &arkwalletv1.GetDustAmountResponse{DustAmount: dust}, nil
}

func (h *WalletServiceHandler) GetTransaction(
	ctx context.Context, req *arkwalletv1.GetTransactionRequest,
) (*arkwalletv1.GetTransactionResponse, error) {
	tx, err := h.walletSvc.GetTransaction(ctx, req.GetTxid())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.GetTransactionResponse{TxHex: tx}, nil
}

func (h *WalletServiceHandler) SignMessage(
	ctx context.Context, req *arkwalletv1.SignMessageRequest,
) (*arkwalletv1.SignMessageResponse, error) {
	sig, err := h.walletSvc.SignMessage(ctx, req.GetMessage())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.SignMessageResponse{Signature: sig}, nil
}

func (h *WalletServiceHandler) VerifyMessageSignature(
	ctx context.Context, req *arkwalletv1.VerifyMessageSignatureRequest,
) (*arkwalletv1.VerifyMessageSignatureResponse, error) {
	valid, err := h.walletSvc.VerifyMessageSignature(ctx, req.GetMessage(), req.GetSignature())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.VerifyMessageSignatureResponse{Valid: valid}, nil
}

func (h *WalletServiceHandler) GetCurrentBlockTime(
	ctx context.Context, _ *arkwalletv1.GetCurrentBlockTimeRequest,
) (*arkwalletv1.GetCurrentBlockTimeResponse, error) {
	ts, err := h.walletSvc.GetCurrentBlockTime(ctx)
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
func (h *WalletServiceHandler) IsTransactionConfirmed(
	ctx context.Context, req *arkwalletv1.IsTransactionConfirmedRequest,
) (*arkwalletv1.IsTransactionConfirmedResponse, error) {
	confirmed, blocknumber, blocktime, err := h.walletSvc.IsTransactionConfirmed(ctx, req.GetTxid())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.IsTransactionConfirmedResponse{
		Confirmed:   confirmed,
		Blocknumber: blocknumber,
		Blocktime:   blocktime,
	}, nil
}

// GetReadyUpdate streams an empty response when the wallet is unlocker and synced.
func (h *WalletServiceHandler) GetReadyUpdate(
	_ *arkwalletv1.GetReadyUpdateRequest, stream arkwalletv1.WalletService_GetReadyUpdateServer,
) error {
	ch := h.walletSvc.GetReadyUpdate(stream.Context())
	select {
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-ch:
		return stream.Send(&arkwalletv1.GetReadyUpdateResponse{
			Ready: true,
		})
	}
}

// NotificationStream streams notifications to the client.
func (h *WalletServiceHandler) NotificationStream(
	_ *arkwalletv1.NotificationStreamRequest, stream arkwalletv1.WalletService_NotificationStreamServer,
) error {
	ctx := stream.Context()
	ch := h.walletSvc.GetNotificationChannel(ctx)

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
						Txid:  v.Key.Txid,
						Vout:  v.Key.VOut,
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

func (h *WalletServiceHandler) Withdraw(
	ctx context.Context, req *arkwalletv1.WithdrawRequest,
) (*arkwalletv1.WithdrawResponse, error) {
	txid, err := h.walletSvc.Withdraw(ctx, req.GetAddress(), req.GetAmount())
	if err != nil {
		return nil, err
	}
	return &arkwalletv1.WithdrawResponse{Txid: txid}, nil
}
