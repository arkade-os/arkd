package handlers

import (
	"context"
	"encoding/hex"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	application "github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type signerHandler struct {
	wallet  application.WalletService
	scanner application.BlockchainScanner
}

func NewSignerHandler(walletSvc application.WalletService) signerv1.SignerServiceServer {
	return &signerHandler{wallet: walletSvc}
}

func (h *signerHandler) GetStatus(
	ctx context.Context, _ *signerv1.GetStatusRequest,
) (*signerv1.GetStatusResponse, error) {
	_, err := h.wallet.GetSignerPubkey(ctx)
	return &signerv1.GetStatusResponse{
		Ready: err == nil,
	}, nil
}

func (h *signerHandler) GetPubkey(
	ctx context.Context, req *signerv1.GetPubkeyRequest,
) (*signerv1.GetPubkeyResponse, error) {
	pubkey, err := h.wallet.GetSignerPubkey(ctx)
	if err != nil {
		return nil, err
	}
	return &signerv1.GetPubkeyResponse{Pubkey: pubkey}, nil
}

func (h *signerHandler) SignTransaction(
	ctx context.Context, req *signerv1.SignTransactionRequest,
) (*signerv1.SignTransactionResponse, error) {
	signMode := application.SignModeSigner
	tx, err := h.wallet.SignTransaction(ctx, signMode, req.PartialTx, req.ExtractRawTx, nil)
	if err != nil {
		return nil, err
	}
	return &signerv1.SignTransactionResponse{SignedTx: tx}, nil
}

func (h *signerHandler) SignTransactionTapscript(
	ctx context.Context, req *signerv1.SignTransactionTapscriptRequest,
) (*signerv1.SignTransactionTapscriptResponse, error) {
	signMode := application.SignModeSigner
	inIndexes := make([]int, 0, len(req.GetInputIndexes()))
	for _, v := range req.GetInputIndexes() {
		inIndexes = append(inIndexes, int(v))
	}
	tx, err := h.wallet.SignTransaction(ctx, signMode, req.GetPartialTx(), false, inIndexes)
	if err != nil {
		return nil, err
	}
	return &signerv1.SignTransactionTapscriptResponse{SignedTx: tx}, nil
}

func (h *signerHandler) SignMessage(
	ctx context.Context, req *signerv1.SignMessageRequest,
) (*signerv1.SignMessageResponse, error) {
	message, err := hex.DecodeString(req.GetMessage())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid message hex: %s", err)
	}
	signature, err := h.wallet.SignMessage(ctx, message)
	if err != nil {
		return nil, err
	}
	return &signerv1.SignMessageResponse{Signature: hex.EncodeToString(signature)}, nil
}
