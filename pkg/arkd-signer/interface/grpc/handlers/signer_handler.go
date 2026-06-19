package handlers

import (
	"context"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
)

type signerHandler struct {
	signer application.Signer
}

func NewSignerHandler(signer application.Signer) signerv1.SignerServiceServer {
	return &signerHandler{signer: signer}
}

func (h *signerHandler) GetStatus(
	ctx context.Context, _ *signerv1.GetStatusRequest,
) (*signerv1.GetStatusResponse, error) {
	return &signerv1.GetStatusResponse{Ready: h.signer.IsReady(ctx)}, nil
}

func (h *signerHandler) GetPubkey(
	ctx context.Context, _ *signerv1.GetPubkeyRequest,
) (*signerv1.GetPubkeyResponse, error) {
	pubkey, err := h.signer.GetPubkey(ctx)
	if err != nil {
		return nil, err
	}
	return &signerv1.GetPubkeyResponse{Pubkey: pubkey}, nil
}

func (h *signerHandler) SignTransaction(
	ctx context.Context, req *signerv1.SignTransactionRequest,
) (*signerv1.SignTransactionResponse, error) {
	tx, err := h.signer.SignTransaction(ctx, req.GetPartialTx(), req.GetExtractRawTx())
	if err != nil {
		return nil, err
	}
	return &signerv1.SignTransactionResponse{SignedTx: tx}, nil
}

func (h *signerHandler) SignTransactionTapscript(
	ctx context.Context, req *signerv1.SignTransactionTapscriptRequest,
) (*signerv1.SignTransactionTapscriptResponse, error) {
	inIndexes := make([]int, 0, len(req.GetInputIndexes()))
	for _, v := range req.GetInputIndexes() {
		inIndexes = append(inIndexes, int(v))
	}
	tx, err := h.signer.SignTransactionTapscript(ctx, req.GetPartialTx(), inIndexes)
	if err != nil {
		return nil, err
	}
	return &signerv1.SignTransactionTapscriptResponse{SignedTx: tx}, nil
}
