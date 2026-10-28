package handlers

import (
	"context"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
)

type signerHandler struct {
	signer *application.Signer
}

func NewSignerHandler(signer *application.Signer) signerv1.SignerServiceServer {
	return &signerHandler{signer: signer}
}

func (h *signerHandler) GetStatus(
	context.Context, *signerv1.GetStatusRequest,
) (*signerv1.GetStatusResponse, error) {
	return &signerv1.GetStatusResponse{Ready: true}, nil
}

func (h *signerHandler) GetPubkey(
	context.Context, *signerv1.GetPubkeyRequest,
) (*signerv1.GetPubkeyResponse, error) {
	deprecated := h.signer.GetDeprecatedPubkeys()
	deprecatedSigners := make([]*signerv1.DeprecatedSigner, 0, len(deprecated))
	for _, d := range deprecated {
		deprecatedSigners = append(deprecatedSigners, &signerv1.DeprecatedSigner{
			Pubkey:     d.Pubkey,
			CutoffDate: d.CutoffDate,
		})
	}
	return &signerv1.GetPubkeyResponse{
		Pubkey:            h.signer.GetPubkey(),
		DeprecatedSigners: deprecatedSigners,
	}, nil
}

func (h *signerHandler) SignTransaction(
	_ context.Context, req *signerv1.SignTransactionRequest,
) (*signerv1.SignTransactionResponse, error) {
	inIndexes := make([]int, 0, len(req.GetInputIndexes()))
	for _, v := range req.GetInputIndexes() {
		inIndexes = append(inIndexes, int(v))
	}
	tx, err := h.signer.SignTransaction(req.GetPartialTx(), inIndexes)
	if err != nil {
		return nil, err
	}
	return &signerv1.SignTransactionResponse{SignedTx: tx}, nil
}
