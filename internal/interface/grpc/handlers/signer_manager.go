package handlers

import (
	"context"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/ports"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type signerManagerHandler struct {
	walletSvc    ports.WalletService
	onLoadSigner func(addr string) error
}

func NewSignerManagerHandler(
	walletSvc ports.WalletService, onLoadSigner func(addr string) error,
) arkv1.SignerManagerServiceServer {
	return &signerManagerHandler{walletSvc, onLoadSigner}
}

func (h *signerManagerHandler) LoadSigner(
	ctx context.Context, req *arkv1.LoadSignerRequest,
) (*arkv1.LoadSignerResponse, error) {
	if req.GetAddress() == "" && req.GetPrivateKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing address or private key")
	}

	if req.GetPrivateKey() != "" {
		if err := h.walletSvc.LoadSignerKey(ctx, req.GetPrivateKey()); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return &arkv1.LoadSignerResponse{}, nil
	}

	if h.onLoadSigner == nil {
		return &arkv1.LoadSignerResponse{}, nil
	}

	addr := req.GetAddress()
	if err := h.onLoadSigner(addr); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	log.Debugf("signer url set to %s", addr)

	return &arkv1.LoadSignerResponse{}, nil
}
