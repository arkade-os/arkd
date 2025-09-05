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
	signerUrl := req.GetSignerUrl()
	signerPrvkey := req.GetSignerPrivateKey()
	if signerUrl == "" && signerPrvkey == "" {
		return nil, status.Error(codes.InvalidArgument, "missing address or private key")
	}
	if signerUrl != "" && signerPrvkey != "" {
		return nil, status.Error(
			codes.InvalidArgument, "address and private key are mutually exclusive",
		)
	}

	if signerPrvkey != "" {
		if err := h.walletSvc.LoadSignerKey(ctx, signerPrvkey); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return &arkv1.LoadSignerResponse{}, nil
	}

	if h.onLoadSigner == nil {
		return &arkv1.LoadSignerResponse{}, nil
	}

	if err := h.onLoadSigner(signerUrl); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	log.Debugf("signer url set to %s", signerUrl)

	return &arkv1.LoadSignerResponse{}, nil
}
