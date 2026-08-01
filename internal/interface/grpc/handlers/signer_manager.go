package handlers

import (
	"context"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type signerManagerHandler struct {
	onLoadSigner func(addr string) error
}

func NewSignerManagerHandler(
	onLoadSigner func(addr string) error,
) arkv1.SignerManagerServiceServer {
	return &signerManagerHandler{onLoadSigner}
}

func (h *signerManagerHandler) LoadSigner(
	ctx context.Context, req *arkv1.LoadSignerRequest,
) (*arkv1.LoadSignerResponse, error) {
	// Runtime key injection into arkd-wallet is no longer supported: the operator
	// key now lives in arkd-signer (ARKD_SIGNER_SECRET_KEY). Only repointing arkd
	// at a signer URL is supported.
	if req.GetSignerPrivateKey() != "" {
		return nil, status.Error(
			codes.InvalidArgument,
			"runtime signer key injection is no longer supported; "+
				"configure ARKD_SIGNER_SECRET_KEY on arkd-signer and provide signer_url",
		)
	}

	signerUrl := req.GetSignerUrl()
	if signerUrl == "" {
		return nil, status.Error(codes.InvalidArgument, "missing signer url")
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
