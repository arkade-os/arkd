package grpcservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/pkg/arkd-signer/config"
	"github.com/arkade-os/arkd/pkg/arkd-signer/interface/grpc/handlers"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type service struct {
	cfg     *config.Config
	server  *http.Server
	grpcSrv *grpc.Server
}

func NewService(cfg *config.Config) (*service, error) {
	return &service{
		cfg: cfg,
	}, nil
}

func (s *service) Start() error {
	grpcSrv := grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
		grpc.UnaryInterceptor(unaryLogger),
		grpc.StreamInterceptor(streamLogger),
	)
	signerv1.RegisterSignerServiceServer(grpcSrv, handlers.NewSignerHandler(s.cfg.SignerSvc))
	grpchealth.RegisterHealthServer(grpcSrv, handlers.NewHealthHandler())

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.cfg.Port),
		Handler: h2c.NewHandler(router(grpcSrv), &http2.Server{}),
	}
	s.grpcSrv = grpcSrv

	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.server.Addr, err)
	}

	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Fatal("signer server stopped unexpectedly")
		}
	}()
	return nil
}

func (s *service) Stop() {
	if s.server != nil {
		_ = s.server.Shutdown(context.Background())
	}
	if s.grpcSrv != nil {
		s.grpcSrv.GracefulStop()
	}
}

// router serves gRPC only, plus /healthz for the container healthcheck.
func router(grpcServer http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		grpcServer.ServeHTTP(w, r)
	})
}

func unaryLogger(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	log.Debugf("gRPC method: %s", info.FullMethod)
	return handler(ctx, req)
}

func streamLogger(
	srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	log.Debugf("gRPC method: %s", info.FullMethod)
	return handler(srv, stream)
}
