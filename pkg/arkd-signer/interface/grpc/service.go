package grpcservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/pkg/arkd-signer/config"
	"github.com/arkade-os/arkd/pkg/arkd-signer/interface/grpc/handlers"
	"github.com/arkade-os/arkd/pkg/arkd-signer/interface/grpc/interceptors"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/pkg/emulator/grpchandler"
	"github.com/meshapi/grpc-api-gateway/gateway"
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
	stopFn  func()
}

func NewService(cfg *config.Config) (*service, error) {
	return &service{
		cfg: cfg,
	}, nil
}

func (s *service) Start() error {
	grpcOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
		interceptors.UnaryInterceptor(),
		interceptors.StreamInterceptor(),
	}
	grpcSrv := grpc.NewServer(grpcOpts...)

	ctx, cancel := context.WithCancel(context.Background())
	signerHandler := handlers.NewSignerHandler(s.cfg.SignerSvc)
	signerv1.RegisterSignerServiceServer(grpcSrv, signerHandler)

	emulatorHandler := grpchandler.New("", s.cfg.EmulatorSvc)
	emulatorv1.RegisterEmulatorServiceServer(grpcSrv, emulatorHandler)

	healthHandler := handlers.NewHealthHandler()
	grpchealth.RegisterHealthServer(grpcSrv, healthHandler)

	gatewayCreds := insecure.NewCredentials()
	gatewayOpts := grpc.WithTransportCredentials(gatewayCreds)
	conn, err := grpc.NewClient(
		gatewayAddress(s.cfg.Port), gatewayOpts,
	)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to connect signer grpc-gateway: %w", err)
	}

	gwmux := gateway.NewServeMux(
		gateway.WithHealthzEndpoint(grpchealth.NewHealthClient(conn)),
	)

	signerv1.RegisterSignerServiceHandler(ctx, gwmux, conn)
	emulatorv1.RegisterEmulatorServiceHandler(ctx, gwmux, conn)

	grpcGateway := http.Handler(gwmux)
	handler := router(grpcSrv, grpcGateway)
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	httpServerHandler := h2c.NewHandler(http.Handler(mux), &http2.Server{})

	s.server = &http.Server{
		Addr:    address(s.cfg.Port),
		Handler: httpServerHandler,
	}
	s.grpcSrv = grpcSrv
	s.stopFn = cancel

	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("failed to start server: %v", err))
		}
	}()
	return nil
}

func (s *service) Stop() {
	if s.stopFn != nil {
		s.stopFn()
	}
	if s.server != nil {
		_ = s.server.Shutdown(context.Background())
	}
	if s.grpcSrv != nil {
		s.grpcSrv.GracefulStop()
	}
}

func router(
	grpcServer *grpc.Server, grpcGateway http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOptionRequest(r) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			return
		}

		if isHttpRequest(r) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

			grpcGateway.ServeHTTP(w, r)
			return
		}
		grpcServer.ServeHTTP(w, r)
	})
}

func isOptionRequest(req *http.Request) bool {
	return req.Method == http.MethodOptions
}

func isHttpRequest(req *http.Request) bool {
	return req.Method == http.MethodGet ||
		strings.Contains(req.Header.Get("Content-Type"), "application/json")
}

func address(port uint32) string {
	return fmt.Sprintf(":%d", port)
}

func gatewayAddress(port uint32) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}
