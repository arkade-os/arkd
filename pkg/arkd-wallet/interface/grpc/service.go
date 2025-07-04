package grpcservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	arkwalletv1 "github.com/arkade-os/api-spec/protobuf/gen/arkwallet/v1"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/config"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/interface/grpc/handlers"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/interface/grpc/interceptors"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protojson"
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
		interceptors.UnaryInterceptor(),
		interceptors.StreamInterceptor(),
	)

	walletHandler := handlers.NewWalletServiceHandler(s.cfg.WalletSvc)
	arkwalletv1.RegisterWalletServiceServer(grpcSrv, walletHandler)

	healthHandler := handlers.NewHealthHandler()
	grpchealth.RegisterHealthServer(grpcSrv, healthHandler)

	gatewayCreds := insecure.NewCredentials()
	gatewayOpts := grpc.WithTransportCredentials(gatewayCreds)
	conn, err := grpc.NewClient(
		gatewayAddress(s.cfg.Port), gatewayOpts,
	)
	if err != nil {
		return fmt.Errorf("failed to connect wallet grpc-gateway: %w", err)
	}

	gwmux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(grpchealth.NewHealthClient(conn)),
		runtime.WithMarshalerOption("application/json+pretty", &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				Indent:    "  ",
				Multiline: true,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		}),
	)

	if err := arkwalletv1.RegisterWalletServiceHandler(
		context.Background(), gwmux, conn,
	); err != nil {
		return err
	}

	grpcGateway := http.Handler(gwmux)
	handler := router(grpcSrv, grpcGateway)
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	httpServerHandler := h2c.NewHandler(http.Handler(mux), &http2.Server{})

	s.server = &http.Server{
		Addr:    address(s.cfg.Port),
		Handler: httpServerHandler,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("failed to start server: %v", err))
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
	return fmt.Sprintf("localhost:%d", port)
}
