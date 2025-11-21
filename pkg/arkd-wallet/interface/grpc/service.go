package grpcservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	signerv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/signer/v1"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/config"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/interface/grpc/handlers"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/interface/grpc/interceptors"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/telemetry"
	"github.com/meshapi/grpc-api-gateway/gateway"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type service struct {
	cfg               *config.Config
	server            *http.Server
	grpcSrv           *grpc.Server
	closeFn           func()
	otelShutdown      func(context.Context) error
	pyroscopeShutdown func() error
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

	s.closeFn = func() {
		s.cfg.WalletSvc.Close()
		s.cfg.ScannerSvc.Close()
	}

	if s.cfg.OtelCollectorEndpoint != "" {
		pushInteval := time.Duration(s.cfg.OtelPushInterval) * time.Second
		otelShutdown, err := telemetry.InitOtelSDK(
			context.Background(),
			s.cfg.OtelCollectorEndpoint,
			pushInteval,
		)
		if err != nil {
			return err
		}

		otelHandler := otelgrpc.NewServerHandler(
			otelgrpc.WithTracerProvider(otel.GetTracerProvider()),
		)
		grpcOpts = append(grpcOpts, grpc.StatsHandler(otelHandler))

		if s.cfg.PyroscopeServerURL != "" {
			pyroscopeShutdown, err := telemetry.InitPyroscope(
				s.cfg.PyroscopeServerURL,
			)
			if err != nil {
				log.WithError(err).Warn("failed to initialize pyroscope, continuing without profiling")
			}

			s.pyroscopeShutdown = pyroscopeShutdown
		}

		s.otelShutdown = otelShutdown
	}
	grpcSrv := grpc.NewServer(grpcOpts...)

	walletHandler := handlers.NewWalletServiceHandler(s.cfg.WalletSvc, s.cfg.ScannerSvc)
	arkwalletv1.RegisterWalletServiceServer(grpcSrv, walletHandler)
	signerHandler := handlers.NewSignerHandler(s.cfg.WalletSvc)
	signerv1.RegisterSignerServiceServer(grpcSrv, signerHandler)

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

	gwmux := gateway.NewServeMux(
		gateway.WithHealthzEndpoint(grpchealth.NewHealthClient(conn)),
		// runtime.WithMarshalerOption("application/json+pretty", &runtime.JSONPb{
		// 	MarshalOptions: protojson.MarshalOptions{
		// 		Indent:    "  ",
		// 		Multiline: true,
		// 	},
		// 	UnmarshalOptions: protojson.UnmarshalOptions{
		// 		DiscardUnknown: true,
		// 	},
		// }),
	)

	ctx := context.Background()
	arkwalletv1.RegisterWalletServiceHandler(ctx, gwmux, conn)
	signerv1.RegisterSignerServiceHandler(ctx, gwmux, conn)

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
	if s.pyroscopeShutdown != nil {
		if err := s.pyroscopeShutdown(); err != nil {
			log.Errorf("failed to shutdown pyroscope: %s", err)
		}

		log.Info("shutdown pyroscope")
	}
	if s.otelShutdown != nil {
		if err := s.otelShutdown(context.Background()); err != nil {
			log.Errorf("failed to shutdown otel: %s", err)
		}

		log.Infof("otel shutdown")
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
