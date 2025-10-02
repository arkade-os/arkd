package grpcservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/config"
	interfaces "github.com/arkade-os/arkd/internal/interface"
	"github.com/arkade-os/arkd/internal/interface/grpc/handlers"
	"github.com/arkade-os/arkd/internal/interface/grpc/interceptors"
	"github.com/arkade-os/arkd/internal/telemetry"
	"github.com/arkade-os/arkd/pkg/kvdb"
	"github.com/arkade-os/arkd/pkg/macaroons"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	macaroonsLocation = "ark"
	macaroonsDbFile   = "macaroons.db"
	macaroonsFolder   = "macaroons"

	tlsKeyFile  = "key.pem"
	tlsCertFile = "cert.pem"
	tlsFolder   = "tls"
)

type service struct {
	version       string
	config        Config
	appConfig     *config.Config
	server        *http.Server
	adminServer   *http.Server
	grpcServer    *grpc.Server
	adminGrpcSrvr *grpc.Server
	macaroonSvc   *macaroons.Service
	otelShutdown  func(context.Context) error
}

func NewService(
	version string, svcConfig Config, appConfig *config.Config,
) (interfaces.Service, error) {
	if err := svcConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid service config: %s", err)
	}
	if err := appConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid app config: %s", err)
	}

	var macaroonSvc *macaroons.Service
	if !svcConfig.NoMacaroons {
		macaroonDB, err := kvdb.Create(
			kvdb.BoltBackendName,
			filepath.Join(svcConfig.Datadir, macaroonsDbFile),
			true,
			kvdb.DefaultDBTimeout,
		)
		if err != nil {
			return nil, err
		}

		keyStore, err := macaroons.NewRootKeyStorage(macaroonDB)
		if err != nil {
			return nil, err
		}
		svc, err := macaroons.NewService(
			keyStore, macaroonsLocation, false, macaroons.IPLockChecker,
		)
		if err != nil {
			return nil, err
		}
		macaroonSvc = svc
	}

	if !svcConfig.insecure() {
		if err := generateOperatorTLSKeyCert(
			svcConfig.tlsDatadir(), svcConfig.TLSExtraIPs, svcConfig.TLSExtraDomains,
		); err != nil {
			return nil, err
		}
		log.Debugf("generated TLS key pair at path: %s", svcConfig.tlsDatadir())
	}

	return &service{
		version:       version,
		config:        svcConfig,
		appConfig:     appConfig,
		server:        nil,
		adminServer:   nil,
		grpcServer:    nil,
		adminGrpcSrvr: nil,
		macaroonSvc:   macaroonSvc,
		otelShutdown:  nil,
	}, nil
}

func (s *service) Start() error {
	withoutAppSvc := false
	if err := s.start(withoutAppSvc); err != nil {
		return err
	}
	log.Infof("started listening at %s", s.config.address())
	if s.config.hasAdminPort() {
		log.Infof("started admin listening at %s", s.config.adminAddress())
	}

	if s.appConfig.UnlockerService() != nil {
		return s.autoUnlock()
	}
	return nil
}

func (s *service) Stop() {
	withAppSvc := true
	s.stop(withAppSvc)
	if s.otelShutdown != nil {
		if err := s.otelShutdown(context.Background()); err != nil {
			log.Errorf("failed to shutdown otel: %s", err)
		}
	}
	log.Info("shutdown service")
}

func (s *service) start(withAppSvc bool) error {
	tlsConfig, err := s.config.tlsConfig()
	if err != nil {
		return err
	}

	if err := s.newServer(tlsConfig, withAppSvc); err != nil {
		return err
	}

	if withAppSvc {
		appSvc, _ := s.appConfig.AppService()
		if err := appSvc.Start(); err != nil {
			return fmt.Errorf("failed to start app service: %s", err)
		}
		log.Info("started app service")
	}

	// Start main server
	if s.config.insecure() {
		// nolint:all
		go s.server.ListenAndServe()
	} else {
		// nolint:all
		go s.server.ListenAndServeTLS("", "")
	}

	// Start admin server if configured on different port
	if s.adminServer != nil {
		if s.config.insecure() {
			// nolint:all
			go s.adminServer.ListenAndServe()
		} else {
			// nolint:all
			go s.adminServer.ListenAndServeTLS("", "")
		}
	}

	return nil
}

func (s *service) stop(withAppSvc bool) {
	if withAppSvc {
		appSvc, _ := s.appConfig.AppService()
		if appSvc != nil {
			appSvc.Stop()
			log.Info("stopped app service")
		}
		s.grpcServer.Stop()
		if s.adminGrpcSrvr != nil {
			s.adminGrpcSrvr.Stop()
		}
	}
	// nolint
	s.server.Shutdown(context.Background())
	if s.adminServer != nil {
		// nolint
		s.adminServer.Shutdown(context.Background())
	}
}

func (s *service) newServer(tlsConfig *tls.Config, withAppSvc bool) error {
	ctx := context.Background()
	if s.appConfig.OtelCollectorEndpoint != "" {
		pushInteval := time.Duration(s.appConfig.OtelPushInterval) * time.Second
		rrsc, err := s.appConfig.RoundReportService()
		if err != nil {
			return err
		}

		otelShutdown, err := telemetry.InitOtelSDK(
			ctx,
			s.appConfig.OtelCollectorEndpoint,
			pushInteval,
			rrsc,
		)
		if err != nil {
			return err
		}

		s.otelShutdown = otelShutdown
	}

	otelHandler := otelgrpc.NewServerHandler(
		otelgrpc.WithTracerProvider(otel.GetTracerProvider()),
	)

	grpcConfig := []grpc.ServerOption{
		interceptors.UnaryInterceptor(s.macaroonSvc),
		interceptors.StreamInterceptor(s.macaroonSvc),
		grpc.StatsHandler(otelHandler),
	}
	creds := insecure.NewCredentials()
	if !s.config.insecure() {
		creds = credentials.NewTLS(tlsConfig)
	}
	grpcConfig = append(grpcConfig, grpc.Creds(creds))

	// Server grpc.
	grpcServer := grpc.NewServer(grpcConfig...)

	onInit := s.onInit
	onUnlock := s.onUnlock
	onReady := s.onReady
	onLoadSigner := s.onLoadSigner
	if withAppSvc {
		appSvc, err := s.appConfig.AppService()
		if err != nil {
			return err
		}
		appHandler := handlers.NewAppServiceHandler(s.version, appSvc)
		eventsCh := appSvc.GetIndexerTxChannel(ctx)
		subscriptionTimeoutDuration := time.Minute // TODO let to be set via config
		indexerHandler := handlers.NewIndexerService(
			s.appConfig.IndexerService(), eventsCh, subscriptionTimeoutDuration,
		)
		arkv1.RegisterArkServiceServer(grpcServer, appHandler)
		arkv1.RegisterIndexerServiceServer(grpcServer, indexerHandler)
		onInit = nil
		onUnlock = nil
		onReady = nil
		onLoadSigner = nil
	}

	walletSvc := s.appConfig.WalletService()
	adminHandler := handlers.NewAdminHandler(s.appConfig.AdminService(), s.appConfig.NoteUriPrefix)
	walletHandler := handlers.NewWalletHandler(walletSvc)
	walletInitHandler := handlers.NewWalletInitializerHandler(walletSvc, onInit, onUnlock, onReady)
	signerManagerHandler := handlers.NewSignerManagerHandler(walletSvc, onLoadSigner)
	healthHandler := handlers.NewHealthHandler()

	var adminGrpcServer *grpc.Server
	if s.config.hasAdminPort() {
		adminGrpcServer = grpc.NewServer(grpcConfig...)
		arkv1.RegisterAdminServiceServer(adminGrpcServer, adminHandler)
		arkv1.RegisterWalletServiceServer(adminGrpcServer, walletHandler)
		arkv1.RegisterWalletInitializerServiceServer(adminGrpcServer, walletInitHandler)
		arkv1.RegisterSignerManagerServiceServer(adminGrpcServer, signerManagerHandler)
		grpchealth.RegisterHealthServer(adminGrpcServer, healthHandler)
	} else {
		arkv1.RegisterAdminServiceServer(grpcServer, adminHandler)
		arkv1.RegisterWalletServiceServer(grpcServer, walletHandler)
		arkv1.RegisterWalletInitializerServiceServer(grpcServer, walletInitHandler)
		arkv1.RegisterSignerManagerServiceServer(grpcServer, signerManagerHandler)
	}
	grpchealth.RegisterHealthServer(grpcServer, healthHandler)

	// Creds for grpc gateway reverse proxy.
	gatewayCreds := insecure.NewCredentials()
	if !s.config.insecure() {
		gatewayCreds = credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // #nosec
		})
	}
	gatewayOpts := grpc.WithTransportCredentials(gatewayCreds)
	conn, err := grpc.NewClient(
		s.config.gatewayAddress(), gatewayOpts,
	)
	if err != nil {
		return err
	}

	customMatcher := func(key string) (string, bool) {
		switch key {
		case "X-Macaroon":
			return "macaroon", true
		default:
			return key, false
		}
	}
	// Reverse proxy grpc-gateway.
	gwmux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(customMatcher),
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

	if !s.config.hasAdminPort() {
		if err := arkv1.RegisterAdminServiceHandler(ctx, gwmux, conn); err != nil {
			return err
		}
		if err := arkv1.RegisterWalletServiceHandler(ctx, gwmux, conn); err != nil {
			return err
		}
		if err := arkv1.RegisterWalletInitializerServiceHandler(ctx, gwmux, conn); err != nil {
			return err
		}
		if err := arkv1.RegisterSignerManagerServiceHandler(ctx, gwmux, conn); err != nil {
			return err
		}
	}

	// Register public services on main gateway
	if withAppSvc {
		if err := arkv1.RegisterArkServiceHandler(ctx, gwmux, conn); err != nil {
			return err
		}
		if err := arkv1.RegisterIndexerServiceHandler(ctx, gwmux, conn); err != nil {
			return err
		}
	}
	grpcGateway := http.Handler(gwmux)

	handler := router(grpcServer, grpcGateway)
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	httpServerHandler := http.Handler(mux)
	if s.config.insecure() {
		httpServerHandler = h2c.NewHandler(httpServerHandler, &http2.Server{})
	}

	s.grpcServer = grpcServer
	s.server = &http.Server{
		Addr:      s.config.address(),
		Handler:   httpServerHandler,
		TLSConfig: tlsConfig,
	}

	// Create separate admin server if admin port is configured
	if s.config.hasAdminPort() {
		adminConn, err := grpc.NewClient(
			s.config.adminGatewayAddress(), gatewayOpts,
		)
		if err != nil {
			return err
		}

		// Create admin gateway mux
		adminGwmux := runtime.NewServeMux(
			runtime.WithIncomingHeaderMatcher(customMatcher),
			runtime.WithHealthzEndpoint(grpchealth.NewHealthClient(adminConn)),
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

		if err := arkv1.RegisterAdminServiceHandler(ctx, adminGwmux, adminConn); err != nil {
			return err
		}
		if err := arkv1.RegisterWalletServiceHandler(ctx, adminGwmux, adminConn); err != nil {
			return err
		}
		if err := arkv1.RegisterWalletInitializerServiceHandler(ctx, adminGwmux, adminConn); err != nil {
			return err
		}
		if err := arkv1.RegisterSignerManagerServiceHandler(ctx, adminGwmux, adminConn); err != nil {
			return err
		}

		adminGrpcGateway := http.Handler(adminGwmux)
		adminHandler := router(adminGrpcServer, adminGrpcGateway)
		adminMux := http.NewServeMux()
		adminMux.Handle("/", adminHandler)

		adminHttpServerHandler := http.Handler(adminMux)
		if s.config.insecure() {
			adminHttpServerHandler = h2c.NewHandler(adminHttpServerHandler, &http2.Server{})
		}

		s.adminGrpcSrvr = adminGrpcServer
		s.adminServer = &http.Server{
			Addr:      s.config.adminAddress(),
			Handler:   adminHttpServerHandler,
			TLSConfig: tlsConfig,
		}
	}

	return nil
}

func (s *service) onUnlock(password string) {
	if s.config.NoMacaroons {
		return
	}

	pwd := []byte(password)
	datadir := s.config.macaroonsDatadir()
	if err := s.macaroonSvc.CreateUnlock(&pwd); err != nil {
		if err != macaroons.ErrAlreadyUnlocked {
			log.WithError(err).Warn("failed to unlock macaroon store")
		}
	}

	done, err := genMacaroons(
		context.Background(), s.macaroonSvc, datadir,
	)
	if err != nil {
		log.WithError(err).Warn("failed to create macaroons")
	}
	if done {
		log.Debugf("created and stored macaroons at path %s", datadir)
	}
}

func (s *service) onInit(password string) {
	if s.config.NoMacaroons {
		return
	}

	pwd := []byte(password)
	datadir := s.config.macaroonsDatadir()
	if err := s.macaroonSvc.CreateUnlock(&pwd); err != nil {
		log.WithError(err).Warn("failed to initialize macaroon store")
	}
	if _, err := genMacaroons(
		context.Background(), s.macaroonSvc, datadir,
	); err != nil {
		log.WithError(err).Warn("failed to create macaroons")
	}
	log.Debugf("generated macaroons at path %s", datadir)
}

func (s *service) onReady() {
	withoutAppSvc := false
	s.stop(withoutAppSvc)

	withAppSvc := true
	if err := s.start(withAppSvc); err != nil {
		log.WithError(err).Fatal("failed to start service")
		withAppSvc := true
		withoutAppSvc := !withAppSvc
		s.stop(withoutAppSvc)
	}
}

func (s *service) onLoadSigner(addr string) error {
	s.appConfig.SignerAddr = addr
	_, err := s.appConfig.SignerService()
	return err
}

func (s *service) autoUnlock() error {
	ctx := context.Background()
	wallet := s.appConfig.WalletService()

	status, err := wallet.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get wallet status: %s", err)
	}
	if !status.IsInitialized() {
		log.Debug("wallet not initiialized, skipping auto unlock")
		return nil
	}

	password, err := s.appConfig.UnlockerService().GetPassword(ctx)
	if err != nil {
		return fmt.Errorf("failed to get password: %s", err)
	}
	if err := wallet.Unlock(ctx, password); err != nil {
		return fmt.Errorf("failed to auto unlock: %s", err)
	}

	go s.onUnlock(password)

	log.Debug("service auto unlocked")
	return nil
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
