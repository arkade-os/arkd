package grpcservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/pprof"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/config"
	interfaces "github.com/arkade-os/arkd/internal/interface"
	"github.com/arkade-os/arkd/internal/interface/grpc/handlers"
	"github.com/arkade-os/arkd/internal/interface/grpc/interceptors"
	"github.com/arkade-os/arkd/internal/telemetry"
	"github.com/arkade-os/arkd/pkg/kvdb"
	"github.com/arkade-os/arkd/pkg/macaroons"
	"github.com/meshapi/grpc-api-gateway/gateway"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
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
	version           string
	config            Config
	appConfig         *config.Config
	server            *http.Server
	adminServer       *http.Server
	grpcServer        *grpc.Server
	adminGrpcSrvr     *grpc.Server
	readinessSvc      *interceptors.ReadinessService
	appSvcStarted     atomic.Bool
	macaroonSvc       *macaroons.Service
	otelShutdown      func(context.Context) error
	pyroscopeShutdown func() error
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
		version:     version,
		config:      svcConfig,
		appConfig:   appConfig,
		macaroonSvc: macaroonSvc,
	}, nil
}

func (s *service) Start() error {
	if err := s.start(); err != nil {
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
	s.stop()
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
	}
	log.Info("shutdown service")
}

func (s *service) start() error {
	tlsConfig, err := s.config.tlsConfig()
	if err != nil {
		return err
	}

	if err := s.newServer(tlsConfig, s.config.EnablePprof); err != nil {
		return err
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

func (s *service) stop() {
	if s.appSvcStarted.CompareAndSwap(true, false) {
		// app service is started, stop it
		appSvc, _ := s.appConfig.AppService()
		if appSvc != nil {
			appSvc.Stop()
		}
		if s.readinessSvc != nil {
			s.readinessSvc.MarkAppServiceStopped()
		}
	}

	// Hard-close HTTP listeners/conns first to avoid mixed HTTP/gRPC window.
	if s.server != nil {
		_ = s.server.Close()
	}
	if s.adminServer != nil {
		_ = s.adminServer.Close()
	}

	// Then close gRPC servers/transports.
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
	if s.adminGrpcSrvr != nil {
		s.adminGrpcSrvr.Stop()
	}
}

func (s *service) startAppServices() error {
	if !s.appSvcStarted.CompareAndSwap(false, true) {
		// app already started, skip
		return nil
	}

	appSvc, err := s.appConfig.AppService()
	if err != nil {
		s.appSvcStarted.Store(false)
		return fmt.Errorf("failed to create app service: %w", err)
	}
	if err := appSvc.Start(); err != nil {
		s.appSvcStarted.Store(false)
		return fmt.Errorf("failed to start app service: %w", err)
	}
	log.Info("started app service")

	if s.readinessSvc != nil {
		s.readinessSvc.MarkAppServiceStarted()
	}

	log.Info("ark and indexer services are now ready")
	return nil
}

func (s *service) newServer(tlsConfig *tls.Config, withPprof bool) error {
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

		if s.appConfig.PyroscopeServerURL != "" {
			pyroscopeShutdown, err := telemetry.InitPyroscope(
				s.appConfig.PyroscopeServerURL,
			)
			if err != nil {
				return err
			}
			s.pyroscopeShutdown = pyroscopeShutdown
		}

		s.otelShutdown = otelShutdown
	}

	otelHandler := otelgrpc.NewServerHandler(
		otelgrpc.WithTracerProvider(otel.GetTracerProvider()),
	)

	s.readinessSvc = interceptors.NewReadinessService(s.appConfig.WalletService())

	grpcConfig := []grpc.ServerOption{
		interceptors.UnaryInterceptor(s.macaroonSvc, s.readinessSvc),
		interceptors.StreamInterceptor(s.macaroonSvc, s.readinessSvc),
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
	appSvc, err := s.appConfig.AppService()
	if err != nil {
		return fmt.Errorf("failed to create app service: %w", err)
	}
	appHandler := handlers.NewAppServiceHandler(s.version, appSvc, s.config.HeartbeatInterval)
	eventsCh := appSvc.GetIndexerTxChannel(ctx)
	subscriptionTimeoutDuration := time.Minute
	indexerSvc, err := s.appConfig.IndexerService()
	if err != nil {
		return fmt.Errorf("failed to create indexer service: %w", err)
	}
	indexerHandler := handlers.NewIndexerService(
		indexerSvc,
		eventsCh,
		subscriptionTimeoutDuration,
		s.config.HeartbeatInterval,
	)
	arkv1.RegisterArkServiceServer(grpcServer, appHandler)
	arkv1.RegisterIndexerServiceServer(grpcServer, indexerHandler)

	walletSvc := s.appConfig.WalletService()
	adminHandler := handlers.NewAdminHandler(
		s.appConfig.AdminService(), s.macaroonSvc,
		s.config.macaroonsDatadir(), s.appConfig.NoteUriPrefix,
	)
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
	gwmux := gateway.NewServeMux(
		gateway.WithIncomingHeaderMatcher(customMatcher),
		gateway.WithHealthzEndpoint(grpchealth.NewHealthClient(conn)),
	)

	if !s.config.hasAdminPort() {
		arkv1.RegisterAdminServiceHandler(ctx, gwmux, conn)
		arkv1.RegisterWalletServiceHandler(ctx, gwmux, conn)
		arkv1.RegisterWalletInitializerServiceHandler(ctx, gwmux, conn)
		arkv1.RegisterSignerManagerServiceHandler(ctx, gwmux, conn)
	}

	// Register public services on main gateway.
	arkv1.RegisterArkServiceHandler(ctx, gwmux, conn)
	arkv1.RegisterIndexerServiceHandler(ctx, gwmux, conn)

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
		adminGwmux := gateway.NewServeMux(
			gateway.WithIncomingHeaderMatcher(customMatcher),
			gateway.WithHealthzEndpoint(grpchealth.NewHealthClient(adminConn)),
		)

		arkv1.RegisterAdminServiceHandler(ctx, adminGwmux, adminConn)
		arkv1.RegisterWalletServiceHandler(ctx, adminGwmux, adminConn)
		arkv1.RegisterWalletInitializerServiceHandler(ctx, adminGwmux, adminConn)
		arkv1.RegisterSignerManagerServiceHandler(ctx, adminGwmux, adminConn)

		adminGrpcGateway := http.Handler(adminGwmux)
		adminHandler := router(adminGrpcServer, adminGrpcGateway)
		adminMux := http.NewServeMux()

		if withPprof {
			adminMux.HandleFunc("/debug/pprof/", pprof.Index)
			adminMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			adminMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			adminMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			adminMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			adminMux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
			adminMux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
			adminMux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
			adminMux.Handle("/debug/pprof/block", pprof.Handler("block"))
			adminMux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
			log.Info("pprof enabled on admin port at /debug/pprof/")
		}

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
	if !s.config.NoMacaroons {
		ctx := context.Background()
		if s.macaroonSvc.IsLocked(ctx) {
			if err := s.appConfig.WalletService().Lock(ctx); err != nil {
				log.WithError(err).Warn("failed to lock wallet and properly setup auth service")
			} else {
				return
			}
		}
	}

	if err := s.startAppServices(); err != nil {
		log.WithError(err).Error("failed to activate app services")
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
		log.Debug("wallet not initialized, skipping auto unlock")
		return nil
	}

	// If the wallet is already unlocked, force the lock to make the very next call to Unlock
	// to take effect and run the onUnlock callback
	if status.IsUnlocked() {
		// nolint
		wallet.Lock(ctx)
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
