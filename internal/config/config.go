package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/ports"
	alertsmanager "github.com/arkade-os/arkd/internal/infrastructure/alertsmanager"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	inmemorylivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/inmemory"
	redislivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/redis"
	blockscheduler "github.com/arkade-os/arkd/internal/infrastructure/scheduler/block"
	timescheduler "github.com/arkade-os/arkd/internal/infrastructure/scheduler/gocron"
	signerclient "github.com/arkade-os/arkd/internal/infrastructure/signer"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	bitcointxdecoder "github.com/arkade-os/arkd/internal/infrastructure/tx-decoder/bitcoin"
	envunlocker "github.com/arkade-os/arkd/internal/infrastructure/unlocker/env"
	fileunlocker "github.com/arkade-os/arkd/internal/infrastructure/unlocker/file"
	walletclient "github.com/arkade-os/arkd/internal/infrastructure/wallet"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const minAllowedSequence = 512

var (
	supportedEventDbs = supportedType{
		"badger":   {},
		"postgres": {},
	}
	supportedDbs = supportedType{
		"badger":   {},
		"sqlite":   {},
		"postgres": {},
	}
	supportedSchedulers = supportedType{
		"gocron": {},
		"block":  {},
	}
	supportedTxBuilders = supportedType{
		"covenantless": {},
	}
	supportedUnlockers = supportedType{
		"env":  {},
		"file": {},
	}
	supportedLiveStores = supportedType{
		"inmemory": {},
		"redis":    {},
	}
)

type Config struct {
	Datadir         string
	Port            uint32
	AdminPort       uint32
	DbMigrationPath string
	NoTLS           bool
	NoMacaroons     bool
	LogLevel        int
	TLSExtraIPs     []string
	TLSExtraDomains []string

	DbType                    string
	EventDbType               string
	DbDir                     string
	DbUrl                     string
	EventDbUrl                string
	EventDbDir                string
	SessionDuration           int64
	BanDuration               int64
	BanThreshold              int64 // number of crimes to trigger a ban
	SchedulerType             string
	TxBuilderType             string
	LiveStoreType             string
	RedisUrl                  string
	RedisTxNumOfRetries       int
	WalletAddr                string
	SignerAddr                string
	VtxoTreeExpiry            arklib.RelativeLocktime
	UnilateralExitDelay       arklib.RelativeLocktime
	PublicUnilateralExitDelay arklib.RelativeLocktime
	CheckpointExitDelay       arklib.RelativeLocktime
	BoardingExitDelay         arklib.RelativeLocktime
	NoteUriPrefix             string
	AllowCSVBlockType         bool
	HeartbeatInterval         int64

	VtxoNoCsvValidationCutoffDate int64

	ScheduledSessionStartTime                 int64
	ScheduledSessionEndTime                   int64
	ScheduledSessionPeriod                    int64
	ScheduledSessionDuration                  int64
	ScheduledSessionMinRoundParticipantsCount int64
	ScheduledSessionMaxRoundParticipantsCount int64
	OtelCollectorEndpoint                     string
	OtelPushInterval                          int64
	PyroscopeServerURL                        string
	RoundReportServiceEnabled                 bool

	EsploraURL      string
	AlertManagerURL string

	UnlockerType     string
	UnlockerFilePath string // file unlocker
	UnlockerPassword string // env unlocker

	RoundMinParticipantsCount int64
	RoundMaxParticipantsCount int64
	UtxoMaxAmount             int64
	UtxoMinAmount             int64
	VtxoMaxAmount             int64
	VtxoMinAmount             int64
	SettlementMinExpiryGap    int64

	OnchainOutputFee int64
	EnablePprof      bool

	repo           ports.RepoManager
	svc            application.Service
	adminSvc       application.AdminService
	wallet         ports.WalletService
	signer         ports.SignerService
	txBuilder      ports.TxBuilder
	scanner        ports.BlockchainScanner
	scheduler      ports.SchedulerService
	unlocker       ports.Unlocker
	liveStore      ports.LiveStore
	network        *arklib.Network
	roundReportSvc application.RoundReportService
	alerts         ports.Alerts
}

func (c *Config) String() string {
	clone := *c
	if clone.UnlockerPassword != "" {
		clone.UnlockerPassword = "••••••"
	}
	json, err := json.MarshalIndent(clone, "", "  ")
	if err != nil {
		return fmt.Sprintf("error while marshalling config JSON: %s", err)
	}
	return string(json)
}

var (
	defaultDatadir             = arklib.AppDataDir("arkd", false)
	defaultSessionDuration     = 30
	defaultBanDuration         = 10 * defaultSessionDuration
	defaultBanThreshold        = 3
	DefaultPort                = 7070
	DefaultAdminPort           = 7071
	defaultDbType              = "postgres"
	defaultEventDbType         = "postgres"
	defaultSchedulerType       = "gocron"
	defaultTxBuilderType       = "covenantless"
	defaultLiveStoreType       = "redis"
	defaultRedisTxNumOfRetries = 10
	defaultEsploraURL          = "https://blockstream.info/api"
	defaultLogLevel            = 4
	defaultVtxoTreeExpiry      = 604672  // 7 days
	defaultUnilateralExitDelay = 86400   // 24 hours
	defaultCheckpointExitDelay = 86400   // 24 hours
	defaultBoardingExitDelay   = 7776000 // 3 months
	defaultNoMacaroons         = false
	defaultNoTLS               = true
	defaultUtxoMaxAmount       = -1 // -1 means no limit (default), 0 means boarding not allowed
	defaultUtxoMinAmount       = -1 // -1 means native dust limit (default)
	defaultVtxoMinAmount       = -1 // -1 means native dust limit (default)
	defaultVtxoMaxAmount       = -1 // -1 means no limit (default)
	defaultAllowCSVBlockType   = false

	defaultRoundMaxParticipantsCount     = 128
	defaultRoundMinParticipantsCount     = 1
	defaultOtelPushInterval              = 10 // seconds
	defaultHeartbeatInterval             = 60 // seconds
	defaultRoundReportServiceEnabled     = false
	defaultSettlementMinExpiryGap        = 0 // disabled by default
	defaultVtxoNoCsvValidationCutoffDate = 0 // disabled by default
	defaultOnchainOutputFee              = 0 // no fee by default
	defaultEnablePprof                   = false
)

// env returns a list of strings prefixed with `ARKD_`.
// This is used as a syntax sugar for defining env vars.
func env(values ...string) []string {
	envs := make([]string, len(values))

	for i, value := range values {
		envs[i] = fmt.Sprintf("ARKD_%s", value)
	}

	return envs
}

var (
	Datadir = &cli.StringFlag{
		Usage: "Directory to store data",
		Name:  "datadir", EnvVars: env("DATADIR"),
		Value: defaultDatadir,
	}

	Port = &cli.UintFlag{
		Usage: "Port (public) to listen on",
		Name:  "port", EnvVars: env("PORT"),
		Value: uint(DefaultPort),
	}

	AdminPort = &cli.UintFlag{
		Usage: "Admin port (private) to listen on, fallback to service port if 0",
		Name:  "admin-port", EnvVars: env("ADMIN_PORT"),
		Value: uint(DefaultAdminPort),
	}

	LogLevel = &cli.IntFlag{
		Usage: "Logging level (0-6, where 6 is trace)",
		Name:  "log-level", EnvVars: env("LOG_LEVEL"),
		Value: defaultLogLevel,
	}

	SessionDuration = &cli.Int64Flag{
		Usage: "How long a batch session lasts (in seconds) before timing out once it started",
		Name:  "session-duration", EnvVars: env("SESSION_DURATION"),
		Value: int64(defaultSessionDuration),
	}

	DbType = &cli.StringFlag{
		Usage: "Database type (postgres, sqlite, badger)",
		Name:  "db-type", EnvVars: env("DB_TYPE"),
		Value: defaultDbType,
	}

	DbUrl = &cli.StringFlag{
		Usage: "Postgres connection url if ARKD_DB_TYPE is set to postgres",
		Name:  "pg-db-url", EnvVars: env("PG_DB_URL"),
	}

	EventDbType = &cli.StringFlag{
		Usage: "Event database type (postgres, badger)",
		Name:  "event-db-type", EnvVars: env("EVENT_DB_TYPE"),
		Value: defaultEventDbType,
	}

	EventDbUrl = &cli.StringFlag{
		Usage: "Postgres connection url if ARKD_EVENT_DB_TYPE is set to postgres",
		Name:  "pg-event-db-url", EnvVars: env("PG_EVENT_DB_URL"),
	}

	TxBuilderType = &cli.StringFlag{
		Usage: "Transaction builder type",
		Name:  "tx-builder-type", EnvVars: env("TX_BUILDER_TYPE"),
		Value: defaultTxBuilderType,
	}

	LiveStoreType = &cli.StringFlag{
		Usage: "Cache service type (redis, inmemory)",
		Name:  "live-store-type", EnvVars: env("LIVE_STORE_TYPE"),
		Value: defaultLiveStoreType,
	}

	RedisUrl = &cli.StringFlag{
		Usage: "Redis db connection url if ARKD_LIVE_STORE_TYPE is set to redis",
		Name:  "redis-url", EnvVars: env("REDIS_URL"),
	}

	RedisTxNumOfRetries = &cli.IntFlag{
		Usage: "Maximum number of retries for Redis write operations in case of conflicts",
		Name:  "redis-num-of-retries", EnvVars: env("REDIS_NUM_OF_RETRIES"),
		Value: defaultRedisTxNumOfRetries,
	}

	// TODO: Make this a cli.DurationFlag.
	VtxoTreeExpiry = &cli.IntFlag{
		Usage: "VTXO tree expiry in seconds",
		Name:  "vtxo-tree-expiry", EnvVars: env("VTXO_TREE_EXPIRY"),
		Value: defaultVtxoTreeExpiry,

		// We could just print 7 days, but it's best to let time.Duration to format it in case we
		// update the value.
		DefaultText: fmt.Sprintf("%d (~%0.f days)", defaultVtxoTreeExpiry,
			(time.Duration(defaultVtxoTreeExpiry)*time.Second).Hours()/24),
	}

	// TODO: Make this a cli.DurationFlag.
	UnilateralExitDelay = &cli.IntFlag{
		Usage: "Unilateral exit delay in seconds",
		Name:  "unilateral-exit-delay", EnvVars: env("UNILATERAL_EXIT_DELAY"),
		Value: defaultUnilateralExitDelay,

		// We could just print 24 hours, but it's best to let time.Duration to format it in case we
		// update the value.
		DefaultText: fmt.Sprintf("%d (~%0.f hours)", defaultUnilateralExitDelay,
			(time.Duration(defaultUnilateralExitDelay) * time.Second).Hours()),
	}

	// TODO: Make this a cli.DurationFlag.
	// TODO: Not documented in README.
	PublicUnilateralExitDelay = &cli.IntFlag{
		Usage: "Public unilateral exit delay in seconds",
		Name:  "public-unilateral-exit-delay", EnvVars: env("PUBLIC_UNILATERAL_EXIT_DELAY"),
		Value: defaultUnilateralExitDelay,

		// We could just print 24 hours, but it's best to let time.Duration to format it in case we
		// update the value.
		DefaultText: fmt.Sprintf("%d (~%0.f hours)", defaultUnilateralExitDelay,
			(time.Duration(defaultUnilateralExitDelay) * time.Second).Hours()),
	}

	// TODO: Make this a cli.DurationFlag.
	BoardingExitDelay = &cli.IntFlag{
		Usage: "Boarding exit delay in seconds",
		Name:  "boarding-exit-delay", EnvVars: env("BOARDING_EXIT_DELAY"),
		Value: defaultBoardingExitDelay,

		DefaultText: fmt.Sprintf("%d (~%0.f months)", defaultBoardingExitDelay,
			(time.Duration(defaultBoardingExitDelay)*time.Second).Hours()/24/30),
	}

	EsploraURL = &cli.StringFlag{
		Usage: "Esplora API URL",
		Name:  "esplora-url", EnvVars: env("ESPLORA_URL"),
		Value: defaultEsploraURL,
	}

	WalletAddr = &cli.StringFlag{
		Usage: "The arkd wallet address to connect to in the form host:port",
		Name:  "wallet-addr", EnvVars: env("WALLET_ADDR"),
	}

	SignerAddr = &cli.StringFlag{
		Usage: "The signer address to connect to in the form host:port",
		Name:  "signer-addr", EnvVars: env("SIGNER_ADDR"),
		DefaultText: "value of `ARKD_WALLET_ADDR`",
	}

	NoMacaroons = &cli.BoolFlag{
		Usage: "Disable Macaroons authentication",
		Name:  "no-macaroons", EnvVars: env("NO_MACAROONS"),
		Value: defaultNoMacaroons,
	}

	NoTLS = &cli.BoolFlag{
		Usage: "Disable TLS",
		Name:  "no-tls", EnvVars: env("NO_TLS"),
		Value: defaultNoTLS,
	}

	UnlockerType = &cli.StringFlag{
		Usage: "Wallet unlocker type (env, file) to enable auto-unlock",
		Name:  "unlocker-type", EnvVars: env("UNLOCKER_TYPE"),
	}

	UnlockerFilePath = &cli.StringFlag{
		Usage: "Path to unlocker file",
		Name:  "unlocker-file-path", EnvVars: env("UNLOCKER_FILE_PATH"),
	}

	UnlockerPassword = &cli.StringFlag{
		Usage: "Wallet unlocker password",
		Name:  "unlocker-password", EnvVars: env("UNLOCKER_PASSWORD"),
	}

	RoundMaxParticipantsCount = &cli.IntFlag{
		Usage: "Maximum number of participants per round",
		Name:  "round-max-participants-count", EnvVars: env("ROUND_MAX_PARTICIPANTS_COUNT"),
		Value: defaultRoundMaxParticipantsCount,
	}

	RoundMinParticipantsCount = &cli.IntFlag{
		Usage: "Minimum number of participants per round",
		Name:  "round-min-participants-count", EnvVars: env("ROUND_MIN_PARTICIPANTS_COUNT"),
		Value: defaultRoundMinParticipantsCount,
	}

	UtxoMaxAmount = &cli.IntFlag{
		Usage: "The maximum allowed amount for boarding or collaborative exit",
		Name:  "utxo-max-amount", EnvVars: env("UTXO_MAX_AMOUNT"),
		Value:       defaultUtxoMaxAmount,
		DefaultText: "-1 unset",
	}

	UtxoMinAmount = &cli.IntFlag{
		Usage: "The minimum allowed amount for boarding or collaborative exit",
		Name:  "utxo-min-amount", EnvVars: env("UTXO_MIN_AMOUNT"),
		Value:       defaultUtxoMinAmount,
		DefaultText: "-1 dust",
	}

	VtxoMaxAmount = &cli.IntFlag{
		Usage: "The maximum allowed amount for vtxos",
		Name:  "vtxo-max-amount", EnvVars: env("VTXO_MAX_AMOUNT"),
		Value:       defaultVtxoMaxAmount,
		DefaultText: "-1 unset",
	}

	VtxoMinAmount = &cli.IntFlag{
		Usage: "The minimum allowed amount for vtxos",
		Name:  "vtxo-min-amount", EnvVars: env("VTXO_MIN_AMOUNT"),
		Value:       defaultVtxoMinAmount,
		DefaultText: "-1 dust",
	}

	// TODO: Make this a cli.DurationFlag.
	BanDuration = &cli.Int64Flag{
		Usage: "Ban duration in seconds",
		Name:  "ban-duration", EnvVars: env("BAN_DURATION"),
		Value: int64(defaultBanDuration),
	}

	BanThreshold = &cli.Int64Flag{
		Usage: "Number of crimes to trigger a ban",
		Name:  "ban-threshold", EnvVars: env("BAN_THRESHOLD"),
		Value: int64(defaultBanThreshold),
	}

	SchedulerType = &cli.StringFlag{
		Usage: "Scheduler type (gocron, block)",
		Name:  "scheduler-type", EnvVars: env("SCHEDULER_TYPE"),
		Value: defaultSchedulerType,
	}

	// TODO: Make this a cli.DurationFlag.
	CheckpointExitDelay = &cli.IntFlag{
		Usage: "Checkpoint exit delay in seconds",
		Name:  "checkpoint-exit-delay", EnvVars: env("CHECKPOINT_EXIT_DELAY"),
		Value: defaultCheckpointExitDelay,
	}

	TLSExtraIP = &cli.StringSliceFlag{
		Usage: "Extra IP addresses for TLS (comma-separated)",
		Name:  "tls-extra-ip", EnvVars: env("TLS_EXTRA_IP"),
	}

	TLSExtraDomain = &cli.StringSliceFlag{
		Usage: "Extra domains for TLS (comma-separated)",
		Name:  "tls-extra-domain", EnvVars: env("TLS_EXTRA_DOMAIN"),
	}

	NoteUriPrefix = &cli.StringFlag{
		Usage: "Note URI prefix",
		Name:  "note-uri-prefix", EnvVars: env("NOTE_URI_PREFIX"),
	}

	// TODO: Make this a cli.TimestampFlag.
	ScheduledSessionStartTime = &cli.IntFlag{
		Usage: "Scheduled session start time (Unix timestamp)",
		Name:  "scheduled-session-start-time", EnvVars: env("SCHEDULED_SESSION_START_TIME"),
	}

	// TODO: Make this a cli.TimestampFlag.
	ScheduledSessionEndTime = &cli.IntFlag{
		Usage: "Scheduled session end time (Unix timestamp)",
		Name:  "scheduled-session-end-time", EnvVars: env("SCHEDULED_SESSION_END_TIME"),
	}

	// TODO: Make this a cli.DurationFlag.
	ScheduledSessionPeriod = &cli.IntFlag{
		Usage: "Scheduled session period in minutes",
		Name:  "scheduled-session-period", EnvVars: env("SCHEDULED_SESSION_PERIOD"),
	}

	// TODO: Make this a cli.DurationFlag.
	ScheduledSessionDuration = &cli.IntFlag{
		Usage: "Scheduled session duration in seconds",
		Name:  "scheduled-session-duration", EnvVars: env("SCHEDULED_SESSION_DURATION"),
	}

	ScheduledSessionMinRoundParticipantsCount = &cli.Int64Flag{
		Usage:   "Min participants for scheduled sessions",
		Name:    "scheduled-session-min-round-participants-count",
		EnvVars: env("SCHEDULED_SESSION_MIN_ROUND_PARTICIPANTS_COUNT"),
	}

	ScheduledSessionMaxRoundParticipantsCount = &cli.Int64Flag{
		Usage:   "Max participants for scheduled sessions",
		Name:    "scheduled-session-max-round-participants-count",
		EnvVars: env("SCHEDULED_SESSION_MAX_ROUND_PARTICIPANTS_COUNT"),
	}

	OtelCollectorEndpoint = &cli.StringFlag{
		Usage: "OpenTelemetry collector endpoint",
		Name:  "collector-endpoint", EnvVars: env("COLLECTOR_ENDPOINT"),
	}

	OtelPushInterval = &cli.IntFlag{
		Usage: "OpenTelemetry push interval in seconds",
		Name:  "otel-push-interval", EnvVars: env("OTEL_PUSH_INTERVAL"),
		Value: defaultOtelPushInterval,
	}

	AllowCSVBlockType = &cli.BoolFlag{
		Usage: "Allow CSV block type",
		Name:  "allow-csv-block-type", EnvVars: env("ALLOW_CSV_BLOCK_TYPE"),
		Value: defaultAllowCSVBlockType,
	}

	HeartbeatInterval = &cli.IntFlag{
		Usage: "Heartbeat interval in seconds",
		Name:  "heartbeat-interval", EnvVars: env("HEARTBEAT_INTERVAL"),
		Value: defaultHeartbeatInterval,
	}

	RoundReportServiceEnabled = &cli.BoolFlag{
		Usage: "Enable round report service",
		Name:  "round-report-enabled", EnvVars: env("ROUND_REPORT_ENABLED"),
		Value: defaultRoundReportServiceEnabled,
	}

	// TODO: The following are not documented on README so I left `Usage: ""` on purpose.
	SettlementMinExpiryGap = &cli.IntFlag{
		Usage: "",
		Name:  "settlement-min-expiry-gap", EnvVars: env("SETTLEMENT_MIN_EXPIRY_GAP"),
		Value:       defaultSettlementMinExpiryGap,
		DefaultText: "0 disabled",
	}

	VtxoNoCsvValidationCutoffDate = &cli.IntFlag{
		Usage: "",
		Name:  "vtxo-no-csv-validation-cutoff-date", EnvVars: env("VTXO_NO_CSV_VALIDATION_CUTOFF_DATE"),
		Value:       defaultVtxoNoCsvValidationCutoffDate,
		DefaultText: "0 disabled",
	}

	OnchainOutputFee = &cli.IntFlag{
		Usage: "",
		Name:  "onchain-output-fee", EnvVars: env("ONCHAIN_OUTPUT_FEE"),
		Value: defaultOnchainOutputFee,
	}

	AlertManagerURL = &cli.StringFlag{
		Usage: "",
		Name:  "alert-manager-url", EnvVars: env("ALERT_MANAGER_URL"),
	}

	PyroscopeServerURL = &cli.StringFlag{
		Usage: "",
		Name:  "pyroscope-server-url", EnvVars: env("PYROSCOPE_SERVER_URL"),
	}

	EnablePprof = &cli.BoolFlag{
		Usage: "",
		Name:  "enable-pprof", EnvVars: env("ENABLE_PPROF"),
		Value: defaultEnablePprof,
	}
)

var Flags = []cli.Flag{
	Datadir,
	Port,
	AdminPort,
	LogLevel,
	SessionDuration,
	DbType,
	DbUrl,
	EventDbType,
	EventDbUrl,
	TxBuilderType,
	LiveStoreType,
	RedisUrl,
	RedisTxNumOfRetries,
	VtxoTreeExpiry,
	UnilateralExitDelay,
	PublicUnilateralExitDelay,
	BoardingExitDelay,
	EsploraURL,
	WalletAddr,
	SignerAddr,
	NoMacaroons,
	NoTLS,
	UnlockerType,
	UnlockerFilePath,
	UnlockerPassword,
	RoundMaxParticipantsCount,
	RoundMinParticipantsCount,
	UtxoMaxAmount,
	UtxoMinAmount,
	VtxoMaxAmount,
	VtxoMinAmount,
	BanDuration,
	BanThreshold,
	SchedulerType,
	CheckpointExitDelay,
	TLSExtraIP,
	TLSExtraDomain,
	NoteUriPrefix,
	ScheduledSessionStartTime,
	ScheduledSessionEndTime,
	ScheduledSessionPeriod,
	ScheduledSessionDuration,
	ScheduledSessionMinRoundParticipantsCount,
	ScheduledSessionMaxRoundParticipantsCount,
	OtelCollectorEndpoint,
	OtelPushInterval,
	AllowCSVBlockType,
	HeartbeatInterval,
	RoundReportServiceEnabled,
	SettlementMinExpiryGap,
	VtxoNoCsvValidationCutoffDate,
	OnchainOutputFee,
	AlertManagerURL,
	PyroscopeServerURL,
	EnablePprof,
}

func LoadConfig(c *cli.Context) (*Config, error) {
	if err := initDatadir(c); err != nil {
		return nil, fmt.Errorf("failed to create datadir: %s", err)
	}

	dbPath := filepath.Join(c.String(Datadir.Name), "db")

	var eventDbUrl string
	if c.String(EventDbType.Name) == "postgres" {
		eventDbUrl = c.String(EventDbUrl.Name)
		if eventDbUrl == "" {
			return nil, fmt.Errorf("event db type set to 'postgres' but event db url is missing")
		}
	}

	var dbUrl string
	if c.String(DbType.Name) == "postgres" {
		dbUrl = c.String(DbUrl.Name)
		if dbUrl == "" {
			return nil, fmt.Errorf("db type set to 'postgres' but db url is missing")
		}
	}

	var redisUrl string
	if c.String(LiveStoreType.Name) == "redis" {
		redisUrl = c.String(RedisUrl.Name)
		if redisUrl == "" {
			return nil, fmt.Errorf("live store type set to 'redis' but redis url is missing")
		}
	}

	allowCSVBlockType := c.Bool(AllowCSVBlockType.Name)
	if c.String(SchedulerType.Name) == "block" {
		allowCSVBlockType = true
	}

	signerAddr := c.String(SignerAddr.Name)
	if signerAddr == "" {
		signerAddr = c.String(WalletAddr.Name)
	}

	// In case the admin port is unset, fallback to service port.
	adminPort := c.Uint(AdminPort.Name)
	if adminPort == 0 {
		adminPort = c.Uint(Port.Name)
	}

	return &Config{
		Datadir:                   c.String(Datadir.Name),
		WalletAddr:                c.String(WalletAddr.Name),
		SignerAddr:                signerAddr,
		SessionDuration:           c.Int64(SessionDuration.Name),
		BanDuration:               c.Int64(BanDuration.Name),
		BanThreshold:              c.Int64(BanThreshold.Name),
		Port:                      uint32(c.Uint(Port.Name)),
		AdminPort:                 uint32(adminPort),
		EventDbType:               c.String(EventDbType.Name),
		DbType:                    c.String(DbType.Name),
		SchedulerType:             c.String(SchedulerType.Name),
		TxBuilderType:             c.String(TxBuilderType.Name),
		LiveStoreType:             c.String(LiveStoreType.Name),
		RedisUrl:                  redisUrl,
		RedisTxNumOfRetries:       c.Int(RedisTxNumOfRetries.Name),
		NoTLS:                     c.Bool(NoTLS.Name),
		DbDir:                     dbPath,
		DbUrl:                     dbUrl,
		EventDbDir:                dbPath,
		EventDbUrl:                eventDbUrl,
		LogLevel:                  c.Int(LogLevel.Name),
		VtxoTreeExpiry:            determineLocktimeType(c.Int64(VtxoTreeExpiry.Name)),
		UnilateralExitDelay:       determineLocktimeType(c.Int64(UnilateralExitDelay.Name)),
		PublicUnilateralExitDelay: determineLocktimeType(c.Int64(PublicUnilateralExitDelay.Name)),
		CheckpointExitDelay:       determineLocktimeType(c.Int64(CheckpointExitDelay.Name)),
		BoardingExitDelay:         determineLocktimeType(c.Int64(BoardingExitDelay.Name)),
		EsploraURL:                c.String(EsploraURL.Name),
		AlertManagerURL:           c.String(AlertManagerURL.Name),
		NoMacaroons:               c.Bool(NoMacaroons.Name),
		TLSExtraIPs:               c.StringSlice(TLSExtraIP.Name),
		TLSExtraDomains:           c.StringSlice(TLSExtraDomain.Name),
		UnlockerType:              c.String(UnlockerType.Name),
		UnlockerFilePath:          c.String(UnlockerFilePath.Name),
		UnlockerPassword:          c.String(UnlockerPassword.Name),
		NoteUriPrefix:             c.String(NoteUriPrefix.Name),
		ScheduledSessionStartTime: c.Int64(ScheduledSessionStartTime.Name),
		ScheduledSessionEndTime:   c.Int64(ScheduledSessionEndTime.Name),
		ScheduledSessionPeriod:    c.Int64(ScheduledSessionPeriod.Name),
		ScheduledSessionDuration:  c.Int64(ScheduledSessionDuration.Name),
		ScheduledSessionMinRoundParticipantsCount: c.Int64(
			ScheduledSessionMinRoundParticipantsCount.Name,
		),
		ScheduledSessionMaxRoundParticipantsCount: c.Int64(
			ScheduledSessionMaxRoundParticipantsCount.Name,
		),
		OtelCollectorEndpoint: c.String(OtelCollectorEndpoint.Name),
		OtelPushInterval:      c.Int64(OtelPushInterval.Name),
		PyroscopeServerURL:    c.String(PyroscopeServerURL.Name),
		HeartbeatInterval:     c.Int64(HeartbeatInterval.Name),

		RoundMaxParticipantsCount:     c.Int64(RoundMaxParticipantsCount.Name),
		RoundMinParticipantsCount:     c.Int64(RoundMinParticipantsCount.Name),
		UtxoMaxAmount:                 c.Int64(UtxoMaxAmount.Name),
		UtxoMinAmount:                 c.Int64(UtxoMinAmount.Name),
		VtxoMaxAmount:                 c.Int64(VtxoMaxAmount.Name),
		VtxoMinAmount:                 c.Int64(VtxoMinAmount.Name),
		AllowCSVBlockType:             allowCSVBlockType,
		RoundReportServiceEnabled:     c.Bool(RoundReportServiceEnabled.Name),
		SettlementMinExpiryGap:        c.Int64(SettlementMinExpiryGap.Name),
		VtxoNoCsvValidationCutoffDate: c.Int64(VtxoNoCsvValidationCutoffDate.Name),
		OnchainOutputFee:              c.Int64(OnchainOutputFee.Name),
		EnablePprof:                   c.Bool(EnablePprof.Name),
	}, nil
}

func initDatadir(c *cli.Context) error {
	datadir := c.String(Datadir.Name)
	return makeDirectoryIfNotExists(datadir)
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModeDir|0o755)
	}
	return nil
}

func determineLocktimeType(locktime int64) arklib.RelativeLocktime {
	if locktime >= minAllowedSequence {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: uint32(locktime)}
	}

	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: uint32(locktime)}
}

func (c *Config) Validate() error {
	if !supportedEventDbs.supports(c.EventDbType) {
		return fmt.Errorf(
			"event db type not supported, please select one of: %s",
			supportedEventDbs,
		)
	}
	if !supportedDbs.supports(c.DbType) {
		return fmt.Errorf("db type not supported, please select one of: %s", supportedDbs)
	}
	if !supportedSchedulers.supports(c.SchedulerType) {
		return fmt.Errorf(
			"scheduler type not supported, please select one of: %s",
			supportedSchedulers,
		)
	}
	if !supportedTxBuilders.supports(c.TxBuilderType) {
		return fmt.Errorf(
			"tx builder type not supported, please select one of: %s",
			supportedTxBuilders,
		)
	}
	if len(c.UnlockerType) > 0 && !supportedUnlockers.supports(c.UnlockerType) {
		return fmt.Errorf(
			"unlocker type not supported, please select one of: %s",
			supportedUnlockers,
		)
	}
	if len(c.LiveStoreType) > 0 && !supportedLiveStores.supports(c.LiveStoreType) {
		return fmt.Errorf(
			"live store type not supported, please select one of: %s",
			supportedLiveStores,
		)
	}
	if c.SessionDuration < 2 {
		return fmt.Errorf("invalid session duration, must be at least 2 seconds")
	}
	if c.BanDuration < 1 {
		return fmt.Errorf("invalid ban duration, must be at least 1 second")
	}
	if c.BanThreshold < 1 {
		log.Debugf("autoban is disabled")
	}
	if c.VtxoTreeExpiry.Type == arklib.LocktimeTypeBlock {
		if c.SchedulerType != "block" {
			return fmt.Errorf(
				"scheduler type must be block if vtxo tree expiry is expressed in blocks",
			)
		}
		if !c.AllowCSVBlockType {
			return fmt.Errorf(
				"CSV block type must be allowed if vtxo tree expiry is expressed in blocks",
			)
		}
	} else { // seconds
		if c.SchedulerType != "gocron" {
			return fmt.Errorf(
				"scheduler type must be gocron if vtxo tree expiry is expressed in seconds",
			)
		}

		// vtxo tree expiry must be a multiple of 512 if expressed in seconds
		if c.VtxoTreeExpiry.Value%minAllowedSequence != 0 {
			c.VtxoTreeExpiry.Value -= c.VtxoTreeExpiry.Value % minAllowedSequence
			log.Infof(
				"vtxo tree expiry must be a multiple of %d, rounded to %d",
				minAllowedSequence, c.VtxoTreeExpiry,
			)
		}
	}

	// Make sure the public unilateral exit delay type matches the internal one
	if c.PublicUnilateralExitDelay.Type != c.UnilateralExitDelay.Type {
		return fmt.Errorf(
			"public unilateral exit delay and unilateral exit delay must have the same type",
		)
	}

	if c.UnilateralExitDelay.Type == arklib.LocktimeTypeBlock {
		return fmt.Errorf(
			"invalid unilateral exit delay, must at least %d", minAllowedSequence,
		)
	}

	if c.BoardingExitDelay.Type == arklib.LocktimeTypeBlock {
		return fmt.Errorf(
			"invalid boarding exit delay, must at least %d", minAllowedSequence,
		)
	}

	if c.CheckpointExitDelay.Type == arklib.LocktimeTypeSecond {
		if c.CheckpointExitDelay.Value%minAllowedSequence != 0 {
			c.CheckpointExitDelay.Value -= c.CheckpointExitDelay.Value % minAllowedSequence
			log.Infof(
				"checkpoint exit delay must be a multiple of %d, rounded to %d",
				minAllowedSequence, c.CheckpointExitDelay,
			)
		}
	}

	if c.UnilateralExitDelay.Value%minAllowedSequence != 0 {
		c.UnilateralExitDelay.Value -= c.UnilateralExitDelay.Value % minAllowedSequence
		log.Infof(
			"unilateral exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.UnilateralExitDelay,
		)
	}

	if c.PublicUnilateralExitDelay.Value%minAllowedSequence != 0 {
		c.PublicUnilateralExitDelay.Value -= c.PublicUnilateralExitDelay.Value % minAllowedSequence
		log.Infof(
			"public unilateral exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.PublicUnilateralExitDelay.Value,
		)
	}

	if c.BoardingExitDelay.Value%minAllowedSequence != 0 {
		c.BoardingExitDelay.Value -= c.BoardingExitDelay.Value % minAllowedSequence
		log.Infof(
			"boarding exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.BoardingExitDelay,
		)
	}

	if c.UnilateralExitDelay == c.BoardingExitDelay {
		return fmt.Errorf("unilateral exit delay and boarding exit delay must be different")
	}

	if c.PublicUnilateralExitDelay.Value < c.UnilateralExitDelay.Value {
		return fmt.Errorf(
			"public unilateral exit delay must be greater than or equal to unilateral exit delay",
		)
	}

	if c.VtxoMinAmount == 0 {
		return fmt.Errorf("vtxo min amount must be greater than 0")
	}

	if c.UtxoMinAmount == 0 {
		return fmt.Errorf("utxo min amount must be greater than 0")
	}

	if c.OnchainOutputFee < 0 {
		return fmt.Errorf("onchain output fee must be greater than 0")
	}

	if err := c.repoManager(); err != nil {
		return err
	}
	if err := c.walletService(); err != nil {
		return err
	}
	if err := c.signerService(); err != nil {
		return err
	}
	if err := c.txBuilderService(); err != nil {
		return err
	}
	if err := c.scannerService(); err != nil {
		return err
	}
	if err := c.liveStoreService(); err != nil {
		return err
	}
	if err := c.schedulerService(); err != nil {
		return err
	}
	if err := c.adminService(); err != nil {
		return err
	}
	if err := c.unlockerService(); err != nil {
		return err
	}
	if err := c.alertsService(); err != nil {
		return err
	}
	return nil
}

func (c *Config) AppService() (application.Service, error) {
	if c.svc == nil {
		if err := c.appService(); err != nil {
			return nil, err
		}
	}
	return c.svc, nil
}

func (c *Config) AdminService() application.AdminService {
	return c.adminSvc
}

func (c *Config) WalletService() ports.WalletService {
	return c.wallet
}

func (c *Config) UnlockerService() ports.Unlocker {
	return c.unlocker
}

func (c *Config) IndexerService() application.IndexerService {
	return application.NewIndexerService(c.repo)
}

func (c *Config) SignerService() (ports.SignerService, error) {
	if err := c.signerService(); err != nil {
		return nil, err
	}
	return c.signer, nil
}

func (c *Config) RoundReportService() (application.RoundReportService, error) {
	if c.roundReportSvc == nil {
		if err := c.roundReportService(); err != nil {
			return nil, err
		}
	}
	return c.roundReportSvc, nil
}

func (c *Config) repoManager() error {
	var svc ports.RepoManager
	var err error
	var eventStoreConfig []interface{}
	var dataStoreConfig []interface{}
	logger := log.New()

	switch c.EventDbType {
	case "badger":
		eventStoreConfig = []interface{}{c.EventDbDir, logger}
	case "postgres":
		eventStoreConfig = []interface{}{c.EventDbUrl}
	default:
		return fmt.Errorf("unknown event db type")
	}

	switch c.DbType {
	case "badger":
		dataStoreConfig = []interface{}{c.DbDir, logger}
	case "sqlite":
		dataStoreConfig = []interface{}{c.DbDir}
	case "postgres":
		dataStoreConfig = []interface{}{c.DbUrl}
	default:
		return fmt.Errorf("unknown db type")
	}

	txDecoder := bitcointxdecoder.NewService()

	svc, err = db.NewService(db.ServiceConfig{
		EventStoreType:   c.EventDbType,
		DataStoreType:    c.DbType,
		EventStoreConfig: eventStoreConfig,
		DataStoreConfig:  dataStoreConfig,
	}, txDecoder)
	if err != nil {
		return err
	}

	c.repo = svc
	return nil
}

func (c *Config) walletService() error {
	arkWallet := c.WalletAddr
	if arkWallet == "" {
		return fmt.Errorf("missing ark wallet address")
	}

	walletSvc, network, err := walletclient.New(arkWallet, c.OtelCollectorEndpoint)
	if err != nil {
		return err
	}

	c.wallet = walletSvc
	c.network = network
	return nil
}

func (c *Config) signerService() error {
	signer := c.SignerAddr
	if signer == "" {
		return fmt.Errorf("missing signer address")
	}

	signerSvc, err := signerclient.New(signer, c.OtelCollectorEndpoint)
	if err != nil {
		return err
	}

	c.signer = signerSvc
	return nil
}

func (c *Config) txBuilderService() error {
	var svc ports.TxBuilder
	var err error
	switch c.TxBuilderType {
	case "covenantless":
		svc = txbuilder.NewTxBuilder(
			c.wallet, c.signer, *c.network, c.VtxoTreeExpiry, c.BoardingExitDelay,
		)
	default:
		err = fmt.Errorf("unknown tx builder type")
	}
	if err != nil {
		return err
	}

	c.txBuilder = svc
	return nil
}

func (c *Config) scannerService() error {
	c.scanner = c.wallet
	return nil
}

func (c *Config) liveStoreService() error {
	if c.txBuilder == nil {
		return fmt.Errorf("tx builder not set")
	}

	var liveStoreSvc ports.LiveStore
	var err error
	switch c.LiveStoreType {
	case "inmemory":
		liveStoreSvc = inmemorylivestore.NewLiveStore(c.txBuilder)
	case "redis":
		redisOpts, err := redis.ParseURL(c.RedisUrl)
		if err != nil {
			return fmt.Errorf("invalid REDIS_URL: %w", err)
		}
		rdb := redis.NewClient(redisOpts)
		liveStoreSvc = redislivestore.NewLiveStore(rdb, c.txBuilder, c.RedisTxNumOfRetries)
	default:
		err = fmt.Errorf("unknown liveStore type")
	}

	if err != nil {
		return err
	}

	c.liveStore = liveStoreSvc
	return nil
}

func (c *Config) schedulerService() error {
	var svc ports.SchedulerService
	var err error
	switch c.SchedulerType {
	case "gocron":
		svc = timescheduler.NewScheduler()
	case "block":
		svc, err = blockscheduler.NewScheduler(c.EsploraURL)
	default:
		err = fmt.Errorf("unknown scheduler type")
	}
	if err != nil {
		return err
	}

	c.scheduler = svc
	return nil
}

func (c *Config) appService() error {
	var ssStartTime, ssEndTime time.Time
	var ssPeriod, ssDuration time.Duration

	if c.ScheduledSessionStartTime > 0 {
		ssStartTime = time.Unix(c.ScheduledSessionStartTime, 0)
		ssEndTime = time.Unix(c.ScheduledSessionEndTime, 0)
	}
	if c.ScheduledSessionPeriod > 0 {
		ssPeriod = time.Duration(c.ScheduledSessionPeriod) * time.Minute
	}
	if c.ScheduledSessionDuration > 0 {
		ssDuration = time.Duration(c.ScheduledSessionDuration) * time.Second
	}
	if err := c.signerService(); err != nil {
		return err
	}
	if err := c.txBuilderService(); err != nil {
		return err
	}

	roundReportSvc, err := c.RoundReportService()
	if err != nil {
		return err
	}

	svc, err := application.NewService(
		c.wallet, c.signer, c.repo, c.txBuilder, c.scanner,
		c.scheduler, c.liveStore, roundReportSvc, c.alerts,
		c.VtxoTreeExpiry, c.UnilateralExitDelay, c.PublicUnilateralExitDelay,
		c.BoardingExitDelay, c.CheckpointExitDelay,
		c.SessionDuration, c.RoundMinParticipantsCount, c.RoundMaxParticipantsCount,
		c.UtxoMaxAmount, c.UtxoMinAmount, c.VtxoMaxAmount, c.VtxoMinAmount,
		c.BanDuration, c.BanThreshold,
		*c.network, c.AllowCSVBlockType, c.NoteUriPrefix,
		ssStartTime, ssEndTime, ssPeriod, ssDuration,
		c.ScheduledSessionMinRoundParticipantsCount, c.ScheduledSessionMaxRoundParticipantsCount,
		c.SettlementMinExpiryGap,
		time.Unix(c.VtxoNoCsvValidationCutoffDate, 0),
		c.OnchainOutputFee,
	)
	if err != nil {
		return err
	}

	c.svc = svc
	return nil
}

func (c *Config) adminService() error {
	unit := ports.UnixTime
	if c.VtxoTreeExpiry.Value < minAllowedSequence {
		unit = ports.BlockHeight
	}

	c.adminSvc = application.NewAdminService(
		c.wallet, c.repo, c.txBuilder, c.liveStore, unit,
		c.RoundMinParticipantsCount, c.RoundMaxParticipantsCount,
	)
	return nil
}

func (c *Config) unlockerService() error {
	if len(c.UnlockerType) <= 0 {
		return nil
	}

	var svc ports.Unlocker
	var err error
	switch c.UnlockerType {
	case "file":
		svc, err = fileunlocker.NewService(c.UnlockerFilePath)
	case "env":
		svc, err = envunlocker.NewService(c.UnlockerPassword)
	default:
		err = fmt.Errorf("unknown unlocker type")
	}
	if err != nil {
		return err
	}
	c.unlocker = svc
	return nil
}

func (c *Config) roundReportService() error {
	if !c.RoundReportServiceEnabled {
		return nil
	}

	c.roundReportSvc = application.NewRoundReportService()
	return nil
}

func (c *Config) alertsService() error {
	if c.AlertManagerURL == "" {
		return nil
	}

	c.alerts = alertsmanager.NewService(c.AlertManagerURL, c.EsploraURL)
	return nil
}

type supportedType map[string]struct{}

func (t supportedType) String() string {
	types := make([]string, 0, len(t))
	for tt := range t {
		types = append(types, tt)
	}
	return strings.Join(types, " | ")
}

func (t supportedType) supports(typeStr string) bool {
	_, ok := t[typeStr]
	return ok
}
