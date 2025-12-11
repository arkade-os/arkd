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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	PostgresAutoCreateDB      bool
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
	Datadir                              = "datadir"
	WalletAddr                           = "wallet-addr"
	SignerAddr                           = "signer-addr"
	SessionDuration                      = "session-duration"
	BanDuration                          = "ban-duration"
	BanThreshold                         = "ban-threshold"
	Port                                 = "port"
	AdminPort                            = "admin-port"
	EventDbType                          = "event-db-type"
	DbType                               = "db-type"
	DbUrl                                = "pg-db-url"
	PostgresAutoCreateDB                 = "pg-db-autocreate"
	EventDbUrl                           = "pg-event-db-url"
	SchedulerType                        = "scheduler-type"
	TxBuilderType                        = "tx-builder-type"
	LiveStoreType                        = "live-store-type"
	RedisUrl                             = "redis-url"
	RedisTxNumOfRetries                  = "redis-num-of-retries"
	LogLevel                             = "log-level"
	VtxoTreeExpiry                       = "vtxo-tree-expiry"
	UnilateralExitDelay                  = "unilateral-exit-delay"
	PublicUnilateralExitDelay            = "public-unilateral-exit-delay"
	CheckpointExitDelay                  = "checkpoint-exit-delay"
	BoardingExitDelay                    = "boarding-exit-delay"
	EsploraURL                           = "esplora-url"
	AlertManagerURL                      = "alert-manager-url"
	NoMacaroons                          = "no-macaroons"
	NoTLS                                = "no-tls"
	TLSExtraIP                           = "tls-extra-ip"
	TLSExtraDomain                       = "tls-extra-domain"
	UnlockerType                         = "unlocker-type"
	UnlockerFilePath                     = "unlocker-file-path"
	UnlockerPassword                     = "unlocker-password"
	NoteUriPrefix                        = "note-uri-prefix"
	ScheduledSessionStartTime            = "scheduled-session-start-time"
	ScheduledSessionEndTime              = "scheduled-session-end-time"
	ScheduledSessionPeriod               = "scheduled-session-period"
	ScheduledSessionDuration             = "scheduled-session-duration"
	ScheduledSessionMinRoundParticipants = "scheduled-session-min-round-participants-count"
	ScheduledSessionMaxRoundParticipants = "scheduled-session-max-round-participants-count"
	OtelCollectorEndpoint                = "otel-collector-endpoint"
	OtelPushInterval                     = "otel-push-interval"
	PyroscopeServerURL                   = "pyroscope-server-url"
	RoundMaxParticipantsCount            = "round-max-participants-count"
	RoundMinParticipantsCount            = "round-min-participants-count"
	UtxoMaxAmount                        = "utxo-max-amount"
	VtxoMaxAmount                        = "vtxo-max-amount"
	UtxoMinAmount                        = "utxo-min-amount"
	VtxoMinAmount                        = "vtxo-min-amount"
	AllowCSVBlockType                    = "allow-csv-block-type"
	HeartbeatInterval                    = "heartbeat-interval"
	RoundReportServiceEnabled            = "round-report-enabled"
	SettlementMinExpiryGap               = "settlement-min-expiry-gap"
	// Skip CSV validation for vtxos created before this date
	VtxoNoCsvValidationCutoffDate = "vtxo-no-csv-validation-cutoff-date"
	OnchainOutputFee              = "onchain-output-fee"
	EnablePprof                   = "enable-pprof"

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

func SetupFlags(cmd *cobra.Command) {
	cmd.Flags().String(Datadir, defaultDatadir, "Directory to store data")
	cmd.Flags().Int(Port, DefaultPort, "Port (public) to listen on")
	cmd.Flags().Int(AdminPort, DefaultAdminPort,
		"Admin port (private) to listen on, fallback to service port if 0")
	cmd.Flags().String(DbType, defaultDbType, "Database type (postgres, sqlite, badger)")
	cmd.Flags().Bool(NoTLS, defaultNoTLS, "Disable TLS")
	cmd.Flags().Int(LogLevel, defaultLogLevel, "Logging level (0-6, where 6 is trace)")
	cmd.Flags().Int64(SessionDuration, int64(defaultSessionDuration),
		"How long a batch session lasts (in seconds) before timing out once it started")
	cmd.Flags().Int64(BanDuration, int64(defaultBanDuration), "Ban duration in seconds")
	cmd.Flags().Int64(BanThreshold, int64(defaultBanThreshold), "Number of crimes to trigger a ban")
	cmd.Flags().Int64(VtxoTreeExpiry, int64(defaultVtxoTreeExpiry), "VTXO tree expiry in seconds")
	cmd.Flags().String(SchedulerType, defaultSchedulerType, "Scheduler type (gocron, block)")
	cmd.Flags().String(EventDbType, defaultEventDbType, "Event database type (postgres, badger)")
	cmd.Flags().String(TxBuilderType, defaultTxBuilderType,
		"Transaction builder type (covenantless)")
	cmd.Flags().Int(UnilateralExitDelay, defaultUnilateralExitDelay,
		"Unilateral exit delay in seconds")
	cmd.Flags().Int(PublicUnilateralExitDelay, defaultUnilateralExitDelay,
		"Public unilateral exit delay in seconds")
	cmd.Flags().Int(CheckpointExitDelay, defaultCheckpointExitDelay,
		"Checkpoint exit delay in seconds")
	cmd.Flags().String(EsploraURL, defaultEsploraURL, "Esplora API URL")
	cmd.Flags().Bool(NoMacaroons, defaultNoMacaroons, "Disable macaroon authentication")
	cmd.Flags().Int(BoardingExitDelay, defaultBoardingExitDelay, "Boarding exit delay in seconds")
	cmd.Flags().Int(RoundMaxParticipantsCount, defaultRoundMaxParticipantsCount,
		"Maximum number of participants per round")
	cmd.Flags().Int(RoundMinParticipantsCount, defaultRoundMinParticipantsCount,
		"Minimum number of participants per round")
	cmd.Flags().Int64(UtxoMaxAmount, int64(defaultUtxoMaxAmount),
		"The maximum allowed amount for boarding or collaborative exit")
	cmd.Flags().Int64(UtxoMinAmount, int64(defaultUtxoMinAmount),
		"The minimum allowed amount for boarding or collaborative exit")
	cmd.Flags().Int64(VtxoMaxAmount, int64(defaultVtxoMaxAmount),
		"The maximum allowed amount for vtxos")
	cmd.Flags().Int64(VtxoMinAmount, int64(defaultVtxoMinAmount),
		"The minimum allowed amount for vtxos")
	cmd.Flags().String(LiveStoreType, defaultLiveStoreType, "Cache service type (redis, inmemory)")
	cmd.Flags().Int(RedisTxNumOfRetries, defaultRedisTxNumOfRetries,
		"Maximum number of retries for Redis write operations in case of conflicts")
	cmd.Flags().Bool(AllowCSVBlockType, defaultAllowCSVBlockType, "Allow CSV block type")
	cmd.Flags().Int64(HeartbeatInterval, int64(defaultHeartbeatInterval),
		"Heartbeat interval in seconds")
	cmd.Flags().Bool(RoundReportServiceEnabled, defaultRoundReportServiceEnabled,
		"Enable round report service")
	cmd.Flags().Int64(SettlementMinExpiryGap, int64(defaultSettlementMinExpiryGap), "")
	cmd.Flags().
		Int64(VtxoNoCsvValidationCutoffDate, int64(defaultVtxoNoCsvValidationCutoffDate), "")
	cmd.Flags().Int64(OnchainOutputFee, int64(defaultOnchainOutputFee), "")
	cmd.Flags().Bool(EnablePprof, defaultEnablePprof, "")

	cmd.Flags().
		String(WalletAddr, "", "The arkd wallet address to connect to in the form host:port")
	cmd.Flags().String(SignerAddr, "", "The signer address to connect to in the form host:port")
	cmd.Flags().String(DbUrl, "", "Postgres connection url if ARKD_DB_TYPE is set to postgres")
	cmd.Flags().
		String(EventDbUrl, "", "Event database url if ARKD_EVENT_DB_TYPE is set to postgres")
	cmd.Flags().Bool(PostgresAutoCreateDB, false,
		"Toggles postgres database creation when it does not exist")
	cmd.Flags().String(RedisUrl, "",
		"Redis db connection url if ARKD_LIVE_STORE_TYPE is set to redis")
	cmd.Flags().String(AlertManagerURL, "", "")
	cmd.Flags().StringSlice(TLSExtraIP, nil, "Extra IP addresses for TLS (comma-separated)")
	cmd.Flags().StringSlice(TLSExtraDomain, nil, "Extra domains for TLS (comma-separated)")
	cmd.Flags().String(UnlockerType, "", "Wallet unlocker type (env, file) to enable auto-unlock")
	cmd.Flags().String(UnlockerFilePath, "", "Path to unlocker file")
	cmd.Flags().String(UnlockerPassword, "", "Wallet unlocker password")
	cmd.Flags().String(NoteUriPrefix, "", "Note URI prefix")
	cmd.Flags().Int64(ScheduledSessionStartTime, 0, "Scheduled session start time (Unix timestamp)")
	cmd.Flags().Int64(ScheduledSessionEndTime, 0, "Scheduled session end time (Unix timestamp)")
	cmd.Flags().Int64(ScheduledSessionPeriod, 0, "Scheduled session period in minutes")
	cmd.Flags().Int64(ScheduledSessionDuration, 0, "Scheduled session duration in seconds")
	cmd.Flags().Int64(ScheduledSessionMinRoundParticipants, 0,
		"Min participants for scheduled sessions")
	cmd.Flags().Int64(ScheduledSessionMaxRoundParticipants, 0,
		"Max participants for scheduled sessions")
	cmd.Flags().String(OtelCollectorEndpoint, "", "OpenTelemetry collector endpoint")
	cmd.Flags().Int64(OtelPushInterval, int64(defaultOtelPushInterval),
		"OpenTelemetry push interval in seconds")
	cmd.Flags().String(PyroscopeServerURL, "", "")
}

func LoadConfig() (*Config, error) {
	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("failed to create datadir: %s", err)
	}

	dbPath := filepath.Join(viper.GetString(Datadir), "db")

	var eventDbUrl string
	if viper.GetString(EventDbType) == "postgres" {
		eventDbUrl = viper.GetString(EventDbUrl)
		if eventDbUrl == "" {
			return nil, fmt.Errorf("event db type set to 'postgres' but event db url is missing")
		}
	}

	var dbUrl string
	if viper.GetString(DbType) == "postgres" {
		dbUrl = viper.GetString(DbUrl)
		if dbUrl == "" {
			return nil, fmt.Errorf("db type set to 'postgres' but db url is missing")
		}
	}

	var redisUrl string
	if viper.GetString(LiveStoreType) == "redis" {
		redisUrl = viper.GetString(RedisUrl)
		if redisUrl == "" {
			return nil, fmt.Errorf("live store type set to 'redis' but redis url is missing")
		}
	}

	allowCSVBlockType := viper.GetBool(AllowCSVBlockType)
	if viper.GetString(SchedulerType) == "block" {
		allowCSVBlockType = true
	}

	signerAddr := viper.GetString(SignerAddr)
	if signerAddr == "" {
		signerAddr = viper.GetString(WalletAddr)
	}

	// In case the admin port is unset, fallback to service port.
	adminPort := viper.GetUint32(AdminPort)
	if adminPort == 0 {
		adminPort = viper.GetUint32(Port)
	}

	return &Config{
		Datadir:                   viper.GetString(Datadir),
		WalletAddr:                viper.GetString(WalletAddr),
		SignerAddr:                signerAddr,
		SessionDuration:           viper.GetInt64(SessionDuration),
		BanDuration:               viper.GetInt64(BanDuration),
		BanThreshold:              viper.GetInt64(BanThreshold),
		Port:                      viper.GetUint32(Port),
		AdminPort:                 adminPort,
		EventDbType:               viper.GetString(EventDbType),
		DbType:                    viper.GetString(DbType),
		SchedulerType:             viper.GetString(SchedulerType),
		TxBuilderType:             viper.GetString(TxBuilderType),
		LiveStoreType:             viper.GetString(LiveStoreType),
		RedisUrl:                  redisUrl,
		RedisTxNumOfRetries:       viper.GetInt(RedisTxNumOfRetries),
		NoTLS:                     viper.GetBool(NoTLS),
		DbDir:                     dbPath,
		DbUrl:                     dbUrl,
		EventDbDir:                dbPath,
		EventDbUrl:                eventDbUrl,
		PostgresAutoCreateDB:      viper.GetBool(PostgresAutoCreateDB),
		LogLevel:                  viper.GetInt(LogLevel),
		VtxoTreeExpiry:            determineLocktimeType(viper.GetInt64(VtxoTreeExpiry)),
		UnilateralExitDelay:       determineLocktimeType(viper.GetInt64(UnilateralExitDelay)),
		PublicUnilateralExitDelay: determineLocktimeType(viper.GetInt64(PublicUnilateralExitDelay)),
		CheckpointExitDelay:       determineLocktimeType(viper.GetInt64(CheckpointExitDelay)),
		BoardingExitDelay:         determineLocktimeType(viper.GetInt64(BoardingExitDelay)),
		EsploraURL:                viper.GetString(EsploraURL),
		AlertManagerURL:           viper.GetString(AlertManagerURL),
		NoMacaroons:               viper.GetBool(NoMacaroons),
		TLSExtraIPs:               viper.GetStringSlice(TLSExtraIP),
		TLSExtraDomains:           viper.GetStringSlice(TLSExtraDomain),
		UnlockerType:              viper.GetString(UnlockerType),
		UnlockerFilePath:          viper.GetString(UnlockerFilePath),
		UnlockerPassword:          viper.GetString(UnlockerPassword),
		NoteUriPrefix:             viper.GetString(NoteUriPrefix),
		ScheduledSessionStartTime: viper.GetInt64(ScheduledSessionStartTime),
		ScheduledSessionEndTime:   viper.GetInt64(ScheduledSessionEndTime),
		ScheduledSessionPeriod:    viper.GetInt64(ScheduledSessionPeriod),
		ScheduledSessionDuration:  viper.GetInt64(ScheduledSessionDuration),
		ScheduledSessionMinRoundParticipantsCount: viper.GetInt64(
			ScheduledSessionMinRoundParticipants,
		),
		ScheduledSessionMaxRoundParticipantsCount: viper.GetInt64(
			ScheduledSessionMaxRoundParticipants,
		),
		OtelCollectorEndpoint: viper.GetString(OtelCollectorEndpoint),
		OtelPushInterval:      viper.GetInt64(OtelPushInterval),
		PyroscopeServerURL:    viper.GetString(PyroscopeServerURL),
		HeartbeatInterval:     viper.GetInt64(HeartbeatInterval),

		RoundMaxParticipantsCount:     viper.GetInt64(RoundMaxParticipantsCount),
		RoundMinParticipantsCount:     viper.GetInt64(RoundMinParticipantsCount),
		UtxoMaxAmount:                 viper.GetInt64(UtxoMaxAmount),
		UtxoMinAmount:                 viper.GetInt64(UtxoMinAmount),
		VtxoMaxAmount:                 viper.GetInt64(VtxoMaxAmount),
		VtxoMinAmount:                 viper.GetInt64(VtxoMinAmount),
		AllowCSVBlockType:             allowCSVBlockType,
		RoundReportServiceEnabled:     viper.GetBool(RoundReportServiceEnabled),
		SettlementMinExpiryGap:        viper.GetInt64(SettlementMinExpiryGap),
		VtxoNoCsvValidationCutoffDate: viper.GetInt64(VtxoNoCsvValidationCutoffDate),
		OnchainOutputFee:              viper.GetInt64(OnchainOutputFee),
		EnablePprof:                   viper.GetBool(EnablePprof),
	}, nil
}

func initDatadir() error {
	datadir := viper.GetString(Datadir)
	return makeDirectoryIfNotExists(datadir)
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModeDir|0755)
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
		eventStoreConfig = []interface{}{c.EventDbUrl, c.PostgresAutoCreateDB}
	default:
		return fmt.Errorf("unknown event db type")
	}

	switch c.DbType {
	case "badger":
		dataStoreConfig = []interface{}{c.DbDir, logger}
	case "sqlite":
		dataStoreConfig = []interface{}{c.DbDir}
	case "postgres":
		dataStoreConfig = []interface{}{c.DbUrl, c.PostgresAutoCreateDB}
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
