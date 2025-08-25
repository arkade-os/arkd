package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	inmemorylivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/inmemory"
	redislivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/redis"
	blockscheduler "github.com/arkade-os/arkd/internal/infrastructure/scheduler/block"
	timescheduler "github.com/arkade-os/arkd/internal/infrastructure/scheduler/gocron"
	txbuilder "github.com/arkade-os/arkd/internal/infrastructure/tx-builder/covenantless"
	bitcointxdecoder "github.com/arkade-os/arkd/internal/infrastructure/tx-decoder/bitcoin"
	envunlocker "github.com/arkade-os/arkd/internal/infrastructure/unlocker/env"
	fileunlocker "github.com/arkade-os/arkd/internal/infrastructure/unlocker/file"
	walletclient "github.com/arkade-os/arkd/internal/infrastructure/wallet"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
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
	DbMigrationPath string
	NoTLS           bool
	NoMacaroons     bool
	LogLevel        int
	TLSExtraIPs     []string
	TLSExtraDomains []string

	DbType              string
	EventDbType         string
	DbDir               string
	DbUrl               string
	EventDbUrl          string
	EventDbDir          string
	RoundInterval       int64
	SchedulerType       string
	TxBuilderType       string
	LiveStoreType       string
	RedisUrl            string
	RedisTxNumOfRetries int
	WalletAddr          string
	VtxoTreeExpiry      arklib.RelativeLocktime
	UnilateralExitDelay arklib.RelativeLocktime
	CheckpointExitDelay arklib.RelativeLocktime
	BoardingExitDelay   arklib.RelativeLocktime
	NoteUriPrefix       string
	AllowCSVBlockType   bool

	MarketHourStartTime     int64
	MarketHourEndTime       int64
	MarketHourPeriod        int64
	MarketHourRoundInterval int64
	OtelCollectorEndpoint   string
	OtelPushInterval        int64

	EsploraURL string

	UnlockerType     string
	UnlockerFilePath string // file unlocker
	UnlockerPassword string // env unlocker

	RoundMinParticipantsCount int64
	RoundMaxParticipantsCount int64
	UtxoMaxAmount             int64
	UtxoMinAmount             int64
	VtxoMaxAmount             int64
	VtxoMinAmount             int64

	repo      ports.RepoManager
	svc       application.Service
	adminSvc  application.AdminService
	wallet    ports.WalletService
	txBuilder ports.TxBuilder
	scanner   ports.BlockchainScanner
	scheduler ports.SchedulerService
	unlocker  ports.Unlocker
	liveStore ports.LiveStore
	network   *arklib.Network
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
	Datadir                   = "DATADIR"
	WalletAddr                = "WALLET_ADDR"
	RoundInterval             = "ROUND_INTERVAL"
	Port                      = "PORT"
	EventDbType               = "EVENT_DB_TYPE"
	DbType                    = "DB_TYPE"
	DbUrl                     = "PG_DB_URL"
	EventDbUrl                = "PG_EVENT_DB_URL"
	SchedulerType             = "SCHEDULER_TYPE"
	TxBuilderType             = "TX_BUILDER_TYPE"
	LiveStoreType             = "LIVE_STORE_TYPE"
	RedisUrl                  = "REDIS_URL"
	RedisTxNumOfRetries       = "REDIS_NUM_OF_RETRIES"
	LogLevel                  = "LOG_LEVEL"
	VtxoTreeExpiry            = "VTXO_TREE_EXPIRY"
	UnilateralExitDelay       = "UNILATERAL_EXIT_DELAY"
	CheckpointExitDelay       = "CHECKPOINT_EXIT_DELAY"
	BoardingExitDelay         = "BOARDING_EXIT_DELAY"
	EsploraURL                = "ESPLORA_URL"
	NoMacaroons               = "NO_MACAROONS"
	NoTLS                     = "NO_TLS"
	TLSExtraIP                = "TLS_EXTRA_IP"
	TLSExtraDomain            = "TLS_EXTRA_DOMAIN"
	UnlockerType              = "UNLOCKER_TYPE"
	UnlockerFilePath          = "UNLOCKER_FILE_PATH"
	UnlockerPassword          = "UNLOCKER_PASSWORD"
	NoteUriPrefix             = "NOTE_URI_PREFIX"
	MarketHourStartTime       = "MARKET_HOUR_START_TIME"
	MarketHourEndTime         = "MARKET_HOUR_END_TIME"
	MarketHourPeriod          = "MARKET_HOUR_PERIOD"
	MarketHourRoundInterval   = "MARKET_HOUR_ROUND_INTERVAL"
	OtelCollectorEndpoint     = "OTEL_COLLECTOR_ENDPOINT"
	OtelPushInterval          = "OTEL_PUSH_INTERVAL"
	RoundMaxParticipantsCount = "ROUND_MAX_PARTICIPANTS_COUNT"
	RoundMinParticipantsCount = "ROUND_MIN_PARTICIPANTS_COUNT"
	UtxoMaxAmount             = "UTXO_MAX_AMOUNT"
	VtxoMaxAmount             = "VTXO_MAX_AMOUNT"
	UtxoMinAmount             = "UTXO_MIN_AMOUNT"
	VtxoMinAmount             = "VTXO_MIN_AMOUNT"
	AllowCSVBlockType         = "ALLOW_CSV_BLOCK_TYPE"

	defaultDatadir             = arklib.AppDataDir("arkd", false)
	defaultRoundInterval       = 30
	DefaultPort                = 7070
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

	defaultRoundMaxParticipantsCount = 128
	defaultRoundMinParticipantsCount = 1
	defaultOtelPushInterval          = 10 // seconds
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARKD")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(Port, DefaultPort)
	viper.SetDefault(DbType, defaultDbType)
	viper.SetDefault(NoTLS, defaultNoTLS)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(RoundInterval, defaultRoundInterval)
	viper.SetDefault(VtxoTreeExpiry, defaultVtxoTreeExpiry)
	viper.SetDefault(SchedulerType, defaultSchedulerType)
	viper.SetDefault(EventDbType, defaultEventDbType)
	viper.SetDefault(TxBuilderType, defaultTxBuilderType)
	viper.SetDefault(UnilateralExitDelay, defaultUnilateralExitDelay)
	viper.SetDefault(CheckpointExitDelay, defaultCheckpointExitDelay)
	viper.SetDefault(EsploraURL, defaultEsploraURL)
	viper.SetDefault(NoMacaroons, defaultNoMacaroons)
	viper.SetDefault(BoardingExitDelay, defaultBoardingExitDelay)
	viper.SetDefault(RoundMaxParticipantsCount, defaultRoundMaxParticipantsCount)
	viper.SetDefault(RoundMinParticipantsCount, defaultRoundMinParticipantsCount)
	viper.SetDefault(UtxoMaxAmount, defaultUtxoMaxAmount)
	viper.SetDefault(UtxoMinAmount, defaultUtxoMinAmount)
	viper.SetDefault(VtxoMaxAmount, defaultVtxoMaxAmount)
	viper.SetDefault(VtxoMinAmount, defaultVtxoMinAmount)
	viper.SetDefault(LiveStoreType, defaultLiveStoreType)
	viper.SetDefault(RedisTxNumOfRetries, defaultRedisTxNumOfRetries)
	viper.SetDefault(AllowCSVBlockType, defaultAllowCSVBlockType)
	viper.SetDefault(OtelPushInterval, defaultOtelPushInterval)

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

	return &Config{
		Datadir:                 viper.GetString(Datadir),
		WalletAddr:              viper.GetString(WalletAddr),
		RoundInterval:           viper.GetInt64(RoundInterval),
		Port:                    viper.GetUint32(Port),
		EventDbType:             viper.GetString(EventDbType),
		DbType:                  viper.GetString(DbType),
		SchedulerType:           viper.GetString(SchedulerType),
		TxBuilderType:           viper.GetString(TxBuilderType),
		LiveStoreType:           viper.GetString(LiveStoreType),
		RedisUrl:                redisUrl,
		RedisTxNumOfRetries:     viper.GetInt(RedisTxNumOfRetries),
		NoTLS:                   viper.GetBool(NoTLS),
		DbDir:                   dbPath,
		DbUrl:                   dbUrl,
		EventDbDir:              dbPath,
		EventDbUrl:              eventDbUrl,
		LogLevel:                viper.GetInt(LogLevel),
		VtxoTreeExpiry:          determineLocktimeType(viper.GetInt64(VtxoTreeExpiry)),
		UnilateralExitDelay:     determineLocktimeType(viper.GetInt64(UnilateralExitDelay)),
		CheckpointExitDelay:     determineLocktimeType(viper.GetInt64(CheckpointExitDelay)),
		BoardingExitDelay:       determineLocktimeType(viper.GetInt64(BoardingExitDelay)),
		EsploraURL:              viper.GetString(EsploraURL),
		NoMacaroons:             viper.GetBool(NoMacaroons),
		TLSExtraIPs:             viper.GetStringSlice(TLSExtraIP),
		TLSExtraDomains:         viper.GetStringSlice(TLSExtraDomain),
		UnlockerType:            viper.GetString(UnlockerType),
		UnlockerFilePath:        viper.GetString(UnlockerFilePath),
		UnlockerPassword:        viper.GetString(UnlockerPassword),
		NoteUriPrefix:           viper.GetString(NoteUriPrefix),
		MarketHourStartTime:     viper.GetInt64(MarketHourStartTime),
		MarketHourEndTime:       viper.GetInt64(MarketHourEndTime),
		MarketHourPeriod:        viper.GetInt64(MarketHourPeriod),
		MarketHourRoundInterval: viper.GetInt64(MarketHourRoundInterval),
		OtelCollectorEndpoint:   viper.GetString(OtelCollectorEndpoint),
		OtelPushInterval:        viper.GetInt64(OtelPushInterval),

		RoundMaxParticipantsCount: viper.GetInt64(RoundMaxParticipantsCount),
		RoundMinParticipantsCount: viper.GetInt64(RoundMinParticipantsCount),
		UtxoMaxAmount:             viper.GetInt64(UtxoMaxAmount),
		UtxoMinAmount:             viper.GetInt64(UtxoMinAmount),
		VtxoMaxAmount:             viper.GetInt64(VtxoMaxAmount),
		VtxoMinAmount:             viper.GetInt64(VtxoMinAmount),
		AllowCSVBlockType:         allowCSVBlockType,
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
	if c.RoundInterval < 2 {
		return fmt.Errorf("invalid round interval, must be at least 2 seconds")
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
			return fmt.Errorf("scheduler type must be gocron if vtxo tree expiry is expressed in seconds")
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

	if c.VtxoMinAmount == 0 {
		return fmt.Errorf("vtxo min amount must be greater than 0")
	}

	if c.UtxoMinAmount == 0 {
		return fmt.Errorf("utxo min amount must be greater than 0")
	}

	if err := c.repoManager(); err != nil {
		return err
	}
	if err := c.walletService(); err != nil {
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

func (c *Config) IndexerService() (application.IndexerService, error) {
	pubKey, err := c.wallet.GetPubkey(context.Background())
	if err != nil {
		return nil, err
	}

	return application.NewIndexerService(pubKey, c.repo), nil
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
	arkWallet := viper.GetString(WalletAddr)
	if arkWallet == "" {
		return fmt.Errorf("ark wallet address not set")
	}

	walletSvc, network, err := walletclient.New(arkWallet)
	if err != nil {
		return err
	}

	c.wallet = walletSvc
	c.network = network
	return nil
}

func (c *Config) txBuilderService() error {
	var svc ports.TxBuilder
	var err error
	switch c.TxBuilderType {
	case "covenantless":
		svc = txbuilder.NewTxBuilder(
			c.wallet, *c.network, c.VtxoTreeExpiry, c.BoardingExitDelay,
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
	var mhStartTime, mhEndTime time.Time
	var mhPeriod, mhRoundInterval time.Duration

	if c.MarketHourStartTime > 0 {
		mhStartTime = time.Unix(c.MarketHourStartTime, 0)
		mhEndTime = time.Unix(c.MarketHourEndTime, 0)
	}
	if c.MarketHourPeriod > 0 {
		mhPeriod = time.Duration(c.MarketHourPeriod) * time.Minute
	}
	if c.MarketHourRoundInterval > 0 {
		mhRoundInterval = time.Duration(c.MarketHourRoundInterval) * time.Second
	}
	svc, err := application.NewService(
		c.wallet, c.repo, c.txBuilder, c.scanner, c.scheduler, c.liveStore,
		c.VtxoTreeExpiry, c.UnilateralExitDelay, c.BoardingExitDelay, c.CheckpointExitDelay,
		c.RoundInterval, c.RoundMinParticipantsCount, c.RoundMaxParticipantsCount,
		c.UtxoMaxAmount, c.UtxoMinAmount, c.VtxoMaxAmount, c.VtxoMinAmount,
		*c.network, c.AllowCSVBlockType, c.NoteUriPrefix,
		mhStartTime, mhEndTime, mhPeriod, mhRoundInterval,
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

	c.adminSvc = application.NewAdminService(c.wallet, c.repo, c.txBuilder, c.liveStore, unit)
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
