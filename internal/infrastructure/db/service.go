package db

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	badgerdb "github.com/arkade-os/arkd/internal/infrastructure/db/badger"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	log "github.com/sirupsen/logrus"
)

//go:embed sqlite/migration/*
var migrations embed.FS

//go:embed postgres/migration/*
var pgMigration embed.FS

var arkRepo badgerdb.ArkRepository

var (
	eventStoreTypes = map[string]func(...interface{}) (domain.EventRepository, error){
		"badger":   badgerdb.NewEventRepository,
		"postgres": pgdb.NewEventRepository,
	}
	roundStoreTypes = map[string]func(...interface{}) (domain.RoundRepository, error){
		"badger":   newBadgerRoundRepository,
		"sqlite":   sqlitedb.NewRoundRepository,
		"postgres": pgdb.NewRoundRepository,
	}
	vtxoStoreTypes = map[string]func(...interface{}) (domain.VtxoRepository, error){
		"badger":   badgerdb.NewVtxoRepository,
		"sqlite":   sqlitedb.NewVtxoRepository,
		"postgres": pgdb.NewVtxoRepository,
	}
	offchainTxStoreTypes = map[string]func(...interface{}) (domain.OffchainTxRepository, error){
		"badger":   newBadgerOffchainTxRepository,
		"sqlite":   sqlitedb.NewOffchainTxRepository,
		"postgres": pgdb.NewOffchainTxRepository,
	}
	convictionStoreTypes = map[string]func(...interface{}) (domain.ConvictionRepository, error){
		"badger":   badgerdb.NewConvictionRepository,
		"sqlite":   sqlitedb.NewConvictionRepository,
		"postgres": pgdb.NewConvictionRepository,
	}
	assetStoreTypes = map[string]func(...interface{}) (domain.AssetRepository, error){
		"sqlite":   sqlitedb.NewAssetRepository,
		"badger":   badgerdb.NewAssetRepository,
		"postgres": pgdb.NewAssetRepository,
	}
	settingsStoreTypes = map[string]func(...interface{}) (domain.SettingsRepository, error){
		"badger":   badgerdb.NewSettingsRepository,
		"sqlite":   sqlitedb.NewSettingsRepository,
		"postgres": pgdb.NewSettingsRepository,
	}
	markerStoreTypes = map[string]func(...interface{}) (domain.MarkerRepository, error){
		"badger":   badgerdb.NewMarkerRepository,
		"sqlite":   sqlitedb.NewMarkerRepository,
		"postgres": pgdb.NewMarkerRepository,
	}
)

const sqliteDbFile = "sqlite.db"

type ServiceConfig struct {
	EventStoreType string
	DataStoreType  string

	EventStoreConfig []interface{}
	DataStoreConfig  []interface{}

	// Settings is the config-built default settings used to seed the settings
	// table on first boot (see handleSettingsSeed).
	Settings domain.Settings
}

type service struct {
	eventStore             domain.EventRepository
	roundStore             domain.RoundRepository
	vtxoStore              domain.VtxoRepository
	markerStore            domain.MarkerRepository
	offchainTxStore        domain.OffchainTxRepository
	convictionStore        domain.ConvictionRepository
	assetStore             domain.AssetRepository
	settingsStore          domain.SettingsRepository
	txDecoder              ports.TxDecoder
	batchEventHandler      *updateHandler[domain.Round]
	offchainTxEventHandler *updateHandler[domain.OffchainTx]
}

func NewService(config ServiceConfig, txDecoder ports.TxDecoder) (ports.RepoManager, error) {
	eventStoreFactory, ok := eventStoreTypes[config.EventStoreType]
	if !ok {
		return nil, fmt.Errorf("event store type not supported")
	}
	roundStoreFactory, ok := roundStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("round store type not supported")
	}
	vtxoStoreFactory, ok := vtxoStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("vtxo store type not supported")
	}
	offchainTxStoreFactory, ok := offchainTxStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	convictionStoreFactory, ok := convictionStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	assetStoreFactory, ok := assetStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	settingsStoreFactory, ok := settingsStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	markerStoreFactory, ok := markerStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	var eventStore domain.EventRepository
	var roundStore domain.RoundRepository
	var vtxoStore domain.VtxoRepository
	var markerStore domain.MarkerRepository
	var offchainTxStore domain.OffchainTxRepository
	var convictionStore domain.ConvictionRepository
	var assetStore domain.AssetRepository
	var settingsStore domain.SettingsRepository
	var err error

	switch config.EventStoreType {
	case "badger":
		eventStore, err = eventStoreFactory(config.EventStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open event store: %s", err)
		}
	case "postgres":
		if len(config.EventStoreConfig) != 3 {
			return nil, fmt.Errorf("invalid data store config for postgres")
		}

		dsn, ok := config.EventStoreConfig[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid DSN for postgres")
		}

		autoCreate, ok := config.EventStoreConfig[1].(bool)
		if !ok {
			return nil, fmt.Errorf("invalid autocreate flag for postgres")
		}

		connectionCfg, ok := config.EventStoreConfig[2].(pgdb.ConnectionConfig)
		if !ok {
			return nil, fmt.Errorf("invalid connection config flags for postgres")
		}

		db, err := pgdb.OpenDb(dsn, autoCreate, pgdb.WithConnectionConfig(connectionCfg))
		if err != nil {
			return nil, fmt.Errorf("failed to open postgres db: %s", err)
		}

		eventStore, err = eventStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open event store: %s", err)
		}
	default:
		return nil, fmt.Errorf("unknown event store db type")
	}

	switch config.DataStoreType {
	case "badger":
		roundStore, err = roundStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open round store: %s", err)
		}
		arkStore := roundStore.(badgerdb.ArkRepository).Store()
		vtxoStoreConfig := append(config.DataStoreConfig, arkStore)
		vtxoStore, err = vtxoStoreFactory(vtxoStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}
		offchainTxStore, err = offchainTxStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
		convictionStore, err = convictionStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create conviction store: %w", err)
		}
		assetStoreConfig := append(config.DataStoreConfig, vtxoStore)
		assetStore, err = assetStoreFactory(assetStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create asset store: %w", err)
		}
		settingsStore, err = settingsStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create settings store: %w", err)
		}
		// Badger has no legacy SQL tables, so its seed is just the config
		// defaults when the store is empty (no backfill).
		existingSettings, err := settingsStore.Get(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to read settings for seed: %w", err)
		}
		if existingSettings == nil {
			if err := settingsStore.Upsert(
				context.Background(), config.Settings, nil,
			); err != nil {
				return nil, fmt.Errorf("failed to seed settings: %w", err)
			}
		}
		// Pass the vtxo store to the marker repository so they share the same data
		badgerVtxoRepo, ok := vtxoStore.(*badgerdb.VtxoRepository)
		if !ok {
			return nil, fmt.Errorf("failed to get badger vtxo repository")
		}
		markerConfig := make(
			[]interface{},
			len(config.DataStoreConfig),
			len(config.DataStoreConfig)+1,
		)
		copy(markerConfig, config.DataStoreConfig)
		markerConfig = append(markerConfig, badgerVtxoRepo.GetStore())
		markerStore, err = markerStoreFactory(markerConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create marker store: %w", err)
		}
		// Badger has no SQL migration path, so rebuild the vtxo marker DAG here
		// on startup. The internal completion-latch guard makes this a cheap
		// no-op after the first successful run.
		markerAccessor, ok := markerStore.(badgerdb.MarkerStoreAccessor)
		if !ok {
			return nil, fmt.Errorf("failed to get badger marker store accessor")
		}
		if err := badgerdb.BackfillVtxoMarkers(
			context.Background(),
			badgerVtxoRepo.GetStore(),
			markerAccessor.GetMarkerStore(),
		); err != nil {
			return nil, fmt.Errorf("failed to backfill vtxo markers: %w", err)
		}

	case "postgres":
		if len(config.DataStoreConfig) != 3 {
			return nil, fmt.Errorf("invalid data store config for postgres")
		}

		dsn, ok := config.DataStoreConfig[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid DSN for postgres")
		}

		autoCreate, ok := config.DataStoreConfig[1].(bool)
		if !ok {
			return nil, fmt.Errorf("invalid autocreate flag for postgres")
		}

		connectionCfg, ok := config.DataStoreConfig[2].(pgdb.ConnectionConfig)
		if !ok {
			return nil, fmt.Errorf("invalid connection config flags for postgres")
		}

		db, err := pgdb.OpenDb(dsn, autoCreate, pgdb.WithConnectionConfig(connectionCfg))
		if err != nil {
			return nil, fmt.Errorf("failed to open postgres db: %s", err)
		}

		pgDriver, err := migratepg.WithInstance(db, &migratepg.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to init postgres migration driver: %s", err)
		}

		source, err := iofs.New(pgMigration, "postgres/migration")
		if err != nil {
			return nil, fmt.Errorf("failed to embed postgres migrations: %s", err)
		}

		m, err := migrate.NewWithInstance("iofs", source, "postgres", pgDriver)
		if err != nil {
			return nil, fmt.Errorf("failed to create postgres migration instance: %s", err)
		}

		err = handleIntentTxidMigration(m, db, config.DataStoreType)
		if err != nil {
			return nil, fmt.Errorf("failed to handle intent txid migration: %w", err)
		}

		err = handleVtxoMarkersMigration(m, db, config.DataStoreType)
		if err != nil {
			return nil, fmt.Errorf("failed to handle vtxo markers migration: %w", err)
		}

		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("failed to run postgres migrations: %s", err)
		}

		if err := handleSettingsSeed(
			context.Background(), db, config.DataStoreType, config.Settings,
		); err != nil {
			return nil, fmt.Errorf("failed to seed settings: %w", err)
		}

		roundStore, err = roundStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open round store: %s", err)
		}

		vtxoStore, err = vtxoStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}

		offchainTxStore, err = offchainTxStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
		convictionStore, err = convictionStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create conviction store: %w", err)
		}
		assetStore, err = assetStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create asset store: %w", err)
		}
		settingsStore, err = settingsStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create settings store: %w", err)
		}
		markerStore, err = markerStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create marker store: %w", err)
		}

	case "sqlite":
		if len(config.DataStoreConfig) != 1 {
			return nil, fmt.Errorf("invalid data store config")
		}

		baseDir, ok := config.DataStoreConfig[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid base directory")
		}

		dbFile := filepath.Join(baseDir, sqliteDbFile)
		db, err := sqlitedb.OpenDb(
			dbFile,
			sqlitedb.WithJournalModeWAL(),
			sqlitedb.WithBusyTimeout(5*time.Second),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to open db: %s", err)
		}

		driver, err := sqlitemigrate.WithInstance(db.Write(), &sqlitemigrate.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to init driver: %s", err)
		}

		source, err := iofs.New(migrations, "sqlite/migration")
		if err != nil {
			return nil, fmt.Errorf("failed to embed migrations: %s", err)
		}

		m, err := migrate.NewWithInstance("iofs", source, "arkdb", driver)
		if err != nil {
			return nil, fmt.Errorf("failed to create migration instance: %s", err)
		}

		err = handleIntentTxidMigration(m, db.Write(), config.DataStoreType)
		if err != nil {
			return nil, fmt.Errorf("failed to handle intent txid migration: %w", err)
		}

		err = handleVtxoMarkersMigration(m, db.Write(), config.DataStoreType)
		if err != nil {
			return nil, fmt.Errorf("failed to handle vtxo markers migration: %w", err)
		}

		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("failed to run migrations: %s", err)
		}

		if err := handleSettingsSeed(
			context.Background(), db.Write(), config.DataStoreType, config.Settings,
		); err != nil {
			return nil, fmt.Errorf("failed to seed settings: %w", err)
		}

		roundStore, err = roundStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open round store: %s", err)
		}
		vtxoStore, err = vtxoStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}
		offchainTxStore, err = offchainTxStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
		convictionStore, err = convictionStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create conviction store: %w", err)
		}
		assetStore, err = assetStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create asset store: %w", err)
		}
		settingsStore, err = settingsStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create settings store: %w", err)
		}
		markerStore, err = markerStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create marker store: %w", err)
		}
	}

	svc := &service{
		eventStore:             eventStore,
		roundStore:             roundStore,
		vtxoStore:              vtxoStore,
		markerStore:            markerStore,
		offchainTxStore:        offchainTxStore,
		txDecoder:              txDecoder,
		convictionStore:        convictionStore,
		assetStore:             assetStore,
		settingsStore:          settingsStore,
		batchEventHandler:      newUpdateHandler[domain.Round](),
		offchainTxEventHandler: newUpdateHandler[domain.OffchainTx](),
	}

	// Register handlers that take care of keeping the projection store up-to-date.
	if txDecoder != nil {
		eventStore.RegisterEventsHandler(domain.RoundTopic, svc.updateProjectionsAfterRoundEvents)
		eventStore.RegisterEventsHandler(
			domain.OffchainTxTopic, svc.updateProjectionsAfterOffchainTxEvents,
		)
	}

	return svc, nil
}

func (s *service) Events() domain.EventRepository {
	return s.eventStore
}

func (s *service) Rounds() domain.RoundRepository {
	return s.roundStore
}

func (s *service) Assets() domain.AssetRepository {
	return s.assetStore
}

func (s *service) Vtxos() domain.VtxoRepository {
	return s.vtxoStore
}

func (s *service) Markers() domain.MarkerRepository {
	return s.markerStore
}

func (s *service) OffchainTxs() domain.OffchainTxRepository {
	return s.offchainTxStore
}

func (s *service) Convictions() domain.ConvictionRepository {
	return s.convictionStore
}

func (s *service) Settings() domain.SettingsRepository {
	return s.settingsStore
}

func (s *service) RegisterBatchUpdateHandler(handler func(data domain.Round)) {
	s.batchEventHandler.set(handler)
}

func (s *service) RegisterOffchainTxUpdateHandler(handler func(data domain.OffchainTx)) {
	s.offchainTxEventHandler.set(handler)
}

func (s *service) RegisterSettingsUpdateHandler(handler func(domain.Settings, []string)) {
	s.settingsStore.RegisterUpdatesHandler(handler)
}

func (s *service) Close() {
	s.eventStore.Close()
	s.roundStore.Close()
	s.vtxoStore.Close()
	s.markerStore.Close()
	s.offchainTxStore.Close()
	s.convictionStore.Close()
	s.settingsStore.Close()
}

func (s *service) updateProjectionsAfterRoundEvents(events []domain.Event) {
	ctx := context.Background()
	round := domain.NewRoundFromEvents(events)
	updateFn := func() bool {
		if err := s.roundStore.AddOrUpdateRound(ctx, *round); err != nil {
			log.WithError(err).Errorf("failed to add or update round %s", round.Id)
			return false
		}
		log.Debugf("added or updated round %s", round.Id)

		if !round.IsEnded() {
			return true
		}

		repo := s.vtxoStore

		lastEvent := events[len(events)-1]
		if lastEvent.GetType() == domain.EventTypeBatchSwept {
			event := lastEvent.(domain.BatchSwept)
			allSweptVtxos := append(event.LeafVtxos, event.PreconfirmedVtxos...)
			// Per-outpoint sweeping avoids marker over-reach: markers can be shared
			// across independent subtrees when offchain txs consolidate inputs from
			// different lineages. Sweeping by marker would incorrectly mark unrelated
			// VTXOs as swept (same reason the checkpoint path uses SweepVtxoOutpoints).
			sweptAt := time.Now().Unix()
			if err := s.markerStore.SweepVtxoOutpoints(ctx, allSweptVtxos, sweptAt); err != nil {
				log.WithError(err).Warn(
					"failed to sweep vtxo outpoints for batch, aborting round projection " +
						"(update not dispatched, not retried)",
				)
				return false
			}
			log.Debugf("swept %d vtxo outpoints for batch", len(allSweptVtxos))

			if event.FullySwept {
				log.WithField("commitment_txid", round.CommitmentTxid).Debugf(
					"round %s fully swept", round.Id,
				)
			}
			return true
		}

		spentVtxos := getSpentVtxoKeysFromRound(*round, s.txDecoder)
		newVtxos := getNewVtxosFromRound(*round, s.txDecoder)

		if len(spentVtxos) > 0 {
			if err := repo.SettleVtxos(ctx, spentVtxos, round.CommitmentTxid); err != nil {
				log.WithError(err).Warn(
					"failed to spend vtxos, aborting round projection " +
						"(update not dispatched, not retried)",
				)
				return false
			}
			log.Debugf("spent %d vtxos", len(spentVtxos))
		}

		if len(newVtxos) > 0 {
			// this will take care of updating asset projections as well
			if err := repo.AddVtxos(ctx, newVtxos); err != nil {
				log.WithError(err).Warn(
					"failed to add new vtxos, aborting round projection " +
						"(update not dispatched, not retried)",
				)
				return false
			}
			log.Debugf("added %d new vtxos", len(newVtxos))

			// Create root markers for batch VTXOs (depth 0 is always at marker boundary).
			if err := s.markerStore.CreateRootMarkersForVtxos(ctx, newVtxos); err != nil {
				log.WithError(err).Warnf(
					"failed to create root markers for %d vtxos", len(newVtxos),
				)
				return false
			}
			log.Debugf("created root markers for %d vtxos", len(newVtxos))
		}
		return true
	}

	dispatch := updateFn()
	if dispatch {
		go s.batchEventHandler.dispatch(*round)
	}
}

func (s *service) updateProjectionsAfterOffchainTxEvents(events []domain.Event) {
	ctx := context.Background()
	offchainTx := domain.NewOffchainTxFromEvents(events)
	updateFn := func() bool {
		if err := s.offchainTxStore.AddOrUpdateOffchainTx(ctx, offchainTx); err != nil {
			log.WithError(err).Errorf("failed to add or update offchain tx %s", offchainTx.ArkTxid)
			return false
		}
		log.Debugf("added or updated offchain tx %s", offchainTx.ArkTxid)

		switch {
		case offchainTx.IsAccepted():
			spentVtxos := make(map[domain.Outpoint]string)
			for _, tx := range offchainTx.CheckpointTxs {
				txid, ins, _, err := s.txDecoder.DecodeTx(tx)
				if err != nil {
					log.WithError(err).Warn("failed to decode checkpoint tx")
					continue
				}
				for _, in := range ins {
					spentVtxos[in] = txid
				}
			}

			// as soon as the checkpoint txs are signed by the signer,
			// we must mark the vtxos as spent to prevent double spending.
			if err := s.vtxoStore.SpendVtxos(ctx, spentVtxos, offchainTx.ArkTxid); err != nil {
				log.WithError(err).Warn("failed to spend vtxos")
				return false
			}
			log.Debugf("spent %d vtxos", len(spentVtxos))
		case offchainTx.IsFinalized():
			txid, _, outs, err := s.txDecoder.DecodeTx(offchainTx.ArkTx)
			if err != nil {
				log.WithError(err).Warn("failed to decode ark tx")
				return false
			}

			// Depth and parent marker IDs are carried by the OffchainTxAccepted event,
			// computed in SubmitOffchainTx from the spent VTXOs.
			newDepth := offchainTx.Depth
			parentMarkerIDs := offchainTx.ParentMarkerIDs

			// Create marker if at boundary depth, or inherit parent markers
			var markerIDs []string
			marker, ids := domain.NewMarker(txid, newDepth, parentMarkerIDs)
			if marker != nil {
				if err := s.markerStore.AddMarker(ctx, *marker); err != nil {
					log.WithError(err).
						Warn("failed to create marker for chained vtxo, falling back to parent markers")
					// Fall back to parent markers so VTXOs are still sweepable.
					// Without this, markerIDs stays nil and the VTXOs become
					// permanently unsweepable — the swept column was removed and
					// swept status is now derived from whether any of a VTXO's
					// markers appear in the swept_marker table.
					markerIDs = parentMarkerIDs
				} else {
					log.Debugf("created marker %s at depth %d", marker.ID, newDepth)
					markerIDs = ids
				}
			} else {
				markerIDs = ids
			}

			issuances, assets, err := getAssetsFromTxOuts(txid, outs)
			if err != nil {
				log.WithError(err).Warn("failed to get assets from tx")
				return false
			}

			sweepTxs, err := s.roundStore.GetSweepTxs(ctx, offchainTx.RootCommitmentTxId)
			// We consider the tx swept if:
			// - there is an error fetching the sweep txs (this is just fallback, should never happen)
			// - the batch is swept
			// - the tx expired (meaning one or all its inputs expired and are already swept or about
			// to be swept)
			txSwept := err != nil || len(sweepTxs) > 0 ||
				time.Now().After(time.Unix(offchainTx.ExpiryTimestamp, 0))
			// once the offchain tx is finalized, the user signed the checkpoint txs
			// thus, we can create the new vtxos in the db.
			newVtxos := make([]domain.Vtxo, 0, len(outs))
			createdDustMarkerIDs := make([]string, 0)
			sweptOutpoints := make([]domain.Outpoint, 0)
			for outIndex, out := range outs {
				// ignore anchor and extension
				if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) ||
					extension.IsExtension(out.PkScript) {
					continue
				}

				// at that point, we should only have valid taproot script
				if len(out.PkScript) != 34 {
					continue
				}

				outputSwept := txSwept
				if !outputSwept {
					outputSwept = script.IsSubDustScript(out.PkScript)
				}

				outpoint := domain.Outpoint{
					Txid: txid,
					VOut: uint32(outIndex),
				}

				vtxoMarkerIDs := markerIDs
				isDust := script.IsSubDustScript(out.PkScript)
				if txSwept && !isDust {
					// The swept column no longer exists, so the Swept flag set on
					// the vtxo struct below is not persisted by AddVtxos. Collect
					// non-dust outpoints to sweep them (via swept_vtxo) before insert.
					// Dust outputs are covered by their swept dust markers.
					sweptOutpoints = append(sweptOutpoints, outpoint)
				}
				if isDust {
					// Dust VTXOs get their own outpoint-based marker so they can be
					// swept individually without affecting sibling non-dust VTXOs
					// that share the same inherited parent markers.
					dustMarkerID := outpoint.String()
					if err := s.markerStore.AddMarker(ctx, domain.Marker{
						ID:              dustMarkerID,
						Depth:           newDepth,
						ParentMarkerIDs: markerIDs,
						CreatedAt:       time.Now().Unix(),
					}); err != nil {
						// Sub-dust vtxos can't be spent offchain (OP_RETURN outputs):
						// they can only be collected until they sum to a non-sub-dust
						// amount (> 330 sats) and settled into a batch. We mark them
						// swept so they fall in the same bucket as expired (swept)
						// vtxos, the only other vtxos with that same "not spendable
						// offchain" trait. If the dust marker can't be persisted the
						// vtxo would instead look like a normal spendable vtxo
						// (postgres/sqlite have no swept column), so we abort the
						// projection rather than store a mis-categorized vtxo; the
						// event is not dispatched.
						log.WithError(err).Warnf("failed to create dust marker %s", dustMarkerID)
						return false
					}
					createdDustMarkerIDs = append(createdDustMarkerIDs, dustMarkerID)
					vtxoMarkerIDs = append(append([]string{}, markerIDs...), dustMarkerID)
				}

				newVtxos = append(newVtxos, domain.Vtxo{
					Outpoint:           outpoint,
					PubKey:             hex.EncodeToString(out.PkScript[2:]),
					Amount:             uint64(out.Amount),
					ExpiresAt:          offchainTx.ExpiryTimestamp,
					CommitmentTxids:    offchainTx.CommitmentTxidsList(),
					RootCommitmentTxid: offchainTx.RootCommitmentTxId,
					Preconfirmed:       true,
					CreatedAt:          offchainTx.StartingTimestamp,
					// mark the vtxo as "swept" if it is below dust limit to prevent it from being spent again in a future offchain tx
					// the only way to spend a swept vtxo is by collecting enough dust to cover the minSettlementVtxoAmount and then settle.
					// because sub-dust vtxos are using OP_RETURN output script, they can't be unilaterally exited.
					// Only badger persists this field directly. Postgres and sqlite
					// have no swept column, so for them it is persisted via the dust
					// marker sweep and the swept outpoints insert below.
					Swept:     outputSwept,
					Depth:     newDepth,
					MarkerIDs: vtxoMarkerIDs,
					Assets:    assets[uint32(outIndex)],
				})
			}

			if len(issuances) > 0 {
				assetsByTx := map[string][]domain.Asset{
					offchainTx.ArkTxid: issuances,
				}
				count, err := s.assetStore.AddAssets(ctx, assetsByTx)
				if err != nil {
					log.WithError(err).Warnf(
						"failed to add issued assets in offchain tx %s", offchainTx.ArkTxid,
					)
					return false
				}
				if count > 0 {
					log.Infof("added %d issued assets", count)
				}
			}

			// Persist swept state BEFORE creating the vtxos, so a failed swept write
			// aborts the projection instead of leaving a spendable vtxo behind. Both
			// tables are independent of the vtxo row: swept_marker references the dust
			// markers created above, and swept_vtxo is keyed by outpoint — neither
			// needs the vtxo to exist yet.

			// Mark dust VTXOs as swept via their markers.
			// Dust vtxos are below dust limit and can't be spent again in future offchain tx.
			// Because sub-dust vtxos are using OP_RETURN output script, they can't be unilaterally exited.
			if len(createdDustMarkerIDs) > 0 {
				sweptAt := time.Now().Unix()
				if err := s.markerStore.BulkSweepMarkers(
					ctx,
					createdDustMarkerIDs,
					sweptAt,
				); err != nil {
					log.WithError(err).
						Warnf("failed to sweep %d dust vtxo markers", len(createdDustMarkerIDs))
					return false
				}
			}

			// Persist swept status for non-dust outputs of a swept/expired tx,
			// per-outpoint like the batch and checkpoint sweep paths.
			if len(sweptOutpoints) > 0 {
				sweptAt := time.Now().Unix()
				if err := s.markerStore.SweepVtxoOutpoints(
					ctx, sweptOutpoints, sweptAt,
				); err != nil {
					log.WithError(err).
						Warnf("failed to sweep %d vtxo outpoints of swept tx", len(sweptOutpoints))
					return false
				}
			}

			if err := s.vtxoStore.AddVtxos(ctx, newVtxos); err != nil {
				log.WithError(err).Warn("failed to add vtxos")
				return false
			}
			log.Debugf("added %d vtxos at depth %d", len(newVtxos), newDepth)
		}
		return true
	}

	dispatch := updateFn()
	if dispatch {
		go s.offchainTxEventHandler.dispatch(*offchainTx)
	}
}

func getSpentVtxoKeysFromRound(
	round domain.Round, txDecoder ports.TxDecoder,
) map[domain.Outpoint]string {
	spentVtxos := make(map[domain.Outpoint]string)

	// Build a map of forfeit tx inputs for O(1) lookup
	forfeitInputs := make(map[domain.Outpoint]string)
	for _, forfeitTx := range round.ForfeitTxs {
		_, ins, _, err := txDecoder.DecodeTx(forfeitTx.Tx)
		if err != nil {
			log.WithError(err).Warnf("failed to decode forfeit tx %s", forfeitTx.Txid)
			continue
		}
		for _, in := range ins {
			forfeitInputs[in] = forfeitTx.Txid
		}
	}

	// Match vtxos with forfeit transactions
	for _, intent := range round.Intents {
		for _, vtxo := range intent.Inputs {
			if !vtxo.RequiresForfeit() {
				spentVtxos[vtxo.Outpoint] = ""
			} else if txid, found := forfeitInputs[vtxo.Outpoint]; found {
				spentVtxos[vtxo.Outpoint] = txid
			}
		}
	}
	return spentVtxos
}

func getNewVtxosFromRound(round domain.Round, txDecoder ports.TxDecoder) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, node := range tree.FlatTxTree(round.VtxoTree).Leaves() {
		txid, _, outs, err := txDecoder.DecodeTx(node.Tx)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}

		_, assets, err := getAssetsFromTxOuts(txid, outs)
		if err != nil {
			log.WithError(err).Warn("failed to get assets from tx")
			continue
		}

		for i, out := range outs {
			// ignore anchor and extension
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) ||
				extension.IsExtension(out.PkScript) {
				continue
			}

			vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				log.WithError(err).Warn("failed to parse vtxo tap key")
				continue
			}

			vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))
			outpoint := domain.Outpoint{Txid: txid, VOut: uint32(i)}
			vtxos = append(vtxos, domain.Vtxo{
				Outpoint:           outpoint,
				PubKey:             vtxoPubkey,
				Amount:             out.Amount,
				CommitmentTxids:    []string{round.CommitmentTxid},
				RootCommitmentTxid: round.CommitmentTxid,
				CreatedAt:          round.EndingTimestamp,
				ExpiresAt:          round.ExpiryTimestamp(),
				Depth:              0,
				MarkerIDs:          []string{outpoint.String()},
				Assets:             assets[uint32(i)],
			})
		}
	}
	return vtxos
}

func getAssetsFromTxOuts(txid string, txOuts []ports.TxOut) (
	[]domain.Asset, map[uint32][]domain.AssetDenomination, error,
) {
	assetPacket := make(asset.Packet, 0)
	for _, out := range txOuts {
		if extension.IsExtension(out.PkScript) {
			ext, err := extension.NewExtensionFromBytes(out.PkScript)
			if err != nil {
				return nil, nil, err
			}

			assetPacket = ext.GetAssetPacket()
			break
		}
	}

	if len(assetPacket) <= 0 {
		return nil, nil, nil
	}

	getAssetId := func(groupIndex uint16) (string, error) {
		if groupIndex >= uint16(len(assetPacket)) {
			return "", fmt.Errorf("group index %d out of range", groupIndex)
		}
		group := assetPacket[groupIndex]
		if group.IsIssuance() {
			id, err := asset.NewAssetId(txid, groupIndex)
			if err != nil {
				return "", fmt.Errorf("failed to compute asset id: %w", err)
			}
			return id.String(), nil
		}
		return group.AssetId.String(), nil

	}

	issuances := make([]domain.Asset, 0)
	assetDenominations := make(map[uint32][]domain.AssetDenomination)
	for grpIndex, ast := range assetPacket {
		for _, out := range ast.Outputs {
			assetId := ""

			if ast.IsIssuance() {
				var err error
				assetId, err = getAssetId(uint16(grpIndex))
				if err != nil {
					return nil, nil, err
				}

				issuance := domain.Asset{
					Id:       assetId,
					Metadata: ast.Metadata,
				}

				if ast.ControlAsset != nil {
					switch ast.ControlAsset.Type {
					case asset.AssetRefByID:
						issuance.ControlAssetId = ast.ControlAsset.AssetId.String()
					case asset.AssetRefByGroup:
						issuance.ControlAssetId, err = getAssetId(ast.ControlAsset.GroupIndex)
						if err != nil {
							return nil, nil, err
						}
					}
				}

				issuances = append(issuances, issuance)
			} else {
				assetId = ast.AssetId.String()
			}

			assetDenominations[uint32(out.Vout)] = append(
				assetDenominations[uint32(out.Vout)], domain.AssetDenomination{
					AssetId: assetId,
					Amount:  out.Amount,
				},
			)
		}
	}
	return issuances, assetDenominations, nil
}

func initBadgerArkRepository(args ...interface{}) (badgerdb.ArkRepository, error) {
	if arkRepo == nil {
		repo, err := badgerdb.NewArkRepository(args...)
		if err != nil {
			return nil, err
		}
		arkRepo = repo
	}
	return arkRepo, nil
}

func newBadgerRoundRepository(args ...interface{}) (domain.RoundRepository, error) {
	return initBadgerArkRepository(args...)
}

func newBadgerOffchainTxRepository(args ...interface{}) (domain.OffchainTxRepository, error) {
	return initBadgerArkRepository(args...)
}

// stepwise migration for intent txid field addition
func handleIntentTxidMigration(m *migrate.Migrate, db *sql.DB, dbType string) error {
	intentTxidMigrationBegin := uint(20260114000000)
	version, dirty, verr := m.Version()
	if verr != nil && !errors.Is(verr, migrate.ErrNilVersion) {
		return fmt.Errorf("failed to read migration version: %w", verr)
	}
	if dirty {
		return fmt.Errorf(
			"database is in a dirty migration state; manual intervention required",
		)
	}

	if version < intentTxidMigrationBegin {
		if err := m.Migrate(intentTxidMigrationBegin); err != nil &&
			!errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("failed to run migrations: %s", err)
		}

		switch dbType {
		case "postgres":
			if err := pgdb.BackfillIntentTxid(context.Background(), db); err != nil {
				return fmt.Errorf("failed to backfill intent txid field: %w", err)
			}
		case "sqlite":
			if err := sqlitedb.BackfillIntentTxid(context.Background(), db); err != nil {
				return fmt.Errorf("failed to backfill intent txid field: %w", err)
			}
		default:
			return fmt.Errorf("unsupported db type for intent txid migration: %s", dbType)
		}
	}

	return nil
}

// stepwise migration for the vtxo marker DAG backfill (real BFS depths +
// boundary markers). Gated at 20260701000000, the marker-DAG schema migration.
// Unlike the intent-txid precedent, the backfill dispatch runs on every startup
// (outside the version gate): its internal data guard makes it a cheap no-op
// once topology exists and re-runs an interrupted (rolled-back) backfill that
// left the version advanced but no data written.
func handleVtxoMarkersMigration(m *migrate.Migrate, db *sql.DB, dbType string) error {
	vtxoMarkersMigrationBegin := uint(20260701000000)
	version, dirty, verr := m.Version()
	if verr != nil && !errors.Is(verr, migrate.ErrNilVersion) {
		return fmt.Errorf("failed to read migration version: %w", verr)
	}
	if dirty {
		return fmt.Errorf(
			"database is in a dirty migration state; manual intervention required",
		)
	}
	if version < vtxoMarkersMigrationBegin {
		if err := m.Migrate(vtxoMarkersMigrationBegin); err != nil &&
			!errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("failed to run migrations: %s", err)
		}
	}

	switch dbType {
	case "postgres":
		if err := pgdb.BackfillVtxoMarkers(context.Background(), db); err != nil {
			return fmt.Errorf("failed to backfill vtxo markers: %w", err)
		}
	case "sqlite":
		if err := sqlitedb.BackfillVtxoMarkers(context.Background(), db); err != nil {
			return fmt.Errorf("failed to backfill vtxo markers: %w", err)
		}
	default:
		return fmt.Errorf("unsupported db type for vtxo markers migration: %s", dbType)
	}

	return nil
}

// handleSettingsSeed seeds the settings table from the config-built defaults on
// first boot, carrying over any legacy intent_fees / scheduled_session rows. It is
// a no-op once the settings row exists. Mirrors handleIntentTxidMigration's dispatch.
func handleSettingsSeed(
	ctx context.Context, db *sql.DB, dbType string, defaults domain.Settings,
) error {
	switch dbType {
	case "postgres":
		return pgdb.SeedSettings(ctx, db, defaults)
	case "sqlite":
		return sqlitedb.SeedSettings(ctx, db, defaults)
	default:
		return fmt.Errorf("unsupported db type for settings seed: %s", dbType)
	}
}
