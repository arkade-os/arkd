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
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	badgerdb "github.com/arkade-os/arkd/internal/infrastructure/db/badger"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
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
	scheduledSessionStoreTypes = map[string]func(...interface{}) (domain.ScheduledSessionRepo, error){
		"badger":   badgerdb.NewScheduledSessionRepository,
		"sqlite":   sqlitedb.NewScheduledSessionRepository,
		"postgres": pgdb.NewScheduledSessionRepository,
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
	intentFeesStoreTypes = map[string]func(...interface{}) (domain.FeeRepository, error){
		"badger":   badgerdb.NewIntentFeesRepository,
		"sqlite":   sqlitedb.NewIntentFeesRepository,
		"postgres": pgdb.NewIntentFeesRepository,
	}
	markerStoreTypes = map[string]func(...interface{}) (domain.MarkerRepository, error){
		"badger":   badgerdb.NewMarkerRepository,
		"sqlite":   sqlitedb.NewMarkerRepository,
		"postgres": pgdb.NewMarkerRepository,
	}
)

const (
	sqliteDbFile = "sqlite.db"
)

type ServiceConfig struct {
	EventStoreType string
	DataStoreType  string

	EventStoreConfig []interface{}
	DataStoreConfig  []interface{}
}

type service struct {
	eventStore            domain.EventRepository
	roundStore            domain.RoundRepository
	vtxoStore             domain.VtxoRepository
	markerStore           domain.MarkerRepository
	scheduledSessionStore domain.ScheduledSessionRepo
	offchainTxStore       domain.OffchainTxRepository
	convictionStore       domain.ConvictionRepository
	intentFeesStore       domain.FeeRepository
	txDecoder             ports.TxDecoder
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
	scheduledSessionStoreFactory, ok := scheduledSessionStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	offchainTxStoreFactory, ok := offchainTxStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	convictionStoreFactory, ok := convictionStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	intentFeesStoreFactory, ok := intentFeesStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	markerStoreFactory := markerStoreTypes[config.DataStoreType]

	var eventStore domain.EventRepository
	var roundStore domain.RoundRepository
	var vtxoStore domain.VtxoRepository
	var markerStore domain.MarkerRepository
	var scheduledSessionStore domain.ScheduledSessionRepo
	var offchainTxStore domain.OffchainTxRepository
	var convictionStore domain.ConvictionRepository
	var intentFeesStore domain.FeeRepository
	var err error

	switch config.EventStoreType {
	case "badger":
		eventStore, err = eventStoreFactory(config.EventStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open event store: %s", err)
		}
	case "postgres":
		if len(config.EventStoreConfig) != 2 {
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

		db, err := pgdb.OpenDb(dsn, autoCreate)
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
		vtxoStore, err = vtxoStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}
		scheduledSessionStore, err = scheduledSessionStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create scheduled session store: %w", err)
		}
		offchainTxStore, err = offchainTxStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
		convictionStore, err = convictionStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create conviction store: %w", err)
		}
		intentFeesStore, err = intentFeesStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create intent fees store: %w", err)
		}
		if markerStoreFactory != nil {
			// For badger, pass the vtxo store to marker repo to share the same database
			badgerVtxoRepo, ok := vtxoStore.(*badgerdb.VtxoRepository)
			if ok {
				markerConfig := append(config.DataStoreConfig, badgerVtxoRepo.Store())
				markerStore, err = markerStoreFactory(markerConfig...)
			} else {
				markerStore, err = markerStoreFactory(config.DataStoreConfig...)
			}
			if err != nil {
				return nil, fmt.Errorf("failed to create marker store: %w", err)
			}
		}
	case "postgres":
		if len(config.DataStoreConfig) != 2 {
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

		db, err := pgdb.OpenDb(dsn, autoCreate)
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

		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("failed to run postgres migrations: %s", err)
		}

		roundStore, err = roundStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open round store: %s", err)
		}

		vtxoStore, err = vtxoStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}

		scheduledSessionStore, err = scheduledSessionStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create scheduled session store: %w", err)
		}

		offchainTxStore, err = offchainTxStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
		convictionStore, err = convictionStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create conviction store: %w", err)
		}
		intentFeesStore, err = intentFeesStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create intent fees store: %w", err)
		}
		if markerStoreFactory != nil {
			markerStore, err = markerStoreFactory(db)
			if err != nil {
				return nil, fmt.Errorf("failed to create marker store: %w", err)
			}
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
		db, err := sqlitedb.OpenDb(dbFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open db: %s", err)
		}

		driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
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

		err = handleIntentTxidMigration(m, db, config.DataStoreType)
		if err != nil {
			return nil, fmt.Errorf("failed to handle intent txid migration: %w", err)
		}

		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("failed to run migrations: %s", err)
		}

		roundStore, err = roundStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open round store: %s", err)
		}
		vtxoStore, err = vtxoStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}
		scheduledSessionStore, err = scheduledSessionStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create scheduled session store: %w", err)
		}
		offchainTxStore, err = offchainTxStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
		convictionStore, err = convictionStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create conviction store: %w", err)
		}
		intentFeesStore, err = intentFeesStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create intent fees store: %w", err)
		}
		if markerStoreFactory != nil {
			markerStore, err = markerStoreFactory(db)
			if err != nil {
				return nil, fmt.Errorf("failed to create marker store: %w", err)
			}
		}
	}

	svc := &service{
		eventStore:            eventStore,
		roundStore:            roundStore,
		vtxoStore:             vtxoStore,
		markerStore:           markerStore,
		scheduledSessionStore: scheduledSessionStore,
		offchainTxStore:       offchainTxStore,
		txDecoder:             txDecoder,
		convictionStore:       convictionStore,
		intentFeesStore:       intentFeesStore,
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

func (s *service) Vtxos() domain.VtxoRepository {
	return s.vtxoStore
}

func (s *service) Markers() domain.MarkerRepository {
	return s.markerStore
}

func (s *service) ScheduledSession() domain.ScheduledSessionRepo {
	return s.scheduledSessionStore
}

func (s *service) OffchainTxs() domain.OffchainTxRepository {
	return s.offchainTxStore
}

func (s *service) Convictions() domain.ConvictionRepository {
	return s.convictionStore
}

func (s *service) Fees() domain.FeeRepository {
	return s.intentFeesStore
}

func (s *service) Close() {
	s.eventStore.Close()
	s.roundStore.Close()
	s.vtxoStore.Close()
	if s.markerStore != nil {
		s.markerStore.Close()
	}
	s.scheduledSessionStore.Close()
	s.offchainTxStore.Close()
	s.convictionStore.Close()
}

func (s *service) updateProjectionsAfterRoundEvents(events []domain.Event) {
	ctx := context.Background()
	round := domain.NewRoundFromEvents(events)

	if err := s.roundStore.AddOrUpdateRound(ctx, *round); err != nil {
		log.WithError(err).Errorf("failed to add or update round %s", round.Id)
		return
	}
	log.Debugf("added or updated round %s", round.Id)

	if !round.IsEnded() {
		return
	}

	repo := s.vtxoStore

	lastEvent := events[len(events)-1]
	if lastEvent.GetType() == domain.EventTypeBatchSwept {
		event := lastEvent.(domain.BatchSwept)
		allSweptVtxos := append(event.LeafVtxos, event.PreconfirmedVtxos...)

		// Try marker-based sweeping first if marker store is available
		if s.markerStore != nil {
			sweptCount := s.sweepVtxosWithMarkers(ctx, allSweptVtxos)
			if sweptCount > 0 {
				log.Debugf("swept %d vtxos using marker-based sweeping", sweptCount)
			}
		} else {
			// Fall back to individual VTXO sweeping
			sweptCount, err := repo.SweepVtxos(ctx, allSweptVtxos)
			if err != nil {
				log.WithError(err).Warn("failed to sweep vtxos")
			} else {
				log.Debugf("swept %d vtxos", sweptCount)
			}
		}

		if event.FullySwept {
			log.WithField("commitment_txid", round.CommitmentTxid).Debugf(
				"round %s fully swept", round.Id,
			)
		}
		return
	}

	spentVtxos := getSpentVtxoKeysFromRound(*round, s.txDecoder)
	newVtxos := getNewVtxosFromRound(round)

	if len(spentVtxos) > 0 {
		for {
			if err := repo.SettleVtxos(ctx, spentVtxos, round.CommitmentTxid); err != nil {
				log.WithError(err).Warn("failed to spend vtxos, retrying...")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Debugf("spent %d vtxos", len(spentVtxos))
			break
		}
	}

	if len(newVtxos) > 0 {
		for {
			if err := repo.AddVtxos(ctx, newVtxos); err != nil {
				log.WithError(err).Warn("failed to add new vtxos, retrying soon")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Debugf("added %d new vtxos", len(newVtxos))
			break
		}

		// Create root markers for batch VTXOs (depth 0 is always at marker boundary)
		if s.markerStore != nil {
			for _, vtxo := range newVtxos {
				// Each batch VTXO at depth 0 gets its own root marker
				markerID := vtxo.Outpoint.String()
				marker := domain.Marker{
					ID:              markerID,
					Depth:           0,
					ParentMarkerIDs: nil, // Root markers have no parents
				}
				if err := s.markerStore.AddMarker(ctx, marker); err != nil {
					log.WithError(err).
						Warnf("failed to create root marker for vtxo %s", vtxo.Outpoint.String())
					continue
				}
				if err := s.markerStore.UpdateVtxoMarkers(ctx, vtxo.Outpoint, []string{markerID}); err != nil {
					log.WithError(err).
						Warnf("failed to update markers for vtxo %s", vtxo.Outpoint.String())
				}
			}
			log.Debugf("created %d root markers for batch vtxos", len(newVtxos))
		}
	}
}

func (s *service) updateProjectionsAfterOffchainTxEvents(events []domain.Event) {
	ctx := context.Background()
	offchainTx := domain.NewOffchainTxFromEvents(events)

	if err := s.offchainTxStore.AddOrUpdateOffchainTx(ctx, offchainTx); err != nil {
		log.WithError(err).Errorf("failed to add or update offchain tx %s", offchainTx.ArkTxid)
		return
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
			return
		}
		log.Debugf("spent %d vtxos", len(spentVtxos))
	case offchainTx.IsFinalized():
		txid, _, outs, err := s.txDecoder.DecodeTx(offchainTx.ArkTx)
		if err != nil {
			log.WithError(err).Warn("failed to decode ark tx")
			return
		}

		// Get spent VTXO outpoints from checkpoint txs to calculate depth
		spentOutpoints := make([]domain.Outpoint, 0)
		for _, tx := range offchainTx.CheckpointTxs {
			_, ins, _, err := s.txDecoder.DecodeTx(tx)
			if err != nil {
				log.WithError(err).Warn("failed to decode checkpoint tx for depth calculation")
				continue
			}
			spentOutpoints = append(spentOutpoints, ins...)
		}

		// Get spent VTXOs to calculate new depth
		var newDepth uint32
		var parentMarkerIDs []string
		if len(spentOutpoints) > 0 {
			spentVtxos, err := s.vtxoStore.GetVtxos(ctx, spentOutpoints)
			if err != nil {
				log.WithError(err).Warn("failed to get spent vtxos for depth calculation")
			} else {
				// Calculate depth: max(parent depths) + 1
				var maxDepth uint32
				parentMarkerSet := make(map[string]struct{})
				for _, v := range spentVtxos {
					if v.Depth > maxDepth {
						maxDepth = v.Depth
					}
					// Collect ALL parent marker IDs for marker linking
					for _, markerID := range v.MarkerIDs {
						if markerID != "" {
							parentMarkerSet[markerID] = struct{}{}
						}
					}
				}
				newDepth = maxDepth + 1
				for id := range parentMarkerSet {
					parentMarkerIDs = append(parentMarkerIDs, id)
				}
			}
		}

		// Create marker if at boundary depth, or inherit ALL parent markers
		var markerIDs []string
		if s.markerStore != nil {
			if domain.IsAtMarkerBoundary(newDepth) {
				// Create marker ID from the first output (the ark tx id + first vtxo vout)
				newMarkerID := fmt.Sprintf("%s:marker:%d", txid, newDepth)
				marker := domain.Marker{
					ID:              newMarkerID,
					Depth:           newDepth,
					ParentMarkerIDs: parentMarkerIDs,
				}
				if err := s.markerStore.AddMarker(ctx, marker); err != nil {
					log.WithError(err).Warn("failed to create marker for chained vtxo")
					// Continue without marker - non-fatal
				} else {
					log.Debugf("created marker %s at depth %d", newMarkerID, newDepth)
					markerIDs = []string{newMarkerID}
				}
			} else if len(parentMarkerIDs) > 0 {
				// Inherit ALL markers from parents at non-boundary depth
				markerIDs = parentMarkerIDs
			}
		}

		// once the offchain tx is finalized, the user signed the checkpoint txs
		// thus, we can create the new vtxos in the db.
		newVtxos := make([]domain.Vtxo, 0, len(outs))
		for outIndex, out := range outs {
			// ignore anchors
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
				continue
			}

			isDust := script.IsSubDustScript(out.PkScript)

			newVtxos = append(newVtxos, domain.Vtxo{
				Outpoint: domain.Outpoint{
					Txid: txid,
					VOut: uint32(outIndex),
				},
				PubKey:             hex.EncodeToString(out.PkScript[2:]),
				Amount:             uint64(out.Amount),
				ExpiresAt:          offchainTx.ExpiryTimestamp,
				CommitmentTxids:    offchainTx.CommitmentTxidsList(),
				RootCommitmentTxid: offchainTx.RootCommitmentTxId,
				Preconfirmed:       true,
				CreatedAt:          offchainTx.StartingTimestamp,
				Depth:              newDepth,
				// mark the vtxo as "swept" if it is below dust limit to prevent it from being spent again in a future offchain tx
				// the only way to spend a swept vtxo is by collecting enough dust to cover the minSettlementVtxoAmount and then settle.
				// because sub-dust vtxos are using OP_RETURN output script, they can't be unilaterally exited.
				Swept: isDust,
			})
		}

		if err := s.vtxoStore.AddVtxos(ctx, newVtxos); err != nil {
			log.WithError(err).Warn("failed to add vtxos")
			return
		}
		log.Debugf("added %d vtxos at depth %d", len(newVtxos), newDepth)

		// Update markers for VTXOs (new marker at boundary, inherited at non-boundary)
		if len(markerIDs) > 0 && s.markerStore != nil {
			for _, vtxo := range newVtxos {
				if err := s.markerStore.UpdateVtxoMarkers(ctx, vtxo.Outpoint, markerIDs); err != nil {
					log.WithError(err).
						Warnf("failed to update markers for vtxo %s", vtxo.Outpoint.String())
				}
			}
		}
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

func getNewVtxosFromRound(round *domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, node := range tree.FlatTxTree(round.VtxoTree).Leaves() {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			// ignore anchors
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
				continue
			}

			vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				log.WithError(err).Warn("failed to parse vtxo tap key")
				continue
			}

			vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))
			vtxos = append(vtxos, domain.Vtxo{
				Outpoint:           domain.Outpoint{Txid: tx.UnsignedTx.TxID(), VOut: uint32(i)},
				PubKey:             vtxoPubkey,
				Amount:             uint64(out.Value),
				CommitmentTxids:    []string{round.CommitmentTxid},
				RootCommitmentTxid: round.CommitmentTxid,
				CreatedAt:          round.EndingTimestamp,
				ExpiresAt:          round.ExpiryTimestamp(),
			})
		}
	}
	return vtxos
}

// sweepVtxosWithMarkers performs marker-based sweeping for VTXOs.
// It groups VTXOs by their marker, sweeps each marker, then bulk-updates all VTXOs.
// Returns the total count of VTXOs swept.
func (s *service) sweepVtxosWithMarkers(
	ctx context.Context,
	vtxoOutpoints []domain.Outpoint,
) int64 {
	if len(vtxoOutpoints) == 0 {
		return 0
	}

	// Get VTXOs to find their markers
	vtxos, err := s.vtxoStore.GetVtxos(ctx, vtxoOutpoints)
	if err != nil {
		log.WithError(err).Warn("failed to get vtxos for marker-based sweep")
		// Fall back to individual sweep
		count, _ := s.vtxoStore.SweepVtxos(ctx, vtxoOutpoints)
		return int64(count)
	}

	// Group VTXOs by their first marker ID (for sweep optimization)
	// We use first marker to avoid duplicate sweeps when vtxo has multiple markers
	markerVtxos := make(map[string][]domain.Outpoint)
	noMarkerVtxos := make([]domain.Outpoint, 0)

	for _, vtxo := range vtxos {
		if len(vtxo.MarkerIDs) > 0 {
			// Use first marker ID for grouping
			markerVtxos[vtxo.MarkerIDs[0]] = append(markerVtxos[vtxo.MarkerIDs[0]], vtxo.Outpoint)
		} else {
			noMarkerVtxos = append(noMarkerVtxos, vtxo.Outpoint)
		}
	}

	var totalSwept int64
	sweptAt := time.Now().Unix()

	// Sweep each marker
	for markerID := range markerVtxos {
		// Mark the marker as swept
		if err := s.markerStore.SweepMarker(ctx, markerID, sweptAt); err != nil {
			log.WithError(err).Warnf("failed to sweep marker %s", markerID)
			// Fall back to individual sweep for this marker's VTXOs
			count, _ := s.vtxoStore.SweepVtxos(ctx, markerVtxos[markerID])
			totalSwept += int64(count)
			continue
		}

		// Bulk sweep all VTXOs with this marker
		count, err := s.markerStore.SweepVtxosByMarker(ctx, markerID)
		if err != nil {
			log.WithError(err).Warnf("failed to bulk sweep vtxos for marker %s", markerID)
			// Fall back to individual sweep
			count, _ := s.vtxoStore.SweepVtxos(ctx, markerVtxos[markerID])
			totalSwept += int64(count)
			continue
		}
		totalSwept += count
		log.Debugf("swept marker %s with %d vtxos", markerID, count)
	}

	// Sweep VTXOs without markers individually
	if len(noMarkerVtxos) > 0 {
		count, err := s.vtxoStore.SweepVtxos(ctx, noMarkerVtxos)
		if err != nil {
			log.WithError(err).Warn("failed to sweep vtxos without markers")
		}
		totalSwept += int64(count)
	}

	return totalSwept
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
