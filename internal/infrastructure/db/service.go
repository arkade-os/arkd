package db

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	log "github.com/sirupsen/logrus"
)

//go:embed postgres/migration/*
var pgMigration embed.FS

var (
	eventStoreTypes = map[string]func(...interface{}) (domain.EventRepository, error){
		"postgres": pgdb.NewEventRepository,
	}
	roundStoreTypes = map[string]func(...interface{}) (domain.RoundRepository, error){
		"postgres": pgdb.NewRoundRepository,
	}
	vtxoStoreTypes = map[string]func(...interface{}) (domain.VtxoRepository, error){
		"postgres": pgdb.NewVtxoRepository,
	}
	utxoStoreTypes = map[string]func(...interface{}) (domain.UtxoRepository, error){
		"postgres": pgdb.NewUtxoRepository,
	}
	offchainTxStoreTypes = map[string]func(...interface{}) (domain.OffchainTxRepository, error){
		"postgres": pgdb.NewOffchainTxRepository,
	}
	convictionStoreTypes = map[string]func(...interface{}) (domain.ConvictionRepository, error){
		"postgres": pgdb.NewConvictionRepository,
	}
	assetStoreTypes = map[string]func(...interface{}) (domain.AssetRepository, error){
		"postgres": pgdb.NewAssetRepository,
	}
	settingsStoreTypes = map[string]func(...interface{}) (domain.SettingsRepository, error){
		"postgres": pgdb.NewSettingsRepository,
	}
	markerStoreTypes = map[string]func(...interface{}) (domain.MarkerRepository, error){
		"postgres": pgdb.NewMarkerRepository,
	}
)

const (
	// projectionsShutdownTimeout bounds how long Close waits for in-flight
	// projection updates. Long enough for the store writes of one update to
	// finish, short enough that a wedged update cannot hold the process open.
	projectionsShutdownTimeout = 30 * time.Second
)

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
	utxoStore              domain.UtxoRepository
	markerStore            domain.MarkerRepository
	offchainTxStore        domain.OffchainTxRepository
	convictionStore        domain.ConvictionRepository
	assetStore             domain.AssetRepository
	settingsStore          domain.SettingsRepository
	txDecoder              ports.TxDecoder
	batchEventHandler      *updateHandler[domain.Round]
	offchainTxEventHandler *updateHandler[domain.OffchainTx]
	onchainTxEventHandler  *updateHandler[domain.OnchainTx]

	// projections counts the updates in flight, the subscriber dispatches they
	// spawn and Reconcile, so Close can wait for them instead of closing a store one
	// of them is still writing to.
	projections sync.WaitGroup
	closeOnce   sync.Once
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
	utxoStoreFactory, ok := utxoStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("utxo store type not supported")
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
	var utxoStore domain.UtxoRepository
	var markerStore domain.MarkerRepository
	var offchainTxStore domain.OffchainTxRepository
	var convictionStore domain.ConvictionRepository
	var assetStore domain.AssetRepository
	var settingsStore domain.SettingsRepository

	switch config.EventStoreType {
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
		utxoStore, err = utxoStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open utxo store: %s", err)
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
		utxoStore:              utxoStore,
		markerStore:            markerStore,
		offchainTxStore:        offchainTxStore,
		txDecoder:              txDecoder,
		convictionStore:        convictionStore,
		assetStore:             assetStore,
		settingsStore:          settingsStore,
		batchEventHandler:      newUpdateHandler[domain.Round](),
		offchainTxEventHandler: newUpdateHandler[domain.OffchainTx](),
		onchainTxEventHandler:  newUpdateHandler[domain.OnchainTx](),
	}

	// Register handlers that take care of keeping the projection store up-to-date.
	if txDecoder != nil {
		eventStore.RegisterEventsHandler(domain.RoundTopic, svc.updateProjectionsAfterRoundEvents)
		eventStore.RegisterEventsHandler(
			domain.OffchainTxTopic, svc.updateProjectionsAfterOffchainTxEvents,
		)
		eventStore.RegisterEventsHandler(
			domain.OnchainTxTopic, svc.updateProjectionsAfterOnchainTxEvents,
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

func (s *service) CosignedUtxos() domain.UtxoRepository {
	return s.utxoStore
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

func (s *service) RegisterOnchainTxUpdateHandler(handler func(data domain.OnchainTx)) {
	s.onchainTxEventHandler.set(handler)
}

func (s *service) RegisterSettingsUpdateHandler(handler func(domain.Settings, []string)) {
	s.settingsStore.RegisterUpdatesHandler(handler)
}

// Reconcile takes care of repairing the projection db in case any event in the past session
// failed to be processed. Close waits for Reconcile to finish in case it's called while the
// latter is running to not leave any update in mid-state.
func (s *service) Reconcile() error {
	s.projections.Add(1)
	defer s.projections.Done()
	return s.reconcileProjections()
}

// Close waits for in flight operation, then closes the stores, so
// no update is cut off between its writes.
func (s *service) Close() {
	s.closeOnce.Do(s.close)
}

func (s *service) close() {
	if !s.drainProjections(projectionsShutdownTimeout) {
		log.Warnf(
			"projection updates still running after %s, closing stores anyway",
			projectionsShutdownTimeout,
		)
	}

	s.roundStore.Close()
	s.vtxoStore.Close()
	s.markerStore.Close()
	s.offchainTxStore.Close()
	s.convictionStore.Close()
	s.assetStore.Close()
	s.settingsStore.Close()
}

// goTracked runs fn in a goroutine Close waits for. Subscriber dispatches go
// through here because the caller closes the channel they publish to right
// after Close returns.
func (s *service) goTracked(fn func()) {
	s.projections.Add(1)
	go func() {
		defer s.projections.Done()
		fn()
	}()
}

// drainProjections closes the event store, which stops dispatching events and
// waits for the handlers already dispatched, then waits for the projection work
// still in flight. It reports whether both finished in time. On a timeout the
// goroutine it started stays parked until they do or the process exits; it
// holds nothing, so that is not a leak.
func (s *service) drainProjections(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.eventStore.Close()
		s.projections.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// reconcileProjections repairs projections a previous run left half written.
// Reconcile runs it before the application produces events, so it sees a quiescent
// store. A failing repair is logged and cannot stop the node from starting.
func (s *service) reconcileProjections() error {
	return s.ensureSweptVtxos()
}

// ensureSweptVtxos marks the vtxos of fully swept batches that are missing a
// swept mark. A sweep is recorded with two writes that are not one transaction,
// the round then the vtxo outpoints, so an interruption between them leaves a
// batch marked swept whose vtxos still look unswept. The swept insert ignores
// duplicates, so a consistent store costs two reads and nothing else.
func (s *service) ensureSweptVtxos() error {
	ctx := context.Background()
	commitmentTxids, err := s.roundStore.GetSweptRounds(ctx)
	if err != nil {
		return fmt.Errorf("failed to get swept batches: %w", err)
	}
	if len(commitmentTxids) == 0 {
		return nil
	}

	// One read across every swept batch, with the predicate the sweeper uses
	// to pick what a batch sweep covers, so reconciliation marks exactly what
	// the sweep would have.
	outpoints, err := s.vtxoStore.GetSweepableVtxosByCommitmentTxids(ctx, commitmentTxids)
	if err != nil {
		return fmt.Errorf(
			"failed to read the unswept vtxos of %d swept batches: %w",
			len(commitmentTxids), err,
		)
	}
	if len(outpoints) == 0 {
		return nil
	}

	// sweptAt is the time of the repair, not of the original sweep, which the
	// projection no longer knows.
	if err := s.markerStore.SweepVtxoOutpoints(ctx, outpoints, time.Now().Unix()); err != nil {
		return fmt.Errorf("failed to sweep %d vtxos of swept batches: %w", len(outpoints), err)
	}
	log.Debugf("reconciled %d vtxos missed to be marked as swept", len(outpoints))
	return nil
}

// updateProjectionsAfterRoundEvents updates the projections as soon as round events are recorded
// to the event db. It makes use of a background context and Close waits for it to complete before
// closing the stores.
func (s *service) updateProjectionsAfterRoundEvents(events []domain.Event) {
	s.projections.Add(1)
	defer s.projections.Done()

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

		// We keep track of boarding utxos as cosigned utxos.
		boardingUtxos, err := getBoardingUtxosFromRound(*round, s.txDecoder)
		if err != nil {
			log.WithError(err).Warn(
				"failed to extract boarding utxos, aborting round projection " +
					"(update not dispatched, not retried)",
			)
			return false
		}
		if len(boardingUtxos) > 0 {
			if err := s.utxoStore.AddUtxos(ctx, boardingUtxos, ""); err != nil {
				log.WithError(err).Warn(
					"failed to add boarding utxos, aborting round projection " +
						"(update not dispatched, not retried)",
				)
				return false
			}
			log.Debugf("added %d boarding utxos", len(boardingUtxos))
		}
		return true
	}

	dispatch := updateFn()
	if dispatch {
		s.goTracked(func() { s.batchEventHandler.dispatch(*round) })
	}
}

// updateProjectionsAfterOffchainTxEvents updates the projections as soon as offchain tx events are
// recorded to the event db. It makes use of a background context and Close waits for it to
// complete before closing the stores.
func (s *service) updateProjectionsAfterOffchainTxEvents(events []domain.Event) {
	s.projections.Add(1)
	defer s.projections.Done()

	ctx := context.Background()
	offchainTx := domain.NewOffchainTxFromEvents(events)
	updateFn := func() bool {
		if err := s.offchainTxStore.AddOrUpdateOffchainTx(ctx, offchainTx); err != nil {
			log.WithError(err).Errorf("failed to add or update offchain tx %s", offchainTx.ArkTxid)
			return false
		}
		log.Debugf("added or updated offchain tx %s", offchainTx.ArkTxid)

		switch {
		case offchainTx.IsAccepted(), offchainTx.IsFinalized():
			spentVtxos := make(map[domain.Outpoint]string)
			for _, tx := range offchainTx.CheckpointTxs {
				txid, ins, _, err := s.txDecoder.DecodeTx(tx)
				if err != nil {
					log.WithError(err).Warn("failed to decode checkpoint tx")
					continue
				}
				for _, in := range ins {
					spentVtxos[in.Outpoint] = txid
				}
			}

			// as soon as the checkpoint txs are signed by the signer,
			// we must mark the vtxos as spent to prevent double spending.
			if err := s.vtxoStore.SpendVtxos(ctx, spentVtxos, offchainTx.ArkTxid); err != nil {
				log.WithError(err).Warn("failed to spend vtxos")
				return false
			}
			log.Debugf("spent %d vtxos", len(spentVtxos))
			if offchainTx.IsAccepted() {
				return true
			}

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
					}); err != nil {
						// Sub-dust vtxos can't be spent offchain (OP_RETURN outputs):
						// they can only be collected until they sum to a non-sub-dust
						// amount (> 330 sats) and settled into a batch. We mark them
						// swept so they fall in the same bucket as expired (swept)
						// vtxos, the only other vtxos with that same "not spendable
						// offchain" trait. If the dust marker can't be persisted the
						// vtxo would instead look like a normal spendable vtxo
						// (postgres has no swept column), so we abort the
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
					// Postgres has no swept column, so this is persisted via the dust
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
		s.goTracked(func() { s.offchainTxEventHandler.dispatch(*offchainTx) })
	}
}

// updateProjectionsAfterOnchainTxEvents updates the projections as soon as onchain tx events are
// recorded to the event db. It makes use of a background context and Close waits for it to
// complete before closing the stores.
func (s *service) updateProjectionsAfterOnchainTxEvents(events []domain.Event) {
	s.projections.Add(1)
	defer s.projections.Done()

	ctx := context.Background()
	onchainTx := domain.NewOnchainTxFromEvents(events)
	updateFn := func() bool {
		switch {
		case onchainTx.IsBroadcasted():
			utxos, err := getUtxosFromOnchainTx(*onchainTx, s.txDecoder)
			if err != nil {
				log.WithError(err).Warnf(
					"failed to get cosigned utxos from onchain tx %s", onchainTx.Txid,
				)
				return false
			}
			// An unrolled vtxo is stored as a pointer to its vtxo record, with no pubkey and
			// amount, the utxo table refuses a row duplicating a vtxo.
			outpoints := make([]domain.Outpoint, 0, len(utxos))
			for _, utxo := range utxos {
				outpoints = append(outpoints, utxo.Outpoint)
			}
			vtxos, err := s.vtxoStore.GetVtxos(ctx, outpoints)
			if err != nil {
				log.WithError(err).Warnf(
					"failed to get vtxos spent by onchain tx %s", onchainTx.Txid,
				)
				return false
			}
			for _, vtxo := range vtxos {
				for i := range utxos {
					if utxos[i].Outpoint == vtxo.Outpoint {
						utxos[i].PubKey, utxos[i].Amount = "", 0
					}
				}
			}
			if err := s.utxoStore.AddUtxos(ctx, utxos, onchainTx.Tx); err != nil {
				log.WithError(err).Warn("failed to add cosigned utxos")
				return false
			}
			log.Debugf("added %d cosigned utxos from onchain tx %s", len(utxos), onchainTx.Txid)
		case onchainTx.IsConfirmed():
			utxos, err := getUtxosFromOnchainTx(*onchainTx, s.txDecoder)
			if err != nil {
				log.WithError(err).Warnf(
					"failed to get cosigned utxos from onchain tx %s", onchainTx.Txid,
				)
				return false
			}

			for i := range utxos {
				utxos[i].Spend = domain.UtxoSpend{
					Txid:              onchainTx.Txid,
					ConfirmedAtTime:   onchainTx.ConfirmedAtTime,
					ConfirmedAtHeight: onchainTx.ConfirmedAtHeight,
				}
			}
			if err := s.utxoStore.UpdateUtxos(ctx, utxos); err != nil {
				log.WithError(err).Warnf(
					"failed to confirm spend of cosigned utxos from onchain tx %s", onchainTx.Txid,
				)
				return false
			}
			log.Debugf(
				"confirmed spend of %d cosigned utxos from onchain tx %s",
				len(utxos), onchainTx.Txid,
			)
		}
		return true
	}

	dispatch := updateFn()
	if dispatch {
		s.goTracked(func() { s.onchainTxEventHandler.dispatch(*onchainTx) })
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
			forfeitInputs[in.Outpoint] = forfeitTx.Txid
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

// getBoardingUtxosFromRound returns the boarding utxos consumed by the round, to be recorded
// as cosigned utxos spent by the commitment tx.
//
// Every intent proves ownership of its inputs with a BIP322 proof: inputs [1:] of the proof
// are the claimed outpoints, each with its prevout, while intent.Inputs are the ones that were
// registered as vtxos, unrolled included. Whatever is claimed by the proof and is not a vtxo
// is a boarding utxo, the same rule used at registration time.
func getBoardingUtxosFromRound(
	round domain.Round, txDecoder ports.TxDecoder,
) ([]domain.Utxo, error) {
	utxos := make([]domain.Utxo, 0)
	for _, intent := range round.Intents {
		vtxos := make(map[domain.Outpoint]struct{}, len(intent.Inputs))
		for _, vtxo := range intent.Inputs {
			vtxos[vtxo.Outpoint] = struct{}{}
		}

		_, ins, _, err := txDecoder.DecodeTx(intent.Proof)
		if err != nil {
			return nil, fmt.Errorf("failed to decode intent %s: %w", intent.Id, err)
		}
		// An intent proof must have at least two inputs as per BIP322.
		if len(ins) < 2 {
			return nil, fmt.Errorf("malformed proof of intent %s: missing inputs", intent.Id)
		}

		// Skip input 0, the BIP322 message input.
		for _, in := range ins[1:] {
			if _, isVtxo := vtxos[in.Outpoint]; isVtxo {
				continue
			}
			if in.Prevout == nil {
				return nil, fmt.Errorf(
					"boarding input %s of intent %s misses prevout", in.Outpoint, intent.Id,
				)
			}
			if !txscript.IsPayToTaproot(in.Prevout.PkScript) {
				return nil, fmt.Errorf(
					"boarding input %s of intent %s is not a taproot output",
					in.Outpoint, intent.Id,
				)
			}
			utxos = append(utxos, domain.Utxo{
				Outpoint:  in.Outpoint,
				Amount:    in.Prevout.Amount,
				PubKey:    hex.EncodeToString(in.Prevout.PkScript[2:]), // drop 2 opcodes bytes
				Spend:     domain.UtxoSpend{Txid: round.CommitmentTxid},
				CreatedAt: round.EndingTimestamp,
			})
		}
	}
	return utxos, nil
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
		if len(ast.Outputs) == 0 {
			continue
		}

		assetId := ""

		// the id of an issuance derives from the group index alone, so it is identical for
		// every output of the group and must be collected once per group.
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

		for _, out := range ast.Outputs {
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
	default:
		return fmt.Errorf("unsupported db type for settings seed: %s", dbType)
	}
}

func getUtxosFromOnchainTx(
	onchainTx domain.OnchainTx, txDecoder ports.TxDecoder,
) ([]domain.Utxo, error) {
	_, ins, _, err := txDecoder.DecodeTx(onchainTx.Tx)
	if err != nil {
		return nil, err
	}

	utxos := make([]domain.Utxo, 0, len(onchainTx.SignedInputs))
	for _, in := range ins {
		if _, ok := onchainTx.SignedInputs[in.String()]; !ok {
			continue
		}
		if in.Prevout == nil {
			return nil, fmt.Errorf(
				"signed input %s of onchain tx %s misses prevout", in.Outpoint, onchainTx.Txid,
			)
		}
		utxos = append(utxos, domain.Utxo{
			Outpoint:  in.Outpoint,
			Amount:    in.Prevout.Amount,
			PubKey:    hex.EncodeToString(in.Prevout.PkScript[2:]), // drop 2 opcodes bytes
			CreatedAt: onchainTx.BroadcastedAt,
			Spend:     domain.UtxoSpend{Txid: onchainTx.Txid},
		})
	}
	return utxos, nil
}
