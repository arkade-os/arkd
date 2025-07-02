package db

import (
	"bytes"
	"context"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	badgerdb "github.com/ark-network/ark/server/internal/infrastructure/db/badger"
	pgdb "github.com/ark-network/ark/server/internal/infrastructure/db/postgres"
	sqlitedb "github.com/ark-network/ark/server/internal/infrastructure/db/sqlite"
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
	marketHourStoreTypes = map[string]func(...interface{}) (domain.MarketHourRepo, error){
		"badger":   badgerdb.NewMarketHourRepository,
		"sqlite":   sqlitedb.NewMarketHourRepository,
		"postgres": pgdb.NewMarketHourRepository,
	}
	offchainTxStoreTypes = map[string]func(...interface{}) (domain.OffchainTxRepository, error){
		"badger":   newBadgerOffchainTxRepository,
		"sqlite":   sqlitedb.NewOffchainTxRepository,
		"postgres": pgdb.NewOffchainTxRepository,
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
	eventStore      domain.EventRepository
	roundStore      domain.RoundRepository
	vtxoStore       domain.VtxoRepository
	marketHourStore domain.MarketHourRepo
	offchainTxStore domain.OffchainTxRepository

	txDecoder ports.TxDecoder
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
	marketHourStoreFactory, ok := marketHourStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}
	offchainTxStoreFactory, ok := offchainTxStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}

	var eventStore domain.EventRepository
	var roundStore domain.RoundRepository
	var vtxoStore domain.VtxoRepository
	var marketHourStore domain.MarketHourRepo
	var offchainTxStore domain.OffchainTxRepository
	var err error

	switch config.EventStoreType {
	case "badger":
		eventStore, err = eventStoreFactory(config.EventStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open event store: %s", err)
		}
	case "postgres":
		if len(config.DataStoreConfig) != 1 {
			return nil, fmt.Errorf("invalid data store config for postgres")
		}

		dsn, ok := config.DataStoreConfig[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid DSN for postgres")
		}

		db, err := pgdb.OpenDb(dsn)
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
		marketHourStore, err = marketHourStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create market hour store: %w", err)
		}
		offchainTxStore, err = offchainTxStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
	case "postgres":
		if len(config.DataStoreConfig) != 1 {
			return nil, fmt.Errorf("invalid data store config for postgres")
		}

		dsn, ok := config.DataStoreConfig[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid DSN for postgres")
		}

		db, err := pgdb.OpenDb(dsn)
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

		marketHourStore, err = marketHourStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create market hour store: %w", err)
		}

		offchainTxStore, err = offchainTxStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
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
		marketHourStore, err = marketHourStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create market hour store: %w", err)
		}
		offchainTxStore, err = offchainTxStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain tx store: %w", err)
		}
	}

	svc := &service{
		eventStore:      eventStore,
		roundStore:      roundStore,
		vtxoStore:       vtxoStore,
		marketHourStore: marketHourStore,
		offchainTxStore: offchainTxStore,
		txDecoder:       txDecoder,
	}

	// Register handlers that take care of keeping the projection store up-to-date.
	if txDecoder != nil {
		eventStore.RegisterEventsHandler(domain.RoundTopic, svc.updateProjectionsAfterRoundEvents)
		eventStore.RegisterEventsHandler(domain.OffchainTxTopic, svc.updateProjectionsAfterOffchainTxEvents)
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

func (s *service) MarketHourRepo() domain.MarketHourRepo {
	return s.marketHourStore
}

func (s *service) OffchainTxs() domain.OffchainTxRepository {
	return s.offchainTxStore
}

func (s *service) Close() {
	s.eventStore.Close()
	s.roundStore.Close()
	s.vtxoStore.Close()
	s.marketHourStore.Close()
	s.offchainTxStore.Close()
}

func (s *service) updateProjectionsAfterRoundEvents(events []domain.Event) {
	ctx := context.Background()
	round := domain.NewRoundFromEvents(events)

	if err := s.roundStore.AddOrUpdateRound(ctx, *round); err != nil {
		log.WithError(err).Fatalf("failed to add or update round %s", round.Id)
	}
	log.Debugf("added or updated round %s", round.Id)

	if !round.IsEnded() {
		return
	}

	repo := s.vtxoStore

	lastEvent := events[len(events)-1]
	if lastEvent.GetType() == domain.EventTypeBatchSwept {
		event := lastEvent.(domain.BatchSwept)
		if err := repo.SweepVtxos(ctx, event.Vtxos); err != nil {
			log.WithError(err).Warn("failed to sweep vtxos")
		}
		if event.FullySwept {
			log.Debugf("round %s fully swept", round.Id)
		}
		log.Debugf("swept %d vtxos", len(event.Vtxos))
		return
	}

	spentVtxos := getSpentVtxoKeysFromRound(*round, s.txDecoder)
	newVtxos := getNewVtxosFromRound(round)

	if len(spentVtxos) > 0 {
		for {
			if err := repo.SettleVtxos(ctx, spentVtxos, round.Txid); err != nil {
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
	}
}

func (s *service) updateProjectionsAfterOffchainTxEvents(events []domain.Event) {
	ctx := context.Background()
	offchainTx := domain.NewOffchainTxFromEvents(events)

	if err := s.offchainTxStore.AddOrUpdateOffchainTx(ctx, offchainTx); err != nil {
		log.WithError(err).Fatalf("failed to add or update offchain tx %s", offchainTx.VirtualTxid)
	}
	log.Debugf("added or updated offchain tx %s", offchainTx.VirtualTxid)

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

		// as soon as the checkpoint txs are signed by the server,
		// we must mark the vtxos as spent to prevent double spending.
		if err := s.vtxoStore.SpendVtxos(ctx, spentVtxos, offchainTx.VirtualTxid); err != nil {
			log.WithError(err).Warn("failed to spend vtxos")
			return
		}
		log.Debugf("spent %d vtxos", len(spentVtxos))
	case offchainTx.IsFinalized():
		txid, _, outs, err := s.txDecoder.DecodeTx(offchainTx.VirtualTx)
		if err != nil {
			log.WithError(err).Warn("failed to decode virtual tx")
			return
		}

		// once the offchain tx is finalized, the user signed the checkpoint txs
		// thus, we can create the new vtxos in the db.
		newVtxos := make([]domain.Vtxo, 0, len(outs))
		for outIndex, out := range outs {
			// ignore anchors
			if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
				continue
			}

			isDust := common.IsSubDustScript(out.PkScript)

			newVtxos = append(newVtxos, domain.Vtxo{
				Outpoint: domain.Outpoint{
					Txid: txid,
					VOut: uint32(outIndex),
				},
				PubKey:             hex.EncodeToString(out.PkScript[2:]),
				Amount:             uint64(out.Amount),
				ExpireAt:           offchainTx.ExpiryTimestamp,
				CommitmentTxids:    offchainTx.CommitmentTxidsList(),
				RootCommitmentTxid: offchainTx.RootCommitmentTxId,
				Preconfirmed:       true,
				CreatedAt:          offchainTx.EndingTimestamp,
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
		log.Debugf("added %d vtxos", len(newVtxos))
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
	for _, request := range round.TxRequests {
		for _, vtxo := range request.Inputs {
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
	for _, chunk := range tree.TxGraphChunkList(round.VtxoTree).Leaves() {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(chunk.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			// ignore anchors
			if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
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
				CommitmentTxids:    []string{round.Txid},
				RootCommitmentTxid: round.Txid,
				CreatedAt:          round.EndingTimestamp,
				ExpireAt:           round.ExpiryTimestamp(),
			})
		}
	}
	return vtxos
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
