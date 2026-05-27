// THROWAWAY: synthetic round/vtxo seeder for measuring restoreWatchingVtxos
// at scale. Plan:
//
//	/home/bob/.claude/plans/theres-likely-improvmeents-in-abstract-hummingbird.md
//
// Delete this binary once we've gathered the data we need.
//
// The seeder inserts N rounds × M vtxos directly through the same domain
// repos arkd uses. Each round is marked sweepable (ended, not failed, not
// swept) with one synthetic 'tree' tx so SelectSweepableRounds returns it,
// and each vtxo has a fresh schnorr x-only pubkey under RootCommitmentTxid.
//
// Usage (sqlite/badger, mirrors arkd's regtest setup):
//
//	ARKD_DB_TYPE=sqlite ARKD_EVENT_DB_TYPE=badger \
//	ARKD_DATADIR=./data/regtest/arkd \
//	go run ./cmd/arkd-bench-seed -rounds 1000 -vtxos-per-round 10
//
// Usage (postgres, mirrors arkd's dev setup):
//
//	ARKD_DB_TYPE=postgres ARKD_EVENT_DB_TYPE=postgres \
//	ARKD_PG_DB_URL=postgresql://... ARKD_PG_EVENT_DB_URL=postgresql://... \
//	go run ./cmd/arkd-bench-seed -rounds 1000 -vtxos-per-round 10
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		rounds        int
		vtxosPerRound int
		batchSize     int
	)
	flag.IntVar(&rounds, "rounds", 100, "number of sweepable rounds to insert")
	flag.IntVar(&vtxosPerRound, "vtxos-per-round", 10, "number of vtxos per round")
	flag.IntVar(&batchSize, "vtxo-batch", 200, "AddVtxos batch size")
	flag.Parse()

	cfg := loadDBConfig()

	svc, err := db.NewService(cfg.serviceConfig, nil)
	if err != nil {
		log.Fatalf("open db: %s", err)
	}
	defer svc.Close()

	ctx := context.Background()
	roundRepo := svc.Rounds()
	vtxoRepo := svc.Vtxos()

	log.Infof("seeding %d rounds × %d vtxos = %d scripts (db_type=%s)",
		rounds, vtxosPerRound, rounds*vtxosPerRound, cfg.dbType)

	start := time.Now()
	for r := 0; r < rounds; r++ {
		now := time.Now().Unix()
		commitmentTxid := randomHex(32)
		round := domain.Round{
			Id:                uuid.New().String(),
			StartingTimestamp: now - 60,
			EndingTimestamp:   now,
			Stage: domain.Stage{
				Code:   int(domain.RoundFinalizationStage),
				Ended:  true,
				Failed: false,
			},
			Intents:            map[string]domain.Intent{},
			CommitmentTxid:     commitmentTxid,
			CommitmentTx:       "synthetic-bench-tx",
			ConnectorAddress:   "",
			Version:            1,
			Swept:              false,
			VtxoTreeExpiration: 100,
			VtxoTree: arktree.FlatTxTree{
				arktree.TxTreeNode{
					Txid: randomHex(32),
					Tx:   "synthetic-bench-tree-tx",
				},
			},
		}
		if err := roundRepo.AddOrUpdateRound(ctx, round); err != nil {
			log.Fatalf("AddOrUpdateRound[%d]: %s", r, err)
		}

		vtxos := make([]domain.Vtxo, 0, vtxosPerRound)
		for v := 0; v < vtxosPerRound; v++ {
			vtxos = append(vtxos, domain.Vtxo{
				Outpoint:           domain.Outpoint{Txid: randomHex(32), VOut: uint32(v)},
				Amount:             1000,
				PubKey:             randomXOnlyPubKey(),
				CommitmentTxids:    []string{commitmentTxid},
				RootCommitmentTxid: commitmentTxid,
				CreatedAt:          now,
				ExpiresAt:          now + 3600,
			})

			if len(vtxos) >= batchSize {
				if err := vtxoRepo.AddVtxos(ctx, vtxos); err != nil {
					log.Fatalf("AddVtxos round=%d: %s", r, err)
				}
				vtxos = vtxos[:0]
			}
		}
		if len(vtxos) > 0 {
			if err := vtxoRepo.AddVtxos(ctx, vtxos); err != nil {
				log.Fatalf("AddVtxos round=%d final: %s", r, err)
			}
		}

		if (r+1)%100 == 0 {
			log.Infof("inserted %d/%d rounds (%.0f rounds/s)",
				r+1, rounds, float64(r+1)/time.Since(start).Seconds())
		}
	}

	log.Infof("done: %d rounds × %d vtxos in %s", rounds, vtxosPerRound, time.Since(start))

	swept, err := roundRepo.GetSweepableRounds(ctx)
	if err != nil {
		log.Fatalf("GetSweepableRounds: %s", err)
	}
	log.Infof("GetSweepableRounds returns %d rows", len(swept))
}

type dbConfig struct {
	dbType        string
	serviceConfig db.ServiceConfig
}

func loadDBConfig() dbConfig {
	dbType := getenv("ARKD_DB_TYPE", "sqlite")
	eventDbType := getenv("ARKD_EVENT_DB_TYPE", "badger")
	datadir := getenv("ARKD_DATADIR", "./data/regtest/arkd")
	dbDir := filepath.Join(datadir, "db")

	logger := log.New()

	var eventStoreCfg []interface{}
	switch eventDbType {
	case "badger":
		eventStoreCfg = []interface{}{dbDir, logger}
	case "postgres":
		eventStoreCfg = []interface{}{
			mustEnv("ARKD_PG_EVENT_DB_URL"),
			boolEnv("ARKD_PG_DB_AUTOCREATE", false),
			pgdb.ConnectionConfig{
				MaxOpenConn:         intEnv("ARKD_PG_DB_MAX_OPEN_CONN", 10),
				MaxIdleConn:         intEnv("ARKD_PG_DB_MAX_IDLE_CONN", 10),
				ConnMaxIdleTimeMins: int64(intEnv("ARKD_PG_DB_CONN_MAX_IDLE_MINS", 5)),
				ConnMaxLifetimeMins: int64(intEnv("ARKD_PG_DB_CONN_MAX_LIFE_MINS", 30)),
			},
		}
	default:
		log.Fatalf("unsupported ARKD_EVENT_DB_TYPE=%q", eventDbType)
	}

	var dataStoreCfg []interface{}
	switch dbType {
	case "badger":
		dataStoreCfg = []interface{}{dbDir, logger}
	case "sqlite":
		dataStoreCfg = []interface{}{dbDir}
	case "postgres":
		dataStoreCfg = []interface{}{
			mustEnv("ARKD_PG_DB_URL"),
			boolEnv("ARKD_PG_DB_AUTOCREATE", false),
			pgdb.ConnectionConfig{
				MaxOpenConn:         intEnv("ARKD_PG_DB_MAX_OPEN_CONN", 10),
				MaxIdleConn:         intEnv("ARKD_PG_DB_MAX_IDLE_CONN", 10),
				ConnMaxIdleTimeMins: int64(intEnv("ARKD_PG_DB_CONN_MAX_IDLE_MINS", 5)),
				ConnMaxLifetimeMins: int64(intEnv("ARKD_PG_DB_CONN_MAX_LIFE_MINS", 30)),
			},
		}
	default:
		log.Fatalf("unsupported ARKD_DB_TYPE=%q", dbType)
	}

	return dbConfig{
		dbType: dbType,
		serviceConfig: db.ServiceConfig{
			EventStoreType:   eventDbType,
			DataStoreType:    dbType,
			EventStoreConfig: eventStoreCfg,
			DataStoreConfig:  dataStoreCfg,
		},
	}
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("rand: %s", err)
	}
	return hex.EncodeToString(buf)
}

func randomXOnlyPubKey() string {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		log.Fatalf("priv: %s", err)
	}
	return hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing required env %s", k)
	}
	return v
}

func intEnv(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	var out int
	if _, err := fmt.Sscanf(v, "%d", &out); err != nil {
		log.Fatalf("invalid int env %s=%q", k, v)
	}
	return out
}

func boolEnv(k string, def bool) bool {
	v := os.Getenv(k)
	switch v {
	case "":
		return def
	case "true", "TRUE", "1":
		return true
	case "false", "FALSE", "0":
		return false
	}
	log.Fatalf("invalid bool env %s=%q", k, v)
	return def
}
