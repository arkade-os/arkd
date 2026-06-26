// Command arkd-forfeit-backfill signs the operator's half of forfeit transactions
// that were persisted before arkd started signing forfeit txs at collection time.
//
// It connects to the same database and signer as arkd (via the standard arkd
// configuration / environment), so the arkd-wallet signer must be running and
// unlocked. It scans every unswept forfeited vtxo, signs the operator's half of
// its forfeit tx when missing, and persists the result. It is safe to run
// repeatedly: forfeit txs that already carry the operator signature are skipped.
package main

import (
	"context"
	"os"

	"github.com/arkade-os/arkd/internal/backfill"
	"github.com/arkade-os/arkd/internal/config"
	log "github.com/sirupsen/logrus"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}
	log.SetLevel(log.Level(cfg.LogLevel))

	repo, err := cfg.RepoManager()
	if err != nil {
		log.Fatalf("failed to init repositories: %s", err)
	}
	defer repo.Close()

	signer, err := cfg.SignerService()
	if err != nil {
		log.Fatalf("failed to init signer: %s", err)
	}

	log.Info("starting forfeit-tx backfill...")
	res, err := backfill.Run(context.Background(), repo.Vtxos(), repo.Rounds(), signer)
	if err != nil {
		log.Fatalf("forfeit-tx backfill failed: %s", err)
	}

	log.Infof(
		"forfeit-tx backfill done: scanned=%d signed=%d already_signed=%d failed=%d",
		res.Scanned, res.Signed, res.AlreadySigned, res.Failed,
	)

	// Non-zero exit when some forfeits could not be signed/persisted, so the
	// operator (or a wrapping script) notices and re-runs after fixing the cause.
	if res.Failed > 0 {
		os.Exit(1)
	}
}
