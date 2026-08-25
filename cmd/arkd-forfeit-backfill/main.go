// Command arkd-forfeit-backfill signs the operator's half of forfeit transactions
// that were persisted before arkd started signing forfeit txs at collection time.
//
// It connects to the same database and signer as arkd (via the standard arkd
// configuration / environment), so the arkd-wallet signer must be running and
// unlocked. It scans every unswept forfeited vtxo, signs the operator's half of
// its forfeit tx when missing, and persists the result. It is safe to run
// repeatedly: forfeit txs that already carry every signature needed to broadcast
// them are skipped.
//
// arkd may keep running while this tool does. A patch can land next to arkd's own
// fraud handling, but both sides decide what to do from the stored psbt, so the
// worst case is that arkd signs a forfeit this tool was about to sign, or reads
// the freshly signed one. Neither loses work and both are idempotent.
//
// It loads every vtxo in one call before filtering. On a large deployment that is
// a big read, so prefer running it off peak.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	log.Info("starting forfeit-tx backfill...")
	start := time.Now()

	repo, err := cfg.RepoManager()
	if err != nil {
		log.Fatalf("failed to init repositories: %s", err)
	}
	defer repo.Close()

	signer, err := cfg.SignerService()
	if err != nil {
		log.Fatalf("failed to init signer: %s", err)
	}

	// Interrupting stops after the round in flight rather than killing the run
	// mid-way, so the operator still gets the counts. Re-running resumes.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, err := backfill.Run(ctx, repo.Vtxos(), repo.Rounds(), signer)
	if err != nil {
		log.Fatalf("forfeit-tx backfill failed: %s", err)
	}

	log.Infof(
		"forfeit-tx backfill done: duration=%s scanned=%d signed=%d already_signed=%d failed=%d",
		time.Since(start).Round(time.Millisecond),
		res.Scanned, res.Signed, res.AlreadySigned, res.Failed,
	)

	// Non-zero exit when some forfeits could not be signed/persisted, so the
	// operator (or a wrapping script) notices and re-runs after fixing the cause.
	if res.Failed > 0 {
		os.Exit(1)
	}
}
