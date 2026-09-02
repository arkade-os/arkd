package application

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// reconcileLookback bounds the transactions window the periodic passes ask the
// wallet for. The unfiltered endpoint returns a wallet's entire history, so a
// window keeps each tick cheap. It only has to cover what the push
// notifications could have missed, which is bounded by how long arkd was down;
// the unwindowed first pass at startup is what catches anything older.
const reconcileLookback = 30 * 24 * time.Hour

// watchOnchainSpends consumes spends pushed by the wallet and records them.
//
// This is the low-latency half of onchain spend tracking. It rides the same
// chain event that already tells arkd a vtxo was unrolled, so a spend is picked
// up as soon as it hits the mempool. It is not sufficient on its own: nothing
// arrives while arkd is down, and nothing here ever retracts a spend that fails
// to confirm. reconcileOnchainSpends covers both.
func (s *service) watchOnchainSpends() {
	// s.ctx rather than context.Background: the scanner drops its listener when
	// the context it was given is cancelled, and selecting on Done lets this
	// goroutine exit on shutdown instead of blocking on a channel nobody feeds.
	ch := s.scanner.GetSpendNotificationChannel(s.ctx)
	for {
		select {
		case <-s.ctx.Done():
			return
		case spends, ok := <-ch:
			if !ok {
				return
			}
			if err := s.applyOnchainSpends(s.ctx, spends); err != nil {
				log.WithError(err).Warn("failed to apply onchain spends")
			}
		}
	}
}

// applyOnchainSpends records the subset of spends that refer to vtxos arkd knows
// about and has seen unrolled. The wallet watches boarding scripts too, so most
// notified spends are not vtxos at all.
func (s *service) applyOnchainSpends(ctx context.Context, spends []ports.Spend) error {
	if len(spends) == 0 {
		return nil
	}

	outpoints := make([]domain.Outpoint, 0, len(spends))
	spendingTxids := make(map[domain.Outpoint]string, len(spends))
	for _, spend := range spends {
		outpoints = append(outpoints, spend.Outpoint)
		spendingTxids[spend.Outpoint] = spend.SpendingTxid
	}

	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, outpoints)
	if err != nil {
		return err
	}

	spentBy := make(map[domain.Outpoint]string)
	for _, vtxo := range vtxos {
		// Only an unrolled vtxo has an onchain output to spend. A vtxo already
		// spent inside the Ark is left alone: MarkVtxosOnchainSpent would ignore
		// it anyway, and filtering here keeps the log honest.
		if !vtxo.Unrolled {
			continue
		}
		if vtxo.Spent && !vtxo.IsOnchainSpent() {
			continue
		}

		spendingTxid := spendingTxids[vtxo.Outpoint]
		if len(spendingTxid) == 0 || vtxo.SpentBy == spendingTxid {
			continue
		}
		spentBy[vtxo.Outpoint] = spendingTxid
	}

	if len(spentBy) == 0 {
		return nil
	}

	if err := s.repoManager.Vtxos().MarkVtxosOnchainSpent(ctx, spentBy); err != nil {
		return err
	}

	for outpoint, spendingTxid := range spentBy {
		log.Debugf("vtxo %s spent onchain by %s", outpoint, spendingTxid)
	}
	return nil
}

// reconcileOnchainSpends periodically re-derives the onchain state of every
// unrolled vtxo from the wallet's view of the chain.
//
// It exists for three things push notifications cannot do: backfill vtxos
// unrolled and spent before this tracking existed, recover spends that arrived
// while arkd was down, and retract a spend whose transaction was replaced or
// evicted without ever confirming.
func (s *service) reconcileOnchainSpends(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// The first pass is unwindowed. A vtxo spent onchain long ago is still in
	// the candidate set, and a rolling window would never reach back far enough
	// to see its spend, so it would stay wrongly unspent forever. Later passes
	// only have to cover what the push notifications could have missed, which is
	// bounded by how long arkd was down.
	s.reconcileOnchainSpendsOnce(s.ctx, nil)

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			from := time.Now().Add(-reconcileLookback)
			s.reconcileOnchainSpendsOnce(s.ctx, &from)
		}
	}
}

func (s *service) reconcileOnchainSpendsOnce(ctx context.Context, from *time.Time) {
	candidates, err := s.repoManager.Vtxos().GetUnrolledUnspentVtxos(ctx)
	if err != nil {
		log.WithError(err).Warn("onchain spend reconcile: failed to load unrolled vtxos")
		return
	}

	recorded, err := s.repoManager.Vtxos().GetOnchainSpentVtxos(ctx)
	if err != nil {
		log.WithError(err).Warn("onchain spend reconcile: failed to load onchain spent vtxos")
		return
	}

	if len(candidates) == 0 && len(recorded) == 0 {
		return
	}

	spends, err := s.scanner.GetSpends(ctx, from)
	if err != nil {
		// An arkd-wallet older than this feature has no GetSpends. Push
		// notifications from such a wallet are silent too, so arkd simply does
		// not track onchain spends until the wallet is upgraded. Log it plainly
		// rather than retrying into a hot loop.
		if status.Code(err) == codes.Unimplemented {
			log.Warn(
				"onchain spend reconcile: wallet does not support GetSpends, " +
					"onchain spends of unrolled vtxos will not be tracked; upgrade arkd-wallet",
			)
			return
		}
		log.WithError(err).Warn("onchain spend reconcile: failed to fetch spends")
		return
	}

	if err := s.applyOnchainSpends(ctx, spends); err != nil {
		log.WithError(err).Warn("onchain spend reconcile: failed to record spends")
	}

	s.retractStaleOnchainSpends(ctx, recorded)
}

// retractStaleOnchainSpends undoes spends whose transaction is gone.
//
// Retraction is driven by an outpoint being *present* in the wallet's unspent
// set, never by its absence from the spend list. Presence is positive evidence
// both that the outpoint is unspent and that its script is still watched, so a
// vtxo whose script fell out of the wallet's tracking is left untouched rather
// than being wrongly un-spent. That matters because marking a live vtxo as spent
// blocks its owner from registering it in an intent.
func (s *service) retractStaleOnchainSpends(ctx context.Context, recorded []domain.Vtxo) {
	if len(recorded) == 0 {
		return
	}

	unspent, err := s.scanner.GetUnspentOutpoints(ctx)
	if err != nil {
		if status.Code(err) != codes.Unimplemented {
			log.WithError(err).Warn(
				"onchain spend reconcile: failed to fetch unspent outpoints",
			)
		}
		return
	}

	stale := make([]domain.Outpoint, 0)
	for _, vtxo := range recorded {
		if _, ok := unspent[vtxo.Outpoint]; ok {
			stale = append(stale, vtxo.Outpoint)
		}
	}

	if len(stale) == 0 {
		return
	}

	if err := s.repoManager.Vtxos().UnmarkVtxosOnchainSpent(ctx, stale); err != nil {
		log.WithError(err).Warn("onchain spend reconcile: failed to retract spends")
		return
	}

	for _, outpoint := range stale {
		log.Debugf("vtxo %s onchain spend retracted, outpoint is unspent again", outpoint)
	}
}
