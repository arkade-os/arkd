package application

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	log "github.com/sirupsen/logrus"
)

// unrollRetractionObservations is how many consecutive reconcile passes must
// find a vtxo's materialising tx dropped by the chain backend before its unroll
// is retracted. One pass is not enough: a transaction that has been broadcast
// but has not reached our node yet reads exactly like one that is gone, and
// retracting a live unroll would hand its owner back a vtxo whose output exists
// on chain. Several passes apart make that reading stable rather than a race
// with propagation.
const unrollRetractionObservations = 3

// retractStaleUnrolls clears the unrolled mark on vtxos whose materialising
// transaction the chain backend no longer has any record of.
//
// A vtxo is marked unrolled the moment its outpoint appears on chain, before any
// confirmation, which is deliberate: the mark is protective and blocks the vtxo
// from being spent inside the Ark while its unroll is in flight. Nothing ever
// cleared it, so an unroll that is evicted or replaced and never mines leaves
// the vtxo wrongly unrolled forever, unspendable by its owner and unsweepable by
// the operator.
//
// Retraction runs on one piece of positive evidence: the node itself no longer
// holds the transaction that would materialise the vtxo, and has not mined it.
//
// The wallet's unspent set is deliberately not consulted. It reads as the
// stronger signal and was used here at first, but it is built from the chain
// backend's own index, which keeps an unconfirmed transaction long after the
// node has dropped it. Verified on a live stack: with the unroll evicted, the
// node reported no such output while the backend still listed the outpoint as
// unspent, so consulting it vetoed exactly the retraction this exists to make.
// The node's answer already accounts for confirmation, so nothing is lost.
func (s *service) retractStaleUnrolls(ctx context.Context, candidates []domain.Vtxo) {
	if len(candidates) == 0 {
		s.forgetUnrollObservations(nil)
		return
	}

	seen := make(map[domain.Outpoint]struct{}, len(candidates))
	stale := make([]domain.Outpoint, 0)
	for _, vtxo := range candidates {
		seen[vtxo.Outpoint] = struct{}{}

		dropped, err := s.scanner.IsTransactionDropped(ctx, vtxo.Txid)
		if err != nil {
			// Not evidence of anything. Leave the count untouched so a flapping
			// backend cannot accumulate its way to a retraction.
			log.WithError(err).Warnf(
				"unroll retraction: failed to look up tx %s, leaving vtxo %s alone",
				vtxo.Txid, vtxo.Outpoint,
			)
			continue
		}

		if s.recordUnrollObservation(vtxo.Outpoint, !dropped) >= unrollRetractionObservations {
			stale = append(stale, vtxo.Outpoint)
		}
	}

	// Anything no longer a candidate has been resolved by another path, so its
	// count must not survive to be counted against a future unroll.
	s.forgetUnrollObservations(seen)

	if len(stale) == 0 {
		return
	}

	if err := s.repoManager.Vtxos().UnmarkVtxosUnrolled(ctx, stale); err != nil {
		log.WithError(err).Warn("unroll retraction: failed to retract unrolls")
		return
	}

	for _, outpoint := range stale {
		s.recordUnrollObservation(outpoint, true)
		log.Debugf(
			"vtxo %s unroll retracted, its tx is no longer held by the node", outpoint,
		)
	}
}

// recordUnrollObservation advances or clears the consecutive count for an
// outpoint and returns the count after the update.
func (s *service) recordUnrollObservation(outpoint domain.Outpoint, known bool) int {
	s.unrollObservationsMu.Lock()
	defer s.unrollObservationsMu.Unlock()

	if known {
		delete(s.unrollObservations, outpoint)
		return 0
	}
	// Built on demand so a zero-value service counts correctly rather than
	// panicking on a nil map.
	if s.unrollObservations == nil {
		s.unrollObservations = make(map[domain.Outpoint]int)
	}
	s.unrollObservations[outpoint]++
	return s.unrollObservations[outpoint]
}

// forgetUnrollObservations drops counts for outpoints outside the given set,
// or all of them when the set is nil.
func (s *service) forgetUnrollObservations(keep map[domain.Outpoint]struct{}) {
	s.unrollObservationsMu.Lock()
	defer s.unrollObservationsMu.Unlock()

	for outpoint := range s.unrollObservations {
		if _, ok := keep[outpoint]; !ok {
			delete(s.unrollObservations, outpoint)
		}
	}
}
