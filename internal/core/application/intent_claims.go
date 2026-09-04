package application

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

// releaseIntentClaims drops the conflict-domain claims an intent holds. Releasing
// is per-owner and idempotent, so a claim already gone, or one since taken by
// someone else, is left alone. Failure is logged rather than returned: the caller
// is always on a path that drops the intent regardless, and a lost release only
// leaves a stale claim, which is worse to turn into a caller-visible error.
func releaseIntentClaims(
	ctx context.Context, store ports.OffChainTxStore, owner string, outpoints []domain.Outpoint,
) {
	if len(outpoints) <= 0 {
		return
	}
	if err := store.ReleaseOutpoints(ctx, owner, outpoints); err != nil {
		log.WithError(err).Warnf("failed to release conflict-domain claims of intent %s", owner)
	}
}

// releaseClaimsOfIntents releases the claims of each given intent, keyed by its
// own id, since the conflict domain is owner-tagged.
//
// Package-level, and shared by every path that drops an intent, including the
// admin service. These paths are the only thing that frees a claimed vtxo, so
// two copies of this that drifted apart would leak claims on whichever path
// missed a fix, with no error anywhere to show it.
func releaseClaimsOfIntents(
	ctx context.Context, store ports.OffChainTxStore, intents []domain.Intent,
) {
	for _, intent := range intents {
		outpoints := make([]domain.Outpoint, 0, len(intent.Inputs))
		for _, in := range intent.Inputs {
			outpoints = append(outpoints, in.Outpoint)
		}
		releaseIntentClaims(ctx, store, intent.Id, outpoints)
	}
}

// intentsOf strips the queue metadata the intent store carries, leaving what the
// claim release needs: the intent id and its inputs.
func intentsOf(timed []ports.TimedIntent) []domain.Intent {
	intents := make([]domain.Intent, 0, len(timed))
	for _, t := range timed {
		intents = append(intents, t.Intent)
	}
	return intents
}
