package application

import (
	"context"
	"math"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/errors"
)

// checkRateLimit rejects offchain txs whose inputs grow a VTXO chain faster than
// the configured velocity (depths per second). For each spent VTXO it measures
// the depth gained since its youngest marker and the time elapsed since that
// marker was created; if depthDelta/timeDelta exceeds the max velocity the input
// is rejected with a suggested cooldown.
func (s *service) checkRateLimit(
	ctx context.Context, spentVtxos []domain.Vtxo,
) errors.Error {
	settings, err := s.cache.Settings().Get(ctx)
	if err != nil {
		return errors.INTERNAL_ERROR.New("failed to get settings: %w", err)
	}
	if !settings.RateLimitEnabled {
		return nil
	}

	now := time.Now().Unix()
	rejectedInputs := make(map[string]errors.InputRateLimitInfoMeta)

	for _, vtxo := range spentVtxos {
		if len(vtxo.MarkerIDs) == 0 {
			continue
		}

		markers, err := s.repoManager.Markers().GetMarkersByIds(ctx, vtxo.MarkerIDs)
		if err != nil || len(markers) == 0 {
			continue
		}

		// Find the youngest marker (highest depth).
		youngestMarker := markers[0]
		for _, m := range markers[1:] {
			if m.Depth > youngestMarker.Depth {
				youngestMarker = m
			}
		}

		if vtxo.Depth <= youngestMarker.Depth {
			continue
		}

		depthDelta := float64(vtxo.Depth - youngestMarker.Depth)
		timeDelta := float64(now - youngestMarker.CreatedAt)
		if timeDelta <= 0 {
			timeDelta = 1 // avoid division by zero
		}

		velocity := depthDelta / timeDelta
		if velocity > settings.RateLimitMaxVelocity {
			cooldown := int64(math.Ceil(depthDelta/settings.RateLimitMaxVelocity - timeDelta))
			if cooldown > settings.RateLimitMaxCooldownSecs {
				cooldown = settings.RateLimitMaxCooldownSecs
			}
			rejectedInputs[vtxo.Outpoint.String()] = errors.InputRateLimitInfoMeta{
				Depth:        int(vtxo.Depth),
				MarkerDepth:  int(youngestMarker.Depth),
				CooldownSecs: cooldown,
			}
		}
	}

	if len(rejectedInputs) > 0 {
		return errors.RATE_LIMITED.New("rate limited: transaction chain growing too fast").
			WithMetadata(errors.RateLimitMetadata{
				Inputs: rejectedInputs,
			})
	}

	return nil
}
