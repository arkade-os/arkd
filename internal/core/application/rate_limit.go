package application

import (
	"context"
	"math"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/errors"
)

func (s *service) checkRateLimit(
	ctx context.Context, spentVtxos []domain.Vtxo,
) errors.Error {
	if !s.rateLimitEnabled {
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

		// Find the youngest marker (highest depth)
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
		if velocity > s.rateLimitMaxVelocity {
			cooldown := int64(math.Ceil(depthDelta/s.rateLimitMaxVelocity - timeDelta))
			if cooldown > s.rateLimitMaxCooldownSecs {
				cooldown = s.rateLimitMaxCooldownSecs
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
