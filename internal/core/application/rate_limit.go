package application

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// checkRateLimit rejects offchain txs whose inputs grow a VTXO chain faster than
// the configured velocity (depths per second). For each spent VTXO it measures
// the depth gained since its deepest marker and the time elapsed since that
// marker was created. If depthDelta/timeDelta exceeds the max velocity the input
// is rejected with a suggested cooldown.
//
// Velocity is measured against the deepest marker only, so an idle chain builds
// up allowance. A chain whose last marker is a day old can burst without being
// limited. That burst is bounded by domain.MarkerInterval, because crossing the
// next marker boundary stamps a fresh marker with the current time and
// enforcement resumes from there. Merging with an old deep chain restores the
// allowance the same way, since the deepest marker wins, and is bounded by the
// same interval.
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

	markers, err := s.markersForVtxos(ctx, spentVtxos)
	if err != nil {
		// Fail open so a marker store blip cannot stall offchain txs, but log it:
		// the limiter is not enforcing anything for this tx.
		log.WithError(err).Warn("failed to load markers, skipping rate limit check")
		return nil
	}

	now := time.Now().Unix()
	maxCooldown := int64(0)
	rejectedInputs := make(map[string]errors.InputRateLimitInfoMeta)

	for _, vtxo := range spentVtxos {
		deepestMarker, ok := deepestMarkerOf(vtxo, markers)
		if !ok || vtxo.Depth <= deepestMarker.Depth {
			continue
		}

		depthDelta := float64(vtxo.Depth - deepestMarker.Depth)
		timeDelta := float64(now - deepestMarker.CreatedAt)
		if timeDelta <= 0 {
			timeDelta = 1 // avoid division by zero
		}

		velocity := depthDelta / timeDelta
		if velocity > settings.RateLimitMaxVelocity {
			cooldown := int64(math.Ceil(depthDelta/settings.RateLimitMaxVelocity - timeDelta))
			if cooldown > settings.RateLimitMaxCooldownSecs {
				cooldown = settings.RateLimitMaxCooldownSecs
			}
			if cooldown > maxCooldown {
				maxCooldown = cooldown
			}
			rejectedInputs[vtxo.Outpoint.String()] = errors.InputRateLimitInfoMeta{
				Depth:        int(vtxo.Depth),
				MarkerDepth:  int(deepestMarker.Depth),
				CooldownSecs: cooldown,
			}
		}
	}

	if len(rejectedInputs) == 0 {
		return nil
	}

	inputs, err := json.Marshal(rejectedInputs)
	if err != nil {
		return errors.INTERNAL_ERROR.New("failed to encode rate limit metadata: %w", err)
	}

	return errors.RATE_LIMITED.New("rate limited: transaction chain growing too fast").
		WithMetadata(errors.RateLimitMetadata{
			CooldownSecs: strconv.FormatInt(maxCooldown, 10),
			Inputs:       string(inputs),
		})
}

// markersForVtxos loads every marker referenced by the given VTXOs in a single
// query, indexed by marker id.
func (s *service) markersForVtxos(
	ctx context.Context, vtxos []domain.Vtxo,
) (map[string]domain.Marker, error) {
	markersByID := make(map[string]domain.Marker)

	ids := domain.MarkerIDsOf(vtxos)
	if len(ids) == 0 {
		return markersByID, nil
	}

	markers, err := s.repoManager.Markers().GetMarkersByIds(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, marker := range markers {
		markersByID[marker.ID] = marker
	}
	return markersByID, nil
}

// deepestMarkerOf returns the highest-depth marker referenced by the VTXO, and
// whether any of its markers were found at all.
//
// Selection is by depth, not by CreatedAt, so the chosen marker is not always
// the most recently created one. A VTXO that merged an old deep chain keeps that
// chain's marker and so measures against an older timestamp, which grants slack.
// That slack is bounded: crossing the next MarkerInterval boundary replaces the
// inherited markers with a single freshly stamped one and enforcement resumes.
func deepestMarkerOf(
	vtxo domain.Vtxo, markers map[string]domain.Marker,
) (domain.Marker, bool) {
	var deepest domain.Marker
	found := false
	for _, id := range vtxo.MarkerIDs {
		marker, ok := markers[id]
		if !ok {
			continue
		}
		if !found || marker.Depth > deepest.Depth {
			deepest = marker
			found = true
		}
	}
	return deepest, found
}
