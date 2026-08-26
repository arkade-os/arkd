package domain

import (
	"fmt"
	"math"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

// nLocktimeMinSeconds mirrors the consensus threshold: an nLockTime below this is
// interpreted as a block height rather than a unix timestamp.
const nLocktimeMinSeconds = 500_000_000

// EpochSchedule turns wall-clock time into the shared expiry date every batch in
// an epoch commits to.
//
// A batch expires at the first epoch boundary at least RolloverWindow away, so
// batches created near the end of an epoch roll into the next one rather than
// handing out vtxos that expire almost immediately. With RolloverWindow < Length
// there are never more than two live expiry dates at once, which is what makes
// vtxos from different batches expiry-fungible: consolidating them strands no
// time value, because they already share a date.
type EpochSchedule struct {
	Anchor           time.Time
	Length           time.Duration // T
	RolloverWindow   time.Duration // L
	SettlementCutoff time.Duration // S
}

func (s EpochSchedule) Validate() error {
	if s.Length <= 0 {
		return fmt.Errorf("epoch length must be greater than 0")
	}
	if s.RolloverWindow <= 0 {
		return fmt.Errorf("rollover window must be greater than 0")
	}
	if s.SettlementCutoff <= 0 {
		return fmt.Errorf("settlement cutoff must be greater than 0")
	}
	if s.RolloverWindow >= s.Length {
		return fmt.Errorf(
			"rollover window (%s) must be shorter than the epoch length (%s)",
			s.RolloverWindow, s.Length,
		)
	}
	if s.SettlementCutoff >= s.RolloverWindow {
		return fmt.Errorf(
			"settlement cutoff (%s) must be shorter than the rollover window (%s)",
			s.SettlementCutoff, s.RolloverWindow,
		)
	}
	// Below the consensus threshold an nLockTime is a block height, so an anchor
	// near the unix epoch would silently produce a height-gated sweep leaf rather
	// than failing loudly.
	if s.Anchor.Unix() < nLocktimeMinSeconds {
		return fmt.Errorf(
			"epoch anchor %s is too early: unix time must be at least %d to be read "+
				"as a timestamp rather than a block height",
			s.Anchor, nLocktimeMinSeconds,
		)
	}
	return nil
}

// BoundaryAfter returns the first epoch boundary at or after t+RolloverWindow.
func (s EpochSchedule) BoundaryAfter(t time.Time) time.Time {
	target := t.Add(s.RolloverWindow)
	if !target.After(s.Anchor) {
		return s.Anchor
	}

	elapsed := target.Sub(s.Anchor)
	n := int64(elapsed / s.Length)
	if elapsed%s.Length != 0 {
		n++
	}

	// n*Length is bounded by elapsed+Length, and elapsed is a Duration, so this
	// only bites if Sub saturated - which needs an anchor centuries in the past.
	// Unreachable with a validated anchor, but silently wrapping into a boundary
	// in the past is the one failure mode here that would not look wrong.
	if n > math.MaxInt64/int64(s.Length) {
		return time.Time{}
	}

	return s.Anchor.Add(time.Duration(n) * s.Length)
}

// ExpiryFor returns the absolute locktime a batch created at t must commit to.
func (s EpochSchedule) ExpiryFor(t time.Time) (arklib.AbsoluteLocktime, error) {
	boundary := s.BoundaryAfter(t).Unix()
	if boundary < nLocktimeMinSeconds || boundary > math.MaxUint32 {
		return 0, fmt.Errorf(
			"epoch boundary %d is outside the representable nLockTime timestamp range",
			boundary,
		)
	}
	return arklib.AbsoluteLocktime(boundary), nil
}

// Governs reports whether a vtxo expiring at expiry is on this schedule.
//
// Every vtxo minted by an epoch batch inherits the batch's expiry date, and that
// date is always an epoch boundary, so landing on the grid is an exact test for
// "this vtxo was minted under epoch expiry". A vtxo from a pre-cutover batch
// expires at parentConfirmedAt+VtxoTreeExpiry, an arbitrary instant, and is not
// governed by the epoch windows: it never had the option of renewing into the
// same date, so the rollover bound would just refuse it for weeks after the flag
// is flipped, and renewing is exactly how such a vtxo migrates onto the schedule.
//
// A legacy vtxo landing on a boundary by coincidence is possible at second
// resolution and harmless: it is then held to the epoch windows, which is the
// stricter of the two policies.
func (s EpochSchedule) Governs(expiry arklib.AbsoluteLocktime) bool {
	if s.Length <= 0 {
		return false
	}

	expiresAt := time.Unix(int64(expiry), 0)
	if expiresAt.Before(s.Anchor) {
		return false
	}
	return expiresAt.Sub(s.Anchor)%s.Length == 0
}

// AdmitsSettle reports whether a vtxo expiring at expiry may be settled at now.
//
// The lower bound is a safety bound and applies to every vtxo input including
// collaborative exits: a settle too close to the epoch boundary produces a
// commitment tx that may still be unconfirmed when the old epoch is swept, and
// forfeit collection is evaluated at finalization, so a vtxo that expires
// mid-round slips through with no forfeit at all.
//
// The upper bound applies only to renewals. Renewing deep inside an epoch is
// pointless — the new vtxo carries the same expiry date — but not free: it makes
// the operator fund a new batch output while the old one stays locked for the
// rest of the epoch. Exits and boarding must stay available at any point.
func (s EpochSchedule) AdmitsSettle(
	expiry arklib.AbsoluteLocktime, now time.Time, isRenewal bool,
) error {
	expiresAt := time.Unix(int64(expiry), 0)

	// "at least SettlementCutoff of life remaining", so exactly at the cutoff is
	// admitted. Matches the direction of checkSettlementExpiryGap.
	if expiresAt.Before(now.Add(s.SettlementCutoff)) {
		return fmt.Errorf(
			"too late: vtxo expires at %s, within the settlement cutoff (%s)",
			expiresAt.UTC(), s.SettlementCutoff,
		)
	}

	if isRenewal && expiresAt.Sub(now) > s.RolloverWindow {
		return fmt.Errorf(
			"too early: vtxo expires at %s, outside the rollover window (%s); "+
				"renewing now would return the same expiry date",
			expiresAt.UTC(), s.RolloverWindow,
		)
	}

	return nil
}
