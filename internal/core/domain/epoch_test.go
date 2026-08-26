package domain_test

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

// testAnchor is 2026-01-05 00:00:00 UTC, a Monday. 28-day epochs keep every later
// boundary on the same weekday and hour forever, which is why 28 beats 30.
var testAnchor = time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)

func testSchedule() domain.EpochSchedule {
	return domain.EpochSchedule{
		Anchor:           testAnchor,
		Length:           28 * 24 * time.Hour,
		RolloverWindow:   7 * 24 * time.Hour,
		SettlementCutoff: 12 * time.Hour,
	}
}

func TestEpochScheduleValidate(t *testing.T) {
	t.Run("defaults are valid", func(t *testing.T) {
		require.NoError(t, testSchedule().Validate())
	})

	t.Run("length must be positive", func(t *testing.T) {
		s := testSchedule()
		s.Length = 0
		require.Error(t, s.Validate())
	})

	t.Run("rollover window must be shorter than the epoch", func(t *testing.T) {
		s := testSchedule()
		s.RolloverWindow = s.Length
		require.Error(t, s.Validate())
	})

	t.Run("settlement cutoff must be shorter than the rollover window", func(t *testing.T) {
		s := testSchedule()
		s.SettlementCutoff = s.RolloverWindow
		require.Error(t, s.Validate())
	})

	t.Run("cutoff must be positive", func(t *testing.T) {
		s := testSchedule()
		s.SettlementCutoff = 0
		require.Error(t, s.Validate())
	})

	// Below 500000000 an nLockTime is read as a block height, not a timestamp, so
	// an anchor near the unix epoch would silently produce a height-gated leaf.
	t.Run("anchor must be late enough to be read as a timestamp", func(t *testing.T) {
		s := testSchedule()
		s.Anchor = time.Unix(1000, 0)
		require.Error(t, s.Validate())
	})
}

func TestEpochScheduleBoundaryAfter(t *testing.T) {
	s := testSchedule()
	day := 24 * time.Hour

	tests := []struct {
		name string
		at   time.Time
		want time.Time
	}{
		{
			// 21 days left in the epoch, more than L, so it targets this boundary
			name: "mid-epoch targets the current boundary",
			at:   testAnchor.Add(-21 * day),
			want: testAnchor,
		},
		{
			// exactly L away: E - t == L still satisfies E >= t+L
			name: "exactly L before the boundary still targets it",
			at:   testAnchor.Add(-7 * day),
			want: testAnchor,
		},
		{
			name: "one second inside the rollover window rolls over",
			at:   testAnchor.Add(-7*day + time.Second),
			want: testAnchor.Add(28 * day),
		},
		{
			name: "on the boundary rolls to the next",
			at:   testAnchor,
			want: testAnchor.Add(28 * day),
		},
		{
			name: "just after a boundary targets the next one",
			at:   testAnchor.Add(time.Second),
			want: testAnchor.Add(28 * day),
		},
		{
			name: "several epochs later",
			at:   testAnchor.Add(100 * day),
			want: testAnchor.Add(112 * day), // 4 * 28
		},
		{
			name: "before the anchor clamps to the anchor",
			at:   testAnchor.Add(-100 * day),
			want: testAnchor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, s.BoundaryAfter(tt.at))
		})
	}
}

// TestEpochScheduleLiveExpiryDates is the property the whole design exists for:
// with L < T there are never more than two distinct live expiry dates, which is
// what makes vtxos from different batches expiry-fungible.
func TestEpochScheduleLiveExpiryDates(t *testing.T) {
	s := testSchedule()
	seen := map[time.Time]struct{}{}

	// sample every hour across one full epoch
	for h := 0; h < 28*24; h++ {
		at := testAnchor.Add(time.Duration(h) * time.Hour)
		seen[s.BoundaryAfter(at)] = struct{}{}
	}

	require.Len(t, seen, 2, "an epoch's batches must land on at most two boundaries")
}

// TestEpochScheduleLifetimeBounds pins the user-visible consequence: a vtxo lives
// at least L and at most T+L.
func TestEpochScheduleLifetimeBounds(t *testing.T) {
	s := testSchedule()

	for h := 0; h < 28*24; h++ {
		at := testAnchor.Add(time.Duration(h) * time.Hour)
		lifetime := s.BoundaryAfter(at).Sub(at)
		require.GreaterOrEqual(t, lifetime, s.RolloverWindow,
			"lifetime must never drop below the rollover window")
		require.LessOrEqual(t, lifetime, s.Length+s.RolloverWindow,
			"lifetime must never exceed one epoch plus the rollover window")
	}
}

func TestEpochScheduleExpiryFor(t *testing.T) {
	s := testSchedule()

	got, err := s.ExpiryFor(testAnchor.Add(-21 * 24 * time.Hour))
	require.NoError(t, err)
	require.Equal(t, arklib.AbsoluteLocktime(testAnchor.Unix()), got)
	require.True(t, got.IsSeconds(), "must be read as a timestamp, not a block height")
}

func TestEpochScheduleAdmitsSettle(t *testing.T) {
	s := testSchedule()
	expiry := arklib.AbsoluteLocktime(testAnchor.Unix())
	day := 24 * time.Hour

	t.Run("renewal deep inside the epoch is rejected as pointless", func(t *testing.T) {
		// 21 days of life left, more than the rollover window: renewing now would
		// return a vtxo with the same expiry date, at the cost of double-locking
		// operator capital for the rest of the epoch.
		err := s.AdmitsSettle(expiry, testAnchor.Add(-21*day), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too early")
	})

	t.Run("exit deep inside the epoch is allowed", func(t *testing.T) {
		// the upper bound applies only to renewals; a collaborative exit must be
		// available at any point in the epoch
		require.NoError(t, s.AdmitsSettle(expiry, testAnchor.Add(-21*day), false))
	})

	t.Run("renewal inside the rollover window is allowed", func(t *testing.T) {
		require.NoError(t, s.AdmitsSettle(expiry, testAnchor.Add(-3*day), true))
	})

	t.Run("settle inside the cutoff is rejected for renewals", func(t *testing.T) {
		err := s.AdmitsSettle(expiry, testAnchor.Add(-time.Hour), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too late")
	})

	t.Run("settle inside the cutoff is rejected for exits too", func(t *testing.T) {
		// the lower bound is a safety bound and applies to every vtxo input: the
		// new commitment tx must confirm before the old epoch is swept
		err := s.AdmitsSettle(expiry, testAnchor.Add(-time.Hour), false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too late")
	})

	t.Run("already expired is rejected", func(t *testing.T) {
		require.Error(t, s.AdmitsSettle(expiry, testAnchor.Add(time.Hour), false))
	})

	t.Run("exactly at the cutoff is allowed", func(t *testing.T) {
		require.NoError(t, s.AdmitsSettle(expiry, testAnchor.Add(-12*time.Hour), false))
	})

	t.Run("exactly at the rollover window is allowed for renewals", func(t *testing.T) {
		require.NoError(t, s.AdmitsSettle(expiry, testAnchor.Add(-7*day), true))
	})
}

// TestSettingsUpdateFreezesEpochAnchor pins that the anchor cannot drift once
// batches are committing to the boundary grid it defines.
func TestSettingsUpdateFreezesEpochAnchor(t *testing.T) {
	anchor := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	moved := anchor.Add(72 * time.Hour)

	base := func(enabled bool) domain.Settings {
		s := validSettings
		s.EpochExpiryEnabled = enabled
		s.EpochAnchor = anchor
		s.EpochLength = 28 * 24 * time.Hour
		s.RolloverWindow = 7 * 24 * time.Hour
		s.SettlementCutoff = 24 * time.Hour
		s.UnrollGrace = arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: 7168,
		}
		return s
	}

	t.Run("settable while epoch expiry is off", func(t *testing.T) {
		s := base(false)
		changelog, err := s.Update(domain.SettingsUpdate{EpochAnchor: &moved})
		require.NoError(t, err)
		require.Contains(t, changelog, "epoch_anchor")
		require.True(t, s.EpochAnchor.Equal(moved))
	})

	t.Run("settable in the same update that turns the flag on", func(t *testing.T) {
		s := base(false)
		enabled := true
		changelog, err := s.Update(domain.SettingsUpdate{
			EpochAnchor: &moved, EpochExpiryEnabled: &enabled,
		})
		require.NoError(t, err)
		require.Contains(t, changelog, "epoch_anchor")
		require.True(t, s.EpochAnchor.Equal(moved))
	})

	t.Run("frozen once epoch expiry is on", func(t *testing.T) {
		s := base(true)
		_, err := s.Update(domain.SettingsUpdate{EpochAnchor: &moved})
		require.ErrorContains(t, err, "epoch_anchor cannot be changed")
		require.True(t, s.EpochAnchor.Equal(anchor), "the receiver must be untouched")
	})

	t.Run("resubmitting the same anchor is a no-op, not an error", func(t *testing.T) {
		s := base(true)
		same := anchor
		changelog, err := s.Update(domain.SettingsUpdate{EpochAnchor: &same})
		require.NoError(t, err)
		require.NotContains(t, changelog, "epoch_anchor")
	})

	t.Run("other epoch settings stay tunable while on", func(t *testing.T) {
		s := base(true)
		window := 5 * 24 * time.Hour
		changelog, err := s.Update(domain.SettingsUpdate{RolloverWindow: &window})
		require.NoError(t, err)
		require.Contains(t, changelog, "rollover_window")
	})
}
