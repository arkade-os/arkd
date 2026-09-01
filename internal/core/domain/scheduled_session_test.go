package domain_test

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

var (
	sessionStart = time.Now().Add(time.Hour)
	sessionEnd   = sessionStart.Add(time.Hour)

	validScheduledSession = domain.ScheduledSession{
		StartTime:                 sessionStart,
		EndTime:                   sessionEnd,
		Period:                    2 * time.Hour,
		Duration:                  10 * time.Minute,
		RoundMinParticipantsCount: 1,
		RoundMaxParticipantsCount: 10,
	}
)

func TestScheduledSession(t *testing.T) {
	testValidateScheduledSession(t)

	testUpdateScheduledSession(t)

	testNewScheduledSession(t)

	testScheduledSessionIsEmpty(t)
}

func testValidateScheduledSession(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			require.NoError(t, validScheduledSession.Validate())
		})

		t.Run("empty is valid", func(t *testing.T) {
			require.NoError(t, domain.ScheduledSession{}.Validate())
		})

		t.Run("invalid", func(t *testing.T) {
			missingStart := validScheduledSession
			missingStart.StartTime = time.Time{}

			missingEnd := validScheduledSession
			missingEnd.EndTime = time.Time{}

			startInPast := validScheduledSession
			startInPast.StartTime = time.Now().Add(-time.Hour)

			startNotBeforeEnd := validScheduledSession
			startNotBeforeEnd.StartTime = sessionEnd

			missingPeriod := validScheduledSession
			missingPeriod.Period = 0

			periodTooSmall := validScheduledSession
			periodTooSmall.Period = 30 * time.Minute

			fixtures := []struct {
				session     domain.ScheduledSession
				expectedErr string
			}{
				{missingStart, "missing start time"},
				{missingEnd, "missing end time"},
				{startInPast, "start time must be in the future"},
				{startNotBeforeEnd, "start time must be before end time"},
				{missingPeriod, "missing period"},
				{periodTooSmall, "period must be at least 1h0m0s (end - start)"},
			}

			for _, f := range fixtures {
				require.EqualError(t, f.session.Validate(), f.expectedErr)
			}
		})
	})
}

func testUpdateScheduledSession(t *testing.T) {
	t.Run("Update", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			session := validScheduledSession

			newPeriod := 3 * time.Hour
			require.NoError(t, session.Update(domain.ScheduledSessionUpdate{Period: &newPeriod}))
			require.Equal(t, newPeriod, session.Period)
		})

		t.Run("invalid update leaves session untouched", func(t *testing.T) {
			session := validScheduledSession

			tooSmall := 30 * time.Minute
			require.EqualError(
				t, session.Update(domain.ScheduledSessionUpdate{Period: &tooSmall}),
				"period must be at least 1h0m0s (end - start)",
			)
			require.Equal(t, validScheduledSession, session)
		})
	})
}

func testNewScheduledSession(t *testing.T) {
	t.Run("NewScheduledSession", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			session, err := domain.NewScheduledSession(
				sessionStart, sessionEnd, 2*time.Hour, 10*time.Minute, 1, 10,
			)
			require.NoError(t, err)
			require.NotNil(t, session)
		})

		t.Run("invalid", func(t *testing.T) {
			session, err := domain.NewScheduledSession(
				time.Time{}, sessionEnd, 2*time.Hour, 10*time.Minute, 1, 10,
			)
			require.EqualError(t, err, "missing start time")
			require.Nil(t, session)
		})
	})
}

func testScheduledSessionIsEmpty(t *testing.T) {
	t.Run("IsEmpty", func(t *testing.T) {
		require.True(t, domain.ScheduledSession{}.IsEmpty())
		require.False(t, validScheduledSession.IsEmpty())
	})
}
