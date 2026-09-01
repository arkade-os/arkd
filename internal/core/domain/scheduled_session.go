package domain

import (
	"fmt"
	"time"
)

type ScheduledSession struct {
	StartTime                 time.Time
	EndTime                   time.Time
	Period                    time.Duration
	Duration                  time.Duration
	RoundMinParticipantsCount int64
	RoundMaxParticipantsCount int64
}

type ScheduledSessionUpdate struct {
	StartTime                 *time.Time
	EndTime                   *time.Time
	Period                    *time.Duration
	Duration                  *time.Duration
	RoundMinParticipantsCount *int64
	RoundMaxParticipantsCount *int64
}

func NewScheduledSession(
	startTime, endTime time.Time, period, duration time.Duration,
	roundMinParticipantsCount, roundMaxParticipantsCount int64,
) (*ScheduledSession, error) {
	session := &ScheduledSession{
		StartTime:                 startTime,
		EndTime:                   endTime,
		Period:                    period,
		Duration:                  duration,
		RoundMinParticipantsCount: roundMinParticipantsCount,
		RoundMaxParticipantsCount: roundMaxParticipantsCount,
	}
	if err := session.Validate(); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *ScheduledSession) Update(u ScheduledSessionUpdate) error {
	// Apply the update to a copy so that, if validation fails, the receiver is
	// left untouched. Settings holds only value types, so this is a full clone.
	updated := *s

	if u.StartTime != nil {
		updated.StartTime = *u.StartTime
	}
	if u.EndTime != nil {
		updated.EndTime = *u.EndTime
	}
	if u.Period != nil {
		updated.Period = *u.Period
	}
	if u.Duration != nil {
		updated.Duration = *u.Duration
	}
	if u.RoundMinParticipantsCount != nil {
		updated.RoundMinParticipantsCount = *u.RoundMinParticipantsCount
	}
	if u.RoundMaxParticipantsCount != nil {
		updated.RoundMaxParticipantsCount = *u.RoundMaxParticipantsCount
	}

	if err := updated.Validate(); err != nil {
		return err
	}

	// Validation passed: commit the changes back onto the receiver.
	*s = updated
	return nil
}

func (s ScheduledSession) Validate() error {
	if s.IsEmpty() {
		return nil
	}

	if s.StartTime.IsZero() {
		return fmt.Errorf("missing start time")
	}
	if s.EndTime.IsZero() {
		return fmt.Errorf("missing end time")
	}
	if !s.StartTime.After(time.Now()) {
		return fmt.Errorf("start time must be in the future")
	}
	if !s.StartTime.Before(s.EndTime) {
		return fmt.Errorf("start time must be before end time")
	}
	if s.Period <= 0 {
		return fmt.Errorf("missing period")
	}
	if gap := s.EndTime.Sub(s.StartTime); gap > s.Period {
		return fmt.Errorf("period must be at least %s (end - start)", gap)
	}
	return nil
}

func (s ScheduledSession) IsEmpty() bool {
	return s.StartTime.IsZero() && s.EndTime.IsZero() && s.Period == 0 && s.Duration == 0 &&
		s.RoundMinParticipantsCount == 0 && s.RoundMaxParticipantsCount == 0
}
