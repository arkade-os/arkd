package domain

import "time"

type ScheduledSession struct {
	StartTime                 time.Time
	EndTime                   time.Time
	Period                    time.Duration
	Duration                  time.Duration
	RoundMinParticipantsCount int64
	RoundMaxParticipantsCount int64
	UpdatedAt                 time.Time
}

func NewScheduledSession(
	startTime, endTime time.Time, period, duration time.Duration,
	roundMinParticipantsCount, roundMaxParticipantsCount int64,
) *ScheduledSession {
	return &ScheduledSession{
		StartTime:                 startTime,
		EndTime:                   endTime,
		Period:                    period,
		Duration:                  duration,
		RoundMinParticipantsCount: roundMinParticipantsCount,
		RoundMaxParticipantsCount: roundMaxParticipantsCount,
	}
}
