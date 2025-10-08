package domain

import "time"

type ScheduledSession struct {
	StartTime time.Time
	EndTime   time.Time
	Period    time.Duration
	Duration  time.Duration
	UpdatedAt time.Time
}

func NewScheduledSession(
	startTime, endTime time.Time, period, duration time.Duration,
) *ScheduledSession {
	return &ScheduledSession{
		StartTime: startTime,
		EndTime:   endTime,
		Period:    period,
		Duration:  duration,
	}
}
