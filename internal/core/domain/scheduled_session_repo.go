package domain

import "context"

type ScheduledSessionRepo interface {
	Get(ctx context.Context) (*ScheduledSession, error)
	Upsert(ctx context.Context, scheduledSession ScheduledSession) error
	Close()
}
