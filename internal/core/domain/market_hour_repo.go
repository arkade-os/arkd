package domain

import "context"

type MarketHourRepo interface {
	Get(ctx context.Context) (*MarketHour, error)
	Upsert(ctx context.Context, marketHour MarketHour) error
	Close()
}
