package domain

import "time"

type MarketHour struct {
	StartTime     time.Time
	EndTime       time.Time
	Period        time.Duration
	RoundInterval time.Duration
	UpdatedAt     time.Time
}

func NewMarketHour(startTime, endTime time.Time, period, roundInterval time.Duration) *MarketHour {
	return &MarketHour{
		StartTime:     startTime,
		EndTime:       endTime,
		Period:        period,
		RoundInterval: roundInterval,
	}
}
