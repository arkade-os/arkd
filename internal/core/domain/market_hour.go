package domain

import "time"

type MarketHour struct {
	StartTime                 time.Time
	EndTime                   time.Time
	Period                    time.Duration
	RoundInterval             time.Duration
	RoundMinParticipantsCount int64
	RoundMaxParticipantsCount int64
	UpdatedAt                 time.Time
}

func NewMarketHour(
	startTime, endTime time.Time, period, roundInterval time.Duration,
	roundMinParticipantsCount, roundMaxParticipantsCount int64,
) *MarketHour {
	return &MarketHour{
		StartTime:                 startTime,
		EndTime:                   endTime,
		Period:                    period,
		RoundInterval:             roundInterval,
		RoundMinParticipantsCount: roundMinParticipantsCount,
		RoundMaxParticipantsCount: roundMaxParticipantsCount,
	}
}
