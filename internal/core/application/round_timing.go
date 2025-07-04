package application

import (
	"time"
)

type roundTiming struct {
	roundEnd time.Time
}

func newRoundTiming(roundInterval time.Duration) roundTiming {
	roundEndTime := time.Now().Add(roundInterval)
	return roundTiming{roundEndTime}
}

func (r roundTiming) remainingDuration() time.Duration {
	return time.Until(r.roundEnd)
}

// 1/6 of the remaining duration
func (r roundTiming) registrationDuration() time.Duration {
	return atLeastOneSecond(r.remainingDuration() / 6)
}

// the total duration of the confirmation phase if all attempts are done
func (r roundTiming) confirmationDuration() time.Duration {
	halfOfRemainingDuration := r.remainingDuration() / 2 // 50% of the remaining duration
	return atLeastOneSecond(halfOfRemainingDuration)
}

// 33% of the remaining duration
// 1/3 for nonces collection
// 1/3 for tree signatures
// 1/3 for finalization
func (r roundTiming) finalizationDuration() time.Duration {
	thirdOfRemainingDuration := r.remainingDuration() / 3
	return atLeastOneSecond(thirdOfRemainingDuration)
}

func atLeastOneSecond(duration time.Duration) time.Duration {
	if duration < time.Second {
		return time.Second
	}
	return duration
}
