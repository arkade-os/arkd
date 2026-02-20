package application

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNextScheduledSession(t *testing.T) {
	scheduledSessionStartTime := parseTime(t, "2023-10-10 13:00:00")
	scheduledSessionEndTime := parseTime(t, "2023-10-10 14:00:00")
	period := 1 * time.Hour

	testCases := []struct {
		now           time.Time
		expectedStart time.Time
		expectedEnd   time.Time
		description   string
	}{
		{
			now:           parseTime(t, "2023-10-10 13:00:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is exactly scheduled session start time",
		},
		{
			now:           parseTime(t, "2023-10-10 13:55:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is in the first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 14:00:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is exactly scheduled session end time",
		},
		{
			now:           parseTime(t, "2023-10-10 14:06:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is after first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 15:30:00"),
			expectedStart: parseTime(t, "2023-10-10 15:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 16:00:00"),
			description:   "now is after second scheduled session",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			startTime, endTime := calcNextScheduledSession(
				tc.now, scheduledSessionStartTime, scheduledSessionEndTime, period,
			)
			require.True(t, startTime.Equal(tc.expectedStart))
			require.True(t, endTime.Equal(tc.expectedEnd))
		})
	}
}

func TestResolveMinAmounts(t *testing.T) {
	const dust int64 = 330

	testCases := []struct {
		description            string
		vtxoMinAmount          int64
		utxoMinAmount          int64
		expectedVtxoSettlement int64
		expectedVtxoOffchain   int64
		expectedUtxoMin        int64
	}{
		{
			description:            "below dust are clamped to dust",
			vtxoMinAmount:          1,
			utxoMinAmount:          100,
			expectedVtxoSettlement: dust,
			expectedVtxoOffchain:   dust,
			expectedUtxoMin:        dust,
		},
		{
			description:            "default -1 is clamped to dust",
			vtxoMinAmount:          -1,
			utxoMinAmount:          -1,
			expectedVtxoSettlement: dust,
			expectedVtxoOffchain:   dust,
			expectedUtxoMin:        dust,
		},
		{
			description:            "above dust are kept as-is",
			vtxoMinAmount:          1000,
			utxoMinAmount:          2000,
			expectedVtxoSettlement: 1000,
			expectedVtxoOffchain:   1000,
			expectedUtxoMin:        2000,
		},
		{
			description:            "exactly dust are kept as-is",
			vtxoMinAmount:          dust,
			utxoMinAmount:          dust,
			expectedVtxoSettlement: dust,
			expectedVtxoOffchain:   dust,
			expectedUtxoMin:        dust,
		},
		{
			description:            "zero is clamped to dust",
			vtxoMinAmount:          0,
			utxoMinAmount:          0,
			expectedVtxoSettlement: dust,
			expectedVtxoOffchain:   dust,
			expectedUtxoMin:        dust,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			settlement, offchain, utxoMin := resolveMinAmounts(
				tc.vtxoMinAmount, tc.utxoMinAmount, dust,
			)
			require.Equal(t, tc.expectedVtxoSettlement, settlement)
			require.Equal(t, tc.expectedVtxoOffchain, offchain)
			require.Equal(t, tc.expectedUtxoMin, utxoMin)
		})
	}
}

func parseTime(t *testing.T, value string) time.Time {
	tm, err := time.ParseInLocation(time.DateTime, value, time.UTC)
	require.NoError(t, err)
	return tm
}
