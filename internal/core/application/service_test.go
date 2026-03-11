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
		description       string
		vtxoMinAmount     int64
		utxoMinAmount     int64
		expectedVtxoMin   int64
		expectedUtxoMin   int64
	}{
		{
			description:     "sub-dust vtxo min is preserved for offchain",
			vtxoMinAmount:   1,
			utxoMinAmount:   100,
			expectedVtxoMin: 1,
			expectedUtxoMin: dust,
		},
		{
			description:     "default -1 is defaulted to dust",
			vtxoMinAmount:   -1,
			utxoMinAmount:   -1,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "arbitrary negative values are defaulted to dust",
			vtxoMinAmount:   -99,
			utxoMinAmount:   -50,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "above dust are kept as-is",
			vtxoMinAmount:   1000,
			utxoMinAmount:   2000,
			expectedVtxoMin: 1000,
			expectedUtxoMin: 2000,
		},
		{
			description:     "exactly dust are kept as-is",
			vtxoMinAmount:   dust,
			utxoMinAmount:   dust,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "zero vtxo min is preserved for offchain",
			vtxoMinAmount:   0,
			utxoMinAmount:   0,
			expectedVtxoMin: 0,
			expectedUtxoMin: dust,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			vtxoMin, utxoMin := resolveMinAmounts(
				tc.vtxoMinAmount, tc.utxoMinAmount, dust,
			)
			require.Equal(t, tc.expectedVtxoMin, vtxoMin)
			require.Equal(t, tc.expectedUtxoMin, utxoMin)
		})
	}
}

func TestCheckUnrolledVtxoExpiry(t *testing.T) {
	now := parseTime(t, "2023-10-10 12:00:00")
	sessionDuration := 30 * time.Second
	customMargin := 5 * time.Minute

	tests := []struct {
		description                 string
		unrolledVtxoMinExpiryMargin time.Duration
		csvExpiresAt                time.Time
		expectErr                   bool
	}{
		{
			description:                 "margin=0, CSV expires after session duration",
			unrolledVtxoMinExpiryMargin: 0,
			csvExpiresAt:                now.Add(1 * time.Minute),
			expectErr:                   false,
		},
		{
			description:                 "margin=0, CSV expires within session duration",
			unrolledVtxoMinExpiryMargin: 0,
			csvExpiresAt:                now.Add(10 * time.Second),
			expectErr:                   true,
		},
		{
			description:                 "margin=0, CSV expires exactly at session duration boundary",
			unrolledVtxoMinExpiryMargin: 0,
			csvExpiresAt:                now.Add(sessionDuration),
			expectErr:                   false,
		},
		{
			description:                 "custom margin, CSV expires after margin",
			unrolledVtxoMinExpiryMargin: customMargin,
			csvExpiresAt:                now.Add(10 * time.Minute),
			expectErr:                   false,
		},
		{
			description:                 "custom margin, CSV expires within margin",
			unrolledVtxoMinExpiryMargin: customMargin,
			csvExpiresAt:                now.Add(2 * time.Minute),
			expectErr:                   true,
		},
		{
			description:                 "custom margin, CSV expires exactly at margin boundary",
			unrolledVtxoMinExpiryMargin: customMargin,
			csvExpiresAt:                now.Add(customMargin),
			expectErr:                   false,
		},
		{
			description:                 "custom margin overrides session duration",
			unrolledVtxoMinExpiryMargin: customMargin,
			csvExpiresAt:                now.Add(1 * time.Minute),
			expectErr:                   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			svc := &service{
				sessionDuration:             sessionDuration,
				unrolledVtxoMinExpiryMargin: tc.unrolledVtxoMinExpiryMargin,
			}

			err := svc.checkUnrolledVtxoExpiry(tc.csvExpiresAt, now)
			if tc.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unrolled vtxo CSV expires too soon")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func parseTime(t *testing.T, value string) time.Time {
	tm, err := time.ParseInLocation(time.DateTime, value, time.UTC)
	require.NoError(t, err)
	return tm
}
