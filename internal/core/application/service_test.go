package application

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNextMarketHour(t *testing.T) {
	marketHourStartTime := parseTime(t, "2023-10-10 13:00:00")
	marketHourEndTime := parseTime(t, "2023-10-10 14:00:00")
	period := 3 * time.Hour

	testCases := []struct {
		now           time.Time
		expectedStart time.Time
		expectedEnd   time.Time
		expectError   bool
		description   string
	}{
		{
			now:           parseTime(t, "2023-10-10 13:00:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			expectError:   false,
			description:   "Now is exactly at the initial market hour start time",
		},
		{
			now:           parseTime(t, "2023-10-10 13:55:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			expectError:   false,
			description:   "Now is during the market period, equals to delta",
		},
		{
			now:           parseTime(t, "2023-10-10 13:56:00"),
			expectedStart: parseTime(t, "2023-10-10 16:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 17:00:00"),
			expectError:   false,
			description:   "Now is during the market period, but after delta",
		},
		{
			now:           parseTime(t, "2023-10-10 14:06:00"),
			expectedStart: parseTime(t, "2023-10-10 16:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 17:00:00"),
			expectError:   false,
			description:   "Now is after market period",
		},
		{
			now:           parseTime(t, "2023-10-10 23:06:00"),
			expectedStart: parseTime(t, "2023-10-11 01:00:00"),
			expectedEnd:   parseTime(t, "2023-10-11 02:00:00"),
			expectError:   false,
			description:   "More periods, return next round",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			startTime, endTime, err := calcNextMarketHour(
				marketHourStartTime,
				marketHourEndTime,
				period,
				marketHourDelta,
				tc.now,
			)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect an error but got: %v", err)
				}
				if !startTime.Equal(tc.expectedStart) {
					t.Errorf("Expected start time %v, got %v", tc.expectedStart.UTC(), startTime.UTC())
				}
				if !endTime.Equal(tc.expectedEnd) {
					t.Errorf("Expected end time %v, got %v", tc.expectedEnd.UTC(), endTime.UTC())
				}
			}
		})
	}
}

func parseTime(t *testing.T, value string) time.Time {
	layout := "2006-01-02 15:04:05"
	tm, err := time.ParseInLocation(layout, value, time.UTC)
	require.NoError(t, err)
	return tm
}
