package arksdk_test

import (
	"testing"

	arksdk "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestWithTimeRange(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			name           string
			before         int64
			after          int64
			expectedBefore int64
			expectedAfter  int64
		}{
			{
				name:           "both bounds",
				before:         2000,
				after:          1000,
				expectedBefore: 2000,
				expectedAfter:  1000,
			},
			{name: "only before",
				before:         2000,
				after:          0,
				expectedBefore: 2000,
				expectedAfter:  0,
			},
			{name: "only after",
				before:         0,
				after:          1000,
				expectedBefore: 0,
				expectedAfter:  1000,
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				o, err := arksdk.ApplyListVtxosOptions(arksdk.WithTimeRange(tc.before, tc.after))
				require.NoError(t, err)
				require.Equal(t, tc.expectedBefore, o.Before)
				require.Equal(t, tc.expectedAfter, o.After)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []arksdk.ListVtxosOption
			expectError string
		}{
			{
				name:        "both bounds zero",
				opts:        []arksdk.ListVtxosOption{arksdk.WithTimeRange(0, 0)},
				expectError: "missing time range",
			},
			{
				name:        "negative before",
				opts:        []arksdk.ListVtxosOption{arksdk.WithTimeRange(-1, 1000)},
				expectError: "negative time bound",
			},
			{
				name:        "negative after",
				opts:        []arksdk.ListVtxosOption{arksdk.WithTimeRange(1000, -1)},
				expectError: "negative time bound",
			},
			{
				name:        "before less than after",
				opts:        []arksdk.ListVtxosOption{arksdk.WithTimeRange(1000, 2000)},
				expectError: "before must be greater than after",
			},
			{
				name:        "before equals after",
				opts:        []arksdk.ListVtxosOption{arksdk.WithTimeRange(1000, 1000)},
				expectError: "before must be greater than after",
			},
			{
				name:        "time range already set",
				opts:        []arksdk.ListVtxosOption{arksdk.WithTimeRange(2000, 1000), arksdk.WithTimeRange(3000, 2000)},
				expectError: "time range already set",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := arksdk.ApplyListVtxosOptions(tc.opts...)
				require.EqualError(t, err, tc.expectError)
			})
		}
	})
}
