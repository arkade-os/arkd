package indexer_test

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestWithPage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			name string
			page *indexer.PageRequest
		}{
			{name: "size and index", page: &indexer.PageRequest{Size: 10, Index: 2}},
			{name: "zero index", page: &indexer.PageRequest{Size: 5, Index: 0}},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				o, err := indexer.ApplyPageOptions(indexer.WithPage(tc.page))
				require.NoError(t, err)
				require.Equal(t, tc.page, o.Page)
			})
		}
	})
}

func TestWithVtxosPage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			name string
			page *indexer.PageRequest
		}{
			{name: "size and index", page: &indexer.PageRequest{Size: 10, Index: 2}},
			{name: "zero index", page: &indexer.PageRequest{Size: 5, Index: 0}},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				o, err := indexer.ApplyGetVtxosOptions(indexer.WithVtxosPage(tc.page))
				require.NoError(t, err)
				require.Equal(t, tc.page, o.Page)
			})
		}
	})
}

func TestWithScripts(t *testing.T) {
	scripts := []string{"script1", "script2"}

	t.Run("valid", func(t *testing.T) {
		o, err := indexer.ApplyGetVtxosOptions(indexer.WithScripts(scripts))
		require.NoError(t, err)
		require.Equal(t, scripts, o.Scripts)
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []indexer.GetVtxosOption
			expectError string
		}{
			{
				name:        "scripts already set",
				opts:        []indexer.GetVtxosOption{indexer.WithScripts(scripts), indexer.WithScripts(scripts)},
				expectError: "scripts already set",
			},
			{
				name: "outpoints already set",
				opts: []indexer.GetVtxosOption{
					indexer.WithOutpoints([]types.Outpoint{{Txid: "abc", VOut: 0}}),
					indexer.WithScripts(scripts),
				},
				expectError: "outpoints already set",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := indexer.ApplyGetVtxosOptions(tc.opts...)
				require.EqualError(t, err, tc.expectError)
			})
		}
	})
}

func TestWithOutpoints(t *testing.T) {
	outpoints := []types.Outpoint{
		{Txid: "abc123", VOut: 0},
		{Txid: "def456", VOut: 1},
	}

	t.Run("valid", func(t *testing.T) {
		o, err := indexer.ApplyGetVtxosOptions(indexer.WithOutpoints(outpoints))
		require.NoError(t, err)
		require.Equal(t, outpoints, o.Outpoints)
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []indexer.GetVtxosOption
			expectError string
		}{
			{
				name:        "outpoints already set",
				opts:        []indexer.GetVtxosOption{indexer.WithOutpoints(outpoints), indexer.WithOutpoints(outpoints)},
				expectError: "outpoints already set",
			},
			{
				name: "scripts already set",
				opts: []indexer.GetVtxosOption{
					indexer.WithScripts([]string{"s1"}),
					indexer.WithOutpoints(outpoints),
				},
				expectError: "scripts already set",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := indexer.ApplyGetVtxosOptions(tc.opts...)
				require.EqualError(t, err, tc.expectError)
			})
		}
	})
}

func TestFormattedOutpoints(t *testing.T) {
	outpoints := []types.Outpoint{
		{Txid: "abc123", VOut: 0},
		{Txid: "def456", VOut: 2},
	}
	o, err := indexer.ApplyGetVtxosOptions(indexer.WithOutpoints(outpoints))
	require.NoError(t, err)
	require.Equal(t, []string{"abc123:0", "def456:2"}, o.FormattedOutpoints())
}

func TestWithFilters(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("spent only", func(t *testing.T) {
			o, err := indexer.ApplyGetVtxosOptions(indexer.WithSpentOnly())
			require.NoError(t, err)
			require.True(t, o.SpentOnly)
		})

		t.Run("spendable only", func(t *testing.T) {
			o, err := indexer.ApplyGetVtxosOptions(indexer.WithSpendableOnly())
			require.NoError(t, err)
			require.True(t, o.SpendableOnly)
		})

		t.Run("recoverable only", func(t *testing.T) {
			o, err := indexer.ApplyGetVtxosOptions(indexer.WithRecoverableOnly())
			require.NoError(t, err)
			require.True(t, o.RecoverableOnly)
		})

		t.Run("pending only", func(t *testing.T) {
			o, err := indexer.ApplyGetVtxosOptions(indexer.WithPendingOnly())
			require.NoError(t, err)
			require.True(t, o.PendingOnly)
		})
	})
}

func TestWithTimeRange(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			name           string
			before         int64
			after          int64
			expectedBefore int64
			expectedAfter  int64
		}{
			{name: "both bounds", before: 2000, after: 1000, expectedBefore: 2000, expectedAfter: 1000},
			{name: "only before", before: 2000, after: 0, expectedBefore: 2000, expectedAfter: 0},
			{name: "only after", before: 0, after: 1000, expectedBefore: 0, expectedAfter: 1000},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				o, err := indexer.ApplyGetVtxosOptions(indexer.WithTimeRange(tc.before, tc.after))
				require.NoError(t, err)
				require.Equal(t, tc.expectedBefore, o.Before)
				require.Equal(t, tc.expectedAfter, o.After)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []indexer.GetVtxosOption
			expectError string
		}{
			{
				name:        "both bounds zero",
				opts:        []indexer.GetVtxosOption{indexer.WithTimeRange(0, 0)},
				expectError: "missing time range",
			},
			{
				name:        "negative before",
				opts:        []indexer.GetVtxosOption{indexer.WithTimeRange(-1, 1000)},
				expectError: "negative time bound",
			},
			{
				name:        "negative after",
				opts:        []indexer.GetVtxosOption{indexer.WithTimeRange(1000, -1)},
				expectError: "negative time bound",
			},
			{
				name:        "before less than after",
				opts:        []indexer.GetVtxosOption{indexer.WithTimeRange(1000, 2000)},
				expectError: "before must be greater than after",
			},
			{
				name:        "before equals after",
				opts:        []indexer.GetVtxosOption{indexer.WithTimeRange(1000, 1000)},
				expectError: "before must be greater than after",
			},
			{
				name:        "time range already set",
				opts:        []indexer.GetVtxosOption{indexer.WithTimeRange(2000, 1000), indexer.WithTimeRange(3000, 2000)},
				expectError: "time range already set",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := indexer.ApplyGetVtxosOptions(tc.opts...)
				require.EqualError(t, err, tc.expectError)
			})
		}
	})
}

func TestWithStartAndEndTime(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		start := time.Unix(1000, 0)
		end := time.Unix(2000, 0)

		testCases := []struct {
			name          string
			opts          []indexer.GetTxHistoryOption
			expectedStart time.Time
			expectedEnd   time.Time
		}{
			{
				name:          "start time only",
				opts:          []indexer.GetTxHistoryOption{indexer.WithStartTime(start)},
				expectedStart: start,
			},
			{
				name:        "end time only",
				opts:        []indexer.GetTxHistoryOption{indexer.WithEndTime(end)},
				expectedEnd: end,
			},
			{
				name:          "both start and end",
				opts:          []indexer.GetTxHistoryOption{indexer.WithStartTime(start), indexer.WithEndTime(end)},
				expectedStart: start,
				expectedEnd:   end,
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				o, err := indexer.ApplyGetTxHistoryOptions(tc.opts...)
				require.NoError(t, err)
				require.Equal(t, tc.expectedStart, o.StartTime)
				require.Equal(t, tc.expectedEnd, o.EndTime)
			})
		}
	})
}
