package handlers

import (
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
)

func TestParseVirtualTxsFilter(t *testing.T) {
	t.Parallel()

	t.Run("nil filter returns zero filter", func(t *testing.T) {
		f, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{})
		require.NoError(t, err)
		require.False(t, f.WithExtension)
		require.Empty(t, f.WithPacket)
		require.Zero(t, f.WithAfterDate)
		require.Zero(t, f.WithBeforeDate)
	})

	t.Run("single CEL expression is projected", func(t *testing.T) {
		f, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{
			Filter: &arkv1.SubscriptionFilter{
				Expressions: []string{"hasPacket(tx.extension, 42)"},
			},
		})
		require.NoError(t, err)
		require.Contains(t, f.WithPacket, 42)
	})

	t.Run("multiple CEL expressions are rejected", func(t *testing.T) {
		_, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{
			Filter: &arkv1.SubscriptionFilter{
				Expressions: []string{"has(tx.extension)", "hasPacket(tx.extension, 1)"},
			},
		})
		require.Error(t, err)
	})

	t.Run("after time range populates WithAfterDate", func(t *testing.T) {
		f, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{
			TimeRange: &arkv1.GetVirtualTxsRequest_After{
				After: &arkv1.TimeRangeAfter{Timestamp: 1000},
			},
		})
		require.NoError(t, err)
		require.Equal(t, int64(1000), f.WithAfterDate)
		require.Zero(t, f.WithBeforeDate)
	})

	t.Run("before time range populates WithBeforeDate", func(t *testing.T) {
		f, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{
			TimeRange: &arkv1.GetVirtualTxsRequest_Before{
				Before: &arkv1.TimeRangeBefore{Timestamp: 2000},
			},
		})
		require.NoError(t, err)
		require.Equal(t, int64(2000), f.WithBeforeDate)
		require.Zero(t, f.WithAfterDate)
	})

	t.Run("within time range populates both bounds", func(t *testing.T) {
		f, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{
			TimeRange: &arkv1.GetVirtualTxsRequest_Within{
				Within: &arkv1.TimeRangeWithin{
					StartTimestamp: 100,
					EndTimestamp:   200,
				},
			},
		})
		require.NoError(t, err)
		require.Equal(t, int64(100), f.WithAfterDate)
		require.Equal(t, int64(200), f.WithBeforeDate)
	})

	t.Run("within with inverted bounds is rejected", func(t *testing.T) {
		_, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{
			TimeRange: &arkv1.GetVirtualTxsRequest_Within{
				Within: &arkv1.TimeRangeWithin{
					StartTimestamp: 200,
					EndTimestamp:   100,
				},
			},
		})
		require.Error(t, err)
	})

	t.Run("invalid CEL expression surfaces error", func(t *testing.T) {
		_, err := parseVirtualTxsFilter(&arkv1.GetVirtualTxsRequest{
			Filter: &arkv1.SubscriptionFilter{
				Expressions: []string{"hasPacket(tx.extension, 1) || hasPacket(tx.extension, 2)"},
			},
		})
		require.Error(t, err)
	})
}
