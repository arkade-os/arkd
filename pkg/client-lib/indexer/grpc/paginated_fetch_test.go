package grpcIndexer

import (
	"context"
	"fmt"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
)

func TestPaginatedFetch(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name       string
			totalPages int32
			wantItems  []int
			wantMinDur time.Duration
		}{
			{
				name:       "single page",
				totalPages: 1,
				wantItems:  []int{0},
			},
			{
				name:       "multiple pages",
				totalPages: 3,
				wantItems:  []int{0, 1, 2},
			},
			{
				name:       "nil page response stops after first page",
				totalPages: 0, // unused, fetch returns nil page
				wantItems:  []int{0},
			},
			{
				name:       "throttles after maxReqsPerSec requests",
				totalPages: int32(maxReqsPerSec + 2),
				wantItems: func() []int {
					items := make([]int, maxReqsPerSec+2)
					for i := range items {
						items[i] = i
					}
					return items
				}(),
				wantMinDur: 900 * time.Millisecond,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				start := time.Now()

				items, err := paginatedFetch(context.Background(), func(
					ctx context.Context, page *arkv1.IndexerPageRequest,
				) ([]int, *arkv1.IndexerPageResponse, error) {
					require.Equal(t, int32(maxPageSize), page.GetSize())
					idx := page.GetIndex()
					if tt.totalPages == 0 {
						return []int{int(idx)}, nil, nil
					}
					return []int{int(idx)}, &arkv1.IndexerPageResponse{
						Current: idx, Next: idx + 1, Total: tt.totalPages,
					}, nil
				})

				require.NoError(t, err)
				require.Equal(t, tt.wantItems, items)
				if tt.wantMinDur > 0 {
					require.GreaterOrEqual(t, time.Since(start), tt.wantMinDur)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name    string
			ctx     context.Context
			fetch   func(context.Context, *arkv1.IndexerPageRequest) ([]int, *arkv1.IndexerPageResponse, error)
			wantErr string
		}{
			{
				name: "fetch error propagates",
				ctx:  context.Background(),
				fetch: func(_ context.Context, page *arkv1.IndexerPageRequest) ([]int, *arkv1.IndexerPageResponse, error) {
					if page.GetIndex() == 1 {
						return nil, nil, fmt.Errorf("server error")
					}
					return []int{1}, &arkv1.IndexerPageResponse{
						Current: 0, Next: 1, Total: 3,
					}, nil
				},
				wantErr: "server error",
			},
			{
				name: "context cancellation",
				ctx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return ctx
				}(),
				fetch: func(ctx context.Context, _ *arkv1.IndexerPageRequest) ([]int, *arkv1.IndexerPageResponse, error) {
					return nil, nil, ctx.Err()
				},
				wantErr: "context canceled",
			},
			{
				name: "exceeds max pages",
				ctx:  context.Background(),
				fetch: func(_ context.Context, page *arkv1.IndexerPageRequest) ([]int, *arkv1.IndexerPageResponse, error) {
					idx := page.GetIndex()
					return []int{int(idx)}, &arkv1.IndexerPageResponse{
						Current: idx, Next: idx + 1, Total: int32(maxPages + 10),
					}, nil
				},
				wantErr: "too many pages",
			},
			{
				name: "context cancelled during throttle",
				ctx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					// Cancel after a short delay so the throttle sleep gets interrupted.
					go func() {
						time.Sleep(50 * time.Millisecond)
						cancel()
					}()
					return ctx
				}(),
				fetch: func(_ context.Context, page *arkv1.IndexerPageRequest) ([]int, *arkv1.IndexerPageResponse, error) {
					idx := page.GetIndex()
					return []int{int(idx)}, &arkv1.IndexerPageResponse{
						Current: idx, Next: idx + 1, Total: int32(maxReqsPerSec + 5),
					}, nil
				},
				wantErr: "context canceled",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resp, err := paginatedFetch(tt.ctx, tt.fetch)
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, resp)
			})
		}
	})
}
