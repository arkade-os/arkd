package indexer

import (
	"context"
	"fmt"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
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
				wantItems:  []int{1},
			},
			{
				name:       "multiple pages",
				totalPages: 3,
				wantItems:  []int{1, 2, 3},
			},
			{
				name:       "nil page response stops after first page",
				totalPages: 0, // unused, fetch returns nil page
				wantItems:  []int{1},
			},
			{
				name:       "throttles after maxReqsPerSec requests",
				totalPages: int32(maxReqsPerSec + 2),
				wantItems: func() []int {
					items := make([]int, maxReqsPerSec+2)
					for i := range items {
						items[i] = i + 1
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
			name     string
			ctx      context.Context
			fetch    func(context.Context, *arkv1.IndexerPageRequest) ([]int, *arkv1.IndexerPageResponse, error)
			wantErr  string
			throttle time.Duration
		}{
			{
				name: "fetch error propagates",
				ctx:  context.Background(),
				fetch: func(_ context.Context, page *arkv1.IndexerPageRequest) ([]int, *arkv1.IndexerPageResponse, error) {
					if page.GetIndex() == 2 {
						return nil, nil, fmt.Errorf("server error")
					}
					return []int{1}, &arkv1.IndexerPageResponse{
						Current: 1, Next: 2, Total: 3,
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
				// Walking every page at the real interval would sleep for minutes.
				throttle: time.Millisecond,
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
				if tt.throttle > 0 {
					prev := throttleInterval
					throttleInterval = tt.throttle
					defer func() { throttleInterval = prev }()
				}

				resp, err := paginatedFetch(tt.ctx, tt.fetch)
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, resp)
			})
		}
	})
}

func TestHasMorePages(t *testing.T) {
	t.Run("stops only after the last page", func(t *testing.T) {
		tests := []struct {
			name       string
			totalPages int32
		}{
			{"single page", 1},
			{"two pages", 2}, // page 1 already reports Next == Total
			{"three pages", 3},
			{"many pages", 10},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				visited := make([]int32, 0, tt.totalPages)

				page := serverPage(1, tt.totalPages)
				visited = append(visited, page.Current)
				for hasMorePages(page) {
					page = serverPage(page.Next, tt.totalPages)
					visited = append(visited, page.Current)
					require.LessOrEqual(
						t, int32(len(visited)), tt.totalPages, "loop must terminate",
					)
				}

				want := make([]int32, 0, tt.totalPages)
				for i := int32(1); i <= tt.totalPages; i++ {
					want = append(want, i)
				}
				require.Equal(t, want, visited, "every page must be read exactly once")
			})
		}
	})

	t.Run("nil page has nothing more to read", func(t *testing.T) {
		require.False(t, hasMorePages(nil))
	})

	t.Run("empty result has nothing more to read", func(t *testing.T) {
		require.False(t, hasMorePages(&clientlib.PageResponse{Current: 1, Next: 0, Total: 0}))
	})
}

// serverPage mirrors the PageResp arkd builds, including the Next clamp.
func serverPage(current, totalPages int32) *clientlib.PageResponse {
	next := totalPages
	if current < totalPages {
		next = current + 1
	}
	return &clientlib.PageResponse{Current: current, Next: next, Total: totalPages}
}
