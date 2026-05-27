package walletclient

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// fakeWalletClient stands in for an arkwalletv1.WalletServiceClient in tests.
// Embedding the interface (with a nil value) means any method we do not
// override will panic, which is fine since each test only drives one or two
// methods. WatchScripts and UnwatchScripts are overridden to record the
// chunks they receive and optionally fail on a chosen call.
type fakeWalletClient struct {
	arkwalletv1.WalletServiceClient
	watchCalls    [][]string
	unwatchCalls  [][]string
	failOnCallIdx int
	failErr       error
}

func (f *fakeWalletClient) WatchScripts(
	_ context.Context, in *arkwalletv1.WatchScriptsRequest, _ ...grpc.CallOption,
) (*arkwalletv1.WatchScriptsResponse, error) {
	// Copy so callers can mutate without disturbing recorded state.
	recorded := append([]string(nil), in.Scripts...)
	f.watchCalls = append(f.watchCalls, recorded)
	if f.failErr != nil && len(f.watchCalls) == f.failOnCallIdx {
		return nil, f.failErr
	}
	return &arkwalletv1.WatchScriptsResponse{}, nil
}

func (f *fakeWalletClient) UnwatchScripts(
	_ context.Context, in *arkwalletv1.UnwatchScriptsRequest, _ ...grpc.CallOption,
) (*arkwalletv1.UnwatchScriptsResponse, error) {
	recorded := append([]string(nil), in.Scripts...)
	f.unwatchCalls = append(f.unwatchCalls, recorded)
	if f.failErr != nil && len(f.unwatchCalls) == f.failOnCallIdx {
		return nil, f.failErr
	}
	return &arkwalletv1.UnwatchScriptsResponse{}, nil
}

// withChunkSize swaps watchScriptsChunkSize for the duration of a test and
// restores it via the returned cleanup function. Lets us drive boundary
// cases without seeding thousands of scripts.
func withChunkSize(t *testing.T, n int) func() {
	t.Helper()
	prev := watchScriptsChunkSize
	watchScriptsChunkSize = n
	return func() { watchScriptsChunkSize = prev }
}

func makeScripts(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		// Content is irrelevant for chunking; index is enough to assert order.
		out[i] = "s" + strconv.Itoa(i)
	}
	return out
}

func TestChunkStrings(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		size int
		want [][]string
	}{
		{
			name: "nil_input",
			in:   nil,
			size: 100,
			want: [][]string{nil},
		},
		{
			name: "empty_input",
			in:   []string{},
			size: 100,
			want: [][]string{{}},
		},
		{
			name: "single_full_chunk",
			in:   []string{"a", "b", "c"},
			size: 10,
			want: [][]string{{"a", "b", "c"}},
		},
		{
			name: "exact_multiple",
			in:   []string{"a", "b", "c", "d"},
			size: 2,
			want: [][]string{{"a", "b"}, {"c", "d"}},
		},
		{
			name: "uneven_last_chunk",
			in:   []string{"a", "b", "c", "d", "e"},
			size: 2,
			want: [][]string{{"a", "b"}, {"c", "d"}, {"e"}},
		},
		{
			name: "size_one",
			in:   []string{"a", "b"},
			size: 1,
			want: [][]string{{"a"}, {"b"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chunkStrings(tt.in, tt.size)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWalletClientWatchScriptsChunking(t *testing.T) {
	t.Run("empty_input_no_calls", func(t *testing.T) {
		fake := &fakeWalletClient{}
		c := &walletDaemonClient{client: fake}
		require.NoError(t, c.WatchScripts(context.Background(), nil))
		require.NoError(t, c.WatchScripts(context.Background(), []string{}))
		require.Empty(t, fake.watchCalls)
	})

	t.Run("single_chunk_when_under_limit", func(t *testing.T) {
		defer withChunkSize(t, 100)()
		fake := &fakeWalletClient{}
		c := &walletDaemonClient{client: fake}
		scripts := makeScripts(75)
		require.NoError(t, c.WatchScripts(context.Background(), scripts))
		require.Len(t, fake.watchCalls, 1)
		require.Equal(t, scripts, fake.watchCalls[0])
	})

	t.Run("exact_chunk_boundary", func(t *testing.T) {
		defer withChunkSize(t, 100)()
		fake := &fakeWalletClient{}
		c := &walletDaemonClient{client: fake}
		scripts := makeScripts(100)
		require.NoError(t, c.WatchScripts(context.Background(), scripts))
		require.Len(t, fake.watchCalls, 1)
		require.Len(t, fake.watchCalls[0], 100)
	})

	t.Run("splits_above_boundary", func(t *testing.T) {
		defer withChunkSize(t, 100)()
		fake := &fakeWalletClient{}
		c := &walletDaemonClient{client: fake}
		scripts := makeScripts(101)
		require.NoError(t, c.WatchScripts(context.Background(), scripts))
		require.Len(t, fake.watchCalls, 2)
		require.Len(t, fake.watchCalls[0], 100)
		require.Len(t, fake.watchCalls[1], 1)
	})

	t.Run("large_input_round_trips_intact", func(t *testing.T) {
		defer withChunkSize(t, 250)()
		fake := &fakeWalletClient{}
		c := &walletDaemonClient{client: fake}
		scripts := makeScripts(1000)
		require.NoError(t, c.WatchScripts(context.Background(), scripts))
		// Expect 4 chunks of 250 each.
		require.Len(t, fake.watchCalls, 4)
		for _, c := range fake.watchCalls {
			require.Len(t, c, 250)
		}
		// Reassemble and confirm order plus completeness.
		var reassembled []string
		for _, c := range fake.watchCalls {
			reassembled = append(reassembled, c...)
		}
		require.Equal(t, scripts, reassembled)
	})

	t.Run("error_on_middle_chunk_short_circuits", func(t *testing.T) {
		defer withChunkSize(t, 10)()
		boom := errors.New("simulated grpc failure")
		fake := &fakeWalletClient{failOnCallIdx: 3, failErr: boom}
		c := &walletDaemonClient{client: fake}
		err := c.WatchScripts(context.Background(), makeScripts(100))
		require.ErrorIs(t, err, boom)
		// Three chunks attempted, the third returned the error. No further
		// calls should fire.
		require.Len(t, fake.watchCalls, 3)
	})
}

func TestWalletClientUnwatchScriptsChunking(t *testing.T) {
	t.Run("empty_input_no_calls", func(t *testing.T) {
		fake := &fakeWalletClient{}
		c := &walletDaemonClient{client: fake}
		require.NoError(t, c.UnwatchScripts(context.Background(), nil))
		require.Empty(t, fake.unwatchCalls)
	})

	t.Run("splits_above_boundary", func(t *testing.T) {
		defer withChunkSize(t, 50)()
		fake := &fakeWalletClient{}
		c := &walletDaemonClient{client: fake}
		require.NoError(t, c.UnwatchScripts(context.Background(), makeScripts(151)))
		require.Len(t, fake.unwatchCalls, 4)
		require.Len(t, fake.unwatchCalls[3], 1)
	})

	t.Run("error_propagates", func(t *testing.T) {
		defer withChunkSize(t, 5)()
		boom := fmt.Errorf("nope")
		fake := &fakeWalletClient{failOnCallIdx: 1, failErr: boom}
		c := &walletDaemonClient{client: fake}
		err := c.UnwatchScripts(context.Background(), makeScripts(20))
		require.ErrorIs(t, err, boom)
		require.Len(t, fake.unwatchCalls, 1)
	})
}
