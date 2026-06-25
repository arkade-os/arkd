package utils_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/stretchr/testify/require"
)

// drainOK is the duration we're willing to wait for asynchronous removals or
// channel closes triggered by the broadcaster. Kept short so the suite stays
// snappy; bump it if CI proves flaky on slow runners.
const drainOK = 200 * time.Millisecond

// expectReceive asserts the channel yields the expected value within drainOK.
func expectReceive[T comparable](t *testing.T, ch <-chan T, want T) {
	t.Helper()
	select {
	case got, ok := <-ch:
		require.True(t, ok, "channel was closed before receiving the expected value")
		require.Equal(t, want, got)
	case <-time.After(drainOK):
		t.Fatalf("expected to receive %v within %s, got nothing", want, drainOK)
	}
}

// expectClosed asserts the channel is closed within drainOK (Recv returns zero
// value with ok=false). Used to verify post-Unsubscribe / Close semantics.
func expectClosed[T any](t *testing.T, ch <-chan T) {
	t.Helper()
	select {
	case _, ok := <-ch:
		require.False(t, ok, "expected channel to be closed, got a value")
	case <-time.After(drainOK):
		t.Fatalf("expected channel to be closed within %s", drainOK)
	}
}

func TestBroadcaster(t *testing.T) {
	t.Run("subscribe receives published values", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		defer b.Close()

		ch := b.Subscribe(4)
		dropped := b.Publish(42)
		require.Equal(t, 0, dropped)

		expectReceive(t, ch, 42)
	})

	t.Run("multiple subscribers each receive a copy", func(t *testing.T) {
		b := utils.NewBroadcaster[string]()
		defer b.Close()

		ch1 := b.Subscribe(4)
		ch2 := b.Subscribe(4)
		ch3 := b.Subscribe(4)

		require.Equal(t, 0, b.Publish("hello"))

		expectReceive(t, ch1, "hello")
		expectReceive(t, ch2, "hello")
		expectReceive(t, ch3, "hello")
	})

	t.Run("buf=0 defaults to 64", func(t *testing.T) {
		// Publish 64 values without consuming; none should be dropped because
		// the default buffer absorbs them all. The 65th publish should drop
		// the subscriber (overflow).
		b := utils.NewBroadcaster[int]()
		defer b.Close()

		ch := b.Subscribe(0)

		for i := 0; i < 64; i++ {
			require.Equal(t, 0, b.Publish(i), "publish #%d should not overflow with the default buffer", i)
		}
		require.Equal(t, 1, b.Publish(64), "65th publish should overflow and drop the slow subscriber")

		// After overflow, the broadcaster removes the listener asynchronously
		// and closes its channel. Drain the 64 buffered items first, then
		// confirm the channel is closed.
		for i := 0; i < 64; i++ {
			expectReceive(t, ch, i)
		}
		expectClosed(t, ch)
	})

	t.Run("unsubscribe closes channel and stops delivery", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		defer b.Close()

		ch := b.Subscribe(4)
		b.Unsubscribe(ch)

		expectClosed(t, ch)

		// A subsequent publish to no remaining listener is a no-op (0 dropped).
		require.Equal(t, 0, b.Publish(99))
	})

	t.Run("unsubscribe with unknown channel is a no-op", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		defer b.Close()

		registered := b.Subscribe(4)

		// A channel that was never subscribed.
		stranger := make(chan int, 1)
		b.Unsubscribe(stranger)

		// The registered subscriber is still active and reachable.
		require.Equal(t, 0, b.Publish(7))
		expectReceive(t, registered, 7)

		// The stranger channel was untouched (still open, no panic).
		select {
		case _, ok := <-stranger:
			t.Fatalf("stranger channel should remain untouched, got ok=%v", ok)
		default:
		}
	})

	t.Run("slow subscriber is dropped and channel is closed", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		defer b.Close()

		fast := b.Subscribe(4)
		slow := b.Subscribe(1)

		// First publish fits both buffers.
		require.Equal(t, 0, b.Publish(1))
		// Second publish: fast still has room, slow's buffer is full → dropped.
		require.Equal(t, 1, b.Publish(2))

		// Fast subscriber sees both values.
		expectReceive(t, fast, 1)
		expectReceive(t, fast, 2)

		// Slow subscriber received the first value before its channel was closed
		// asynchronously by the broadcaster.
		expectReceive(t, slow, 1)
		expectClosed(t, slow)
	})

	t.Run("publish returns count of dropped listeners across the fleet", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		defer b.Close()

		ok1 := b.Subscribe(4)
		ok2 := b.Subscribe(4)
		slow1 := b.Subscribe(1)
		slow2 := b.Subscribe(1)

		// Fill the slow ones' buffers so the next publish overflows both.
		require.Equal(t, 0, b.Publish(1))
		require.Equal(t, 2, b.Publish(2), "two slow subscribers should be dropped on the second publish")

		// Healthy subscribers still get both.
		expectReceive(t, ok1, 1)
		expectReceive(t, ok1, 2)
		expectReceive(t, ok2, 1)
		expectReceive(t, ok2, 2)

		// Slow ones got #1 before being dropped, then their channels close.
		expectReceive(t, slow1, 1)
		expectClosed(t, slow1)
		expectReceive(t, slow2, 1)
		expectClosed(t, slow2)
	})

	t.Run("close closes all subscriber channels", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()

		ch1 := b.Subscribe(4)
		ch2 := b.Subscribe(4)

		b.Close()

		expectClosed(t, ch1)
		expectClosed(t, ch2)
	})

	t.Run("subscribe after close returns an already-closed channel", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		b.Close()

		ch := b.Subscribe(4)
		expectClosed(t, ch)
	})

	t.Run("publish after close drops nothing and does not panic", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		b.Close()

		require.NotPanics(t, func() {
			require.Equal(t, 0, b.Publish(1))
		})
	})

	t.Run("close is idempotent", func(t *testing.T) {
		b := utils.NewBroadcaster[int]()
		_ = b.Subscribe(4)

		require.NotPanics(t, func() {
			b.Close()
			b.Close()
		})
	})

	t.Run("concurrent publishers and subscribers", func(t *testing.T) {
		// Stress test under the race detector: many concurrent producers,
		// subscribers, unsubscribers. The contract we assert: no panics, no
		// deadlocks, and the broadcaster terminates cleanly via Close.
		b := utils.NewBroadcaster[int]()

		const (
			producers   = 8
			subscribers = 16
			publishes   = 200
		)

		var (
			wg          sync.WaitGroup
			startSignal = make(chan struct{})
			received    atomic.Int64
		)

		// Subscribers consume until their channel closes.
		for i := 0; i < subscribers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ch := b.Subscribe(8)
				<-startSignal
				for range ch {
					received.Add(1)
				}
			}()
		}

		// Producers publish in parallel.
		for i := 0; i < producers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-startSignal
				for j := 0; j < publishes; j++ {
					b.Publish(id*1000 + j)
				}
			}(i)
		}

		close(startSignal)

		// Give producers a moment to actually push some values, then close
		// the broadcaster. All subscribers should drain and exit.
		time.Sleep(50 * time.Millisecond)
		b.Close()
		wg.Wait()

		require.Greater(t, received.Load(), int64(0),
			"at least some values should have been received before Close")
	})
}
