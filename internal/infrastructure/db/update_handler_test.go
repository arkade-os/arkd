package db

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestUpdateHandlerSet(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name    string
			numSets int
		}{
			{
				name:    "sets handler when unset",
				numSets: 1,
			},
			{
				name:    "ignores second set (write-once)",
				numSets: 2,
			},
			{
				name:    "ignores all subsequent sets",
				numSets: 5,
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				h := newUpdateHandler[domain.OffchainTx]()

				var active atomic.Int32
				for i := 0; i < f.numSets; i++ {
					id := int32(i + 1)
					h.set(func(data domain.OffchainTx) {
						active.Store(id)
					})
				}

				h.dispatch(domain.OffchainTx{})

				// Only the first handler ever installed should run.
				require.Eventually(t, func() bool {
					return active.Load() == 1
				}, time.Second, 10*time.Millisecond)
			})
		}
	})
}

func TestUpdateHandlerDispatch(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name string
			data domain.OffchainTx
		}{
			{
				name: "dispatches data to handler",
				data: domain.OffchainTx{},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				h := newUpdateHandler[domain.OffchainTx]()

				received := make(chan domain.OffchainTx, 1)
				h.set(func(data domain.OffchainTx) {
					received <- data
				})

				h.dispatch(f.data)

				select {
				case got := <-received:
					require.Equal(t, f.data.ArkTxid, got.ArkTxid)
				case <-time.After(time.Second):
					t.Fatal("handler was not invoked within timeout")
				}
			})
		}

		t.Run("does not block the caller", func(t *testing.T) {
			h := newUpdateHandler[domain.OffchainTx]()

			release := make(chan struct{})
			entered := make(chan struct{})
			h.set(func(data domain.OffchainTx) {
				close(entered)
				<-release
			})

			start := time.Now()
			h.dispatch(domain.OffchainTx{})
			require.Less(t, time.Since(start), 100*time.Millisecond)

			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("handler goroutine did not start")
			}
			close(release)
		})

		t.Run("no-op when handler not set", func(t *testing.T) {
			h := newUpdateHandler[domain.OffchainTx]()

			require.NotPanics(t, func() {
				h.dispatch(domain.OffchainTx{})
			})
		})
	})
}
