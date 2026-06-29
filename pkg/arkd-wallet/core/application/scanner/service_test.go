package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestConnection(t *testing.T) {
	startScanner := func(t *testing.T, fake *fakeNbxplorer, initialBackoff, maxBackoff time.Duration) *scanner {
		t.Helper()

		s := &scanner{
			nbxplorer:             fake,
			chainParams:           &chaincfg.RegressionNetParams,
			notificationListeners: make([]chan map[string][]application.Utxo, 0),
			initialBackoff:        initialBackoff,
			maxBackoff:            maxBackoff,
		}
		require.NoError(t, s.start(t.Context()))
		return s
	}

	addListeners := func(s *scanner, count int) []chan map[string][]application.Utxo {
		listeners := make([]chan map[string][]application.Utxo, count)
		s.lock.Lock()
		defer s.lock.Unlock()
		for i := range listeners {
			listeners[i] = make(chan map[string][]application.Utxo, 128)
			s.notificationListeners = append(s.notificationListeners, listeners[i])
		}
		return listeners
	}

	expectNotification := func(t *testing.T, ch <-chan map[string][]application.Utxo, script string, value uint64, timeout time.Duration) {
		t.Helper()

		select {
		case msg := <-ch:
			require.Len(t, msg, 1)
			utxos := msg[script]
			require.Len(t, utxos, 1)
			require.Equal(t, script, utxos[0].Script)
			require.EqualValues(t, value, utxos[0].Value)
		case <-time.After(timeout):
			require.Fail(t, "timeout waiting for notification")
		}
	}

	t.Run("fanout to listeners", func(t *testing.T) {
		notifCh := make(chan []ports.Utxo, 1)
		fake := &fakeNbxplorer{notifChs: []chan []ports.Utxo{notifCh}}
		listeners := addListeners(startScanner(t, fake, defaultInitialBackoff, defaultMaxBackoff), 2)

		notifCh <- []ports.Utxo{{
			OutPoint: wire.OutPoint{Index: 0},
			Script:   "deadbeef",
			Value:    1000,
		}}

		for _, listener := range listeners {
			expectNotification(t, listener, "deadbeef", 1000, time.Second)
		}
	})

	t.Run("reconnects on closed channel", func(t *testing.T) {
		firstCh := make(chan []ports.Utxo)
		secondCh := make(chan []ports.Utxo, 1)
		fake := &fakeNbxplorer{notifChs: []chan []ports.Utxo{firstCh, secondCh}}
		listener := addListeners(startScanner(t, fake, 10*time.Millisecond, 50*time.Millisecond), 1)[0]

		close(firstCh)
		secondCh <- []ports.Utxo{{
			OutPoint: wire.OutPoint{Index: 1},
			Script:   "cafebabe",
			Value:    5000,
		}}

		expectNotification(t, listener, "cafebabe", 5000, 2*time.Second)
		require.GreaterOrEqual(t, fake.calls(), 2)
	})

	t.Run("reconnects multiple times", func(t *testing.T) {
		ch1 := make(chan []ports.Utxo)
		ch2 := make(chan []ports.Utxo)
		ch3 := make(chan []ports.Utxo, 1)
		fake := &fakeNbxplorer{notifChs: []chan []ports.Utxo{ch1, ch2, ch3}}
		listener := addListeners(startScanner(t, fake, 5*time.Millisecond, 20*time.Millisecond), 1)[0]

		close(ch1)
		close(ch2)
		ch3 <- []ports.Utxo{{
			OutPoint: wire.OutPoint{Index: 2},
			Script:   "f00dface",
			Value:    9000,
		}}

		expectNotification(t, listener, "f00dface", 9000, 2*time.Second)
		require.GreaterOrEqual(t, fake.calls(), 3)
	})
}

type fakeNbxplorer struct {
	ports.Nbxplorer

	mu         sync.Mutex
	notifChs   []chan []ports.Utxo
	callIdx    int
	initialErr error
}

func (f *fakeNbxplorer) GetAddressNotifications(ctx context.Context) (<-chan []ports.Utxo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.callIdx
	f.callIdx++
	if idx == 0 && f.initialErr != nil {
		return nil, f.initialErr
	}
	if idx >= len(f.notifChs) {
		ch := make(chan []ports.Utxo)
		return ch, nil
	}
	return f.notifChs[idx], nil
}

func (f *fakeNbxplorer) Close() error { return nil }

func (f *fakeNbxplorer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callIdx
}
