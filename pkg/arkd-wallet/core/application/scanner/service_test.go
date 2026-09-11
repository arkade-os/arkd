package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestConnection(t *testing.T) {
	startScanner := func(t *testing.T, fake *fakeNbxplorer, initialBackoff, maxBackoff time.Duration) *scanner {
		t.Helper()

		s := &scanner{
			nbxplorer:             fake,
			chainParams:           &chaincfg.RegressionNetParams,
			notificationListeners: make([]chan map[string][]application.Utxo, 0),
			spendListeners:        make([]chan []application.Spend, 0),
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
		notifCh := make(chan ports.ChainNotification, 1)
		fake := &fakeNbxplorer{notifChs: []chan ports.ChainNotification{notifCh}}
		listeners := addListeners(startScanner(t, fake, defaultInitialBackoff, defaultMaxBackoff), 2)

		notifCh <- ports.ChainNotification{Utxos: []ports.Utxo{{
			OutPoint: wire.OutPoint{Index: 0},
			Script:   "deadbeef",
			Value:    1000,
		}}}

		for _, listener := range listeners {
			expectNotification(t, listener, "deadbeef", 1000, time.Second)
		}
	})

	t.Run("reconnects on closed channel", func(t *testing.T) {
		firstCh := make(chan ports.ChainNotification)
		secondCh := make(chan ports.ChainNotification, 1)
		fake := &fakeNbxplorer{notifChs: []chan ports.ChainNotification{firstCh, secondCh}}
		listener := addListeners(startScanner(t, fake, 10*time.Millisecond, 50*time.Millisecond), 1)[0]

		close(firstCh)
		secondCh <- ports.ChainNotification{Utxos: []ports.Utxo{{
			OutPoint: wire.OutPoint{Index: 1},
			Script:   "cafebabe",
			Value:    5000,
		}}}

		expectNotification(t, listener, "cafebabe", 5000, 2*time.Second)
		require.GreaterOrEqual(t, fake.calls(), 2)
	})

	t.Run("removes listener on ctx cancel", func(t *testing.T) {
		fake := &fakeNbxplorer{}
		s := startScanner(t, fake, defaultInitialBackoff, defaultMaxBackoff)

		cancelledCtx, cancel := context.WithCancel(t.Context())
		s.GetNotificationChannel(cancelledCtx)
		s.GetNotificationChannel(t.Context())

		cancel()

		listenerCount := func() int {
			s.lock.RLock()
			defer s.lock.RUnlock()
			return len(s.notificationListeners)
		}
		require.Eventually(t, func() bool {
			return listenerCount() == 1
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("reconnects multiple times", func(t *testing.T) {
		ch1 := make(chan ports.ChainNotification)
		ch2 := make(chan ports.ChainNotification)
		ch3 := make(chan ports.ChainNotification, 1)
		fake := &fakeNbxplorer{notifChs: []chan ports.ChainNotification{ch1, ch2, ch3}}
		listener := addListeners(startScanner(t, fake, 5*time.Millisecond, 20*time.Millisecond), 1)[0]

		close(ch1)
		close(ch2)
		ch3 <- ports.ChainNotification{Utxos: []ports.Utxo{{
			OutPoint: wire.OutPoint{Index: 2},
			Script:   "f00dface",
			Value:    9000,
		}}}

		expectNotification(t, listener, "f00dface", 9000, 2*time.Second)
		require.GreaterOrEqual(t, fake.calls(), 3)
	})
}

// TestSpendFanout covers the half of a chain notification that searchNewUTXOs
// cannot see. A transaction spending a watched output creates no new UTXO at
// that script, so before spends were carried alongside the UTXOs the event was
// indistinguishable from nothing having happened.
func TestSpendFanout(t *testing.T) {
	newScanner := func(t *testing.T, fake *fakeNbxplorer) *scanner {
		t.Helper()
		s := &scanner{
			nbxplorer:             fake,
			chainParams:           &chaincfg.RegressionNetParams,
			notificationListeners: make([]chan map[string][]application.Utxo, 0),
			spendListeners:        make([]chan []application.Spend, 0),
			initialBackoff:        defaultInitialBackoff,
			maxBackoff:            defaultMaxBackoff,
		}
		require.NoError(t, s.start(t.Context()))
		return s
	}

	spentHash, err := chainhash.NewHashFromStr(
		"4ba63c204f39841e3a7c98e458586307cf6d33bbed9a9a520c827ab043f32701",
	)
	require.NoError(t, err)

	t.Run("delivers spends with no new utxos", func(t *testing.T) {
		notifCh := make(chan ports.ChainNotification, 1)
		fake := &fakeNbxplorer{notifChs: []chan ports.ChainNotification{notifCh}}
		s := newScanner(t, fake)
		spendCh := s.GetSpendNotificationChannel(t.Context())
		utxoCh := s.GetNotificationChannel(t.Context())

		notifCh <- ports.ChainNotification{
			Spends: []ports.Spend{{
				OutPoint:      wire.OutPoint{Hash: *spentHash, Index: 0},
				SpendingTxid:  "0e85af9b9c0fe73b82cd59a46b333cd312b830706cf82dda856c81d0d09e1f72",
				Confirmations: 3,
			}},
		}

		select {
		case spends := <-spendCh:
			require.Len(t, spends, 1)
			require.Equal(t, spentHash.String(), spends[0].Txid)
			require.EqualValues(t, 0, spends[0].Index)
			require.Equal(
				t,
				"0e85af9b9c0fe73b82cd59a46b333cd312b830706cf82dda856c81d0d09e1f72",
				spends[0].SpendingTxid,
			)
			require.EqualValues(t, 3, spends[0].Confirmations)
		case <-time.After(time.Second):
			require.Fail(t, "timeout waiting for spend notification")
		}

		// A spend-only notification must not wake the utxo listeners with an
		// empty map, which consumers would otherwise treat as a real event.
		select {
		case msg := <-utxoCh:
			require.Fail(t, "unexpected utxo notification", "got %v", msg)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("removes spend listener on ctx cancel", func(t *testing.T) {
		fake := &fakeNbxplorer{}
		s := newScanner(t, fake)

		cancelledCtx, cancel := context.WithCancel(t.Context())
		s.GetSpendNotificationChannel(cancelledCtx)
		s.GetSpendNotificationChannel(t.Context())

		cancel()

		listenerCount := func() int {
			s.lock.RLock()
			defer s.lock.RUnlock()
			return len(s.spendListeners)
		}
		require.Eventually(t, func() bool {
			return listenerCount() == 1
		}, time.Second, 10*time.Millisecond)
	})
}

type fakeNbxplorer struct {
	ports.Nbxplorer

	mu         sync.Mutex
	notifChs   []chan ports.ChainNotification
	callIdx    int
	initialErr error
}

func (f *fakeNbxplorer) GetAddressNotifications(ctx context.Context) (<-chan ports.ChainNotification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.callIdx
	f.callIdx++
	if idx == 0 && f.initialErr != nil {
		return nil, f.initialErr
	}
	if idx >= len(f.notifChs) {
		ch := make(chan ports.ChainNotification)
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
