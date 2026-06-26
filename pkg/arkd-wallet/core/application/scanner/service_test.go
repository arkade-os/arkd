package scanner

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

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

func TestNew_InitialGetAddressNotificationsError(t *testing.T) {
	fake := &fakeNbxplorer{
		initialErr: fmt.Errorf("nbxplorer unavailable"),
	}
	_, err := New(fake, "regtest")
	require.Error(t, err)
}

func TestStart_FanoutToListeners(t *testing.T) {
	notifCh := make(chan []ports.Utxo, 1)
	fake := &fakeNbxplorer{
		notifChs: []chan []ports.Utxo{notifCh},
	}

	ctx := t.Context()

	s := &scanner{
		nbxplorer:             fake,
		chainParams:           &chaincfg.RegressionNetParams,
		notificationListeners: make([]chan map[string][]application.Utxo, 0),
	}
	require.NoError(t, s.start(ctx))

	listener1 := make(chan map[string][]application.Utxo, 128)
	listener2 := make(chan map[string][]application.Utxo, 128)
	s.lock.Lock()
	s.notificationListeners = append(s.notificationListeners, listener1, listener2)
	s.lock.Unlock()

	notifCh <- []ports.Utxo{{
		OutPoint: wire.OutPoint{Index: 0},
		Script:   "deadbeef",
		Value:    1000,
	}}

	expectNotification := func(ch <-chan map[string][]application.Utxo) {
		select {
		case msg := <-ch:
			require.Len(t, msg, 1)
			utxos := msg["deadbeef"]
			require.Len(t, utxos, 1)
			require.Equal(t, "deadbeef", utxos[0].Script)
			require.EqualValues(t, 1000, utxos[0].Value)
		case <-time.After(time.Second):
			require.Fail(t, "timeout waiting for notification")
		}
	}

	expectNotification(listener1)
	expectNotification(listener2)
}

func TestStart_ReconnectsOnClosedChannel(t *testing.T) {
	initialBackoff = 10 * time.Millisecond
	maxBackoff = 50 * time.Millisecond
	defer func() {
		initialBackoff = time.Second
		maxBackoff = 30 * time.Second
	}()

	firstCh := make(chan []ports.Utxo)
	secondCh := make(chan []ports.Utxo, 1)
	fake := &fakeNbxplorer{
		notifChs: []chan []ports.Utxo{firstCh, secondCh},
	}

	ctx := t.Context()

	s := &scanner{
		nbxplorer:             fake,
		chainParams:           &chaincfg.RegressionNetParams,
		notificationListeners: make([]chan map[string][]application.Utxo, 0),
	}
	require.NoError(t, s.start(ctx))

	listener := make(chan map[string][]application.Utxo, 128)
	s.lock.Lock()
	s.notificationListeners = append(s.notificationListeners, listener)
	s.lock.Unlock()

	close(firstCh)

	secondCh <- []ports.Utxo{{
		OutPoint: wire.OutPoint{Index: 1},
		Script:   "cafebabe",
		Value:    5000,
	}}

	select {
	case msg := <-listener:
		require.Len(t, msg, 1)
		utxos := msg["cafebabe"]
		require.Len(t, utxos, 1)
		require.Equal(t, "cafebabe", utxos[0].Script)
		require.EqualValues(t, 5000, utxos[0].Value)
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for notification after reconnect")
	}
	require.GreaterOrEqual(t, fake.calls(), 2)
}

func TestStart_ReconnectsMultipleTimes(t *testing.T) {
	initialBackoff = 5 * time.Millisecond
	maxBackoff = 20 * time.Millisecond
	defer func() {
		initialBackoff = time.Second
		maxBackoff = 30 * time.Second
	}()

	ch1 := make(chan []ports.Utxo)
	ch2 := make(chan []ports.Utxo)
	ch3 := make(chan []ports.Utxo, 1)
	fake := &fakeNbxplorer{
		notifChs: []chan []ports.Utxo{ch1, ch2, ch3},
	}

	ctx := t.Context()

	s := &scanner{
		nbxplorer:             fake,
		chainParams:           &chaincfg.RegressionNetParams,
		notificationListeners: make([]chan map[string][]application.Utxo, 0),
	}
	require.NoError(t, s.start(ctx))

	listener := make(chan map[string][]application.Utxo, 128)
	s.lock.Lock()
	s.notificationListeners = append(s.notificationListeners, listener)
	s.lock.Unlock()

	close(ch1)
	close(ch2)
	ch3 <- []ports.Utxo{{
		OutPoint: wire.OutPoint{Index: 2},
		Script:   "f00dface",
		Value:    9000,
	}}

	select {
	case msg := <-listener:
		require.Len(t, msg, 1)
		utxos := msg["f00dface"]
		require.Len(t, utxos, 1)
		require.Equal(t, "f00dface", utxos[0].Script)
		require.EqualValues(t, 9000, utxos[0].Value)
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for notification after multiple reconnects")
	}
	require.GreaterOrEqual(t, fake.calls(), 3)
}
