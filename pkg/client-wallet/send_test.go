package wallet

import (
	"context"
	"errors"
	"sync"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

// errStopRead ends a spend at its first read of wallet state, so the tests need no server.
var errStopRead = errors.New("stop at first read")

// lockProbe records, at each read of wallet state, whether txLock was held at that moment.
type lockProbe struct {
	lock     *sync.RWMutex
	observed []bool
}

// probeIdentity is an unlocked identity whose ListKeys, the first step of every VTXO read,
// reports to the probe.
type probeIdentity struct {
	clientlib.Identity
	probe *lockProbe
}

// probeIndexer reports the control asset lookup that ReissueAsset makes before it reads VTXOs.
type probeIndexer struct {
	clientlib.Indexer
	probe *lockProbe
}

func TestSendOffChain(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("reads vtxos under txLock", func(t *testing.T) {
			requireReadsUnderTxLock(t, func(ctx context.Context, w *wallet) error {
				_, err := w.SendOffChain(ctx, nil)
				return err
			})
		})
	})
}

// requireReadsUnderTxLock runs spend on a wallet whose first read of wallet state fails, and
// requires that txLock was already held at that read and was released when spend returned.
func requireReadsUnderTxLock(t *testing.T, spend func(context.Context, *wallet) error) {
	t.Helper()

	lock := &sync.RWMutex{}
	probe := &lockProbe{lock: lock}
	w := &wallet{
		identity: probeIdentity{probe: probe},
		indexer:  probeIndexer{probe: probe},
		txLock:   lock,
	}

	require.ErrorIs(t, spend(t.Context(), w), errStopRead)
	require.Equal(t, []bool{true}, probe.observed)
	require.True(t, lock.TryLock())
	lock.Unlock()
}

func (p *lockProbe) record() error {
	held := !p.lock.TryLock()
	if !held {
		p.lock.Unlock()
	}
	p.observed = append(p.observed, held)
	return errStopRead
}

func (i probeIdentity) IsLocked() bool { return false }

func (i probeIdentity) ListKeys(context.Context) ([]clientlib.KeyRef, error) {
	return nil, i.probe.record()
}

func (i probeIndexer) GetAsset(context.Context, string) (*clientlib.AssetInfo, error) {
	return nil, i.probe.record()
}
