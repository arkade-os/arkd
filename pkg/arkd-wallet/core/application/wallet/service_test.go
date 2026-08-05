package wallet

import (
	"context"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// fakeNbxplorer is a minimal ports.Nbxplorer used to count script lookups.
type fakeNbxplorer struct {
	getScriptCalls int
	scriptDetails  func(scheme, script string) (*ports.ScriptPubKeyDetails, error)
}

var _ ports.Nbxplorer = (*fakeNbxplorer)(nil)

func (f *fakeNbxplorer) GetScriptPubKeyDetails(
	_ context.Context, scheme, script string,
) (*ports.ScriptPubKeyDetails, error) {
	f.getScriptCalls++
	if f.scriptDetails != nil {
		return f.scriptDetails(scheme, script)
	}
	return nil, fmt.Errorf("script not found")
}

func (f *fakeNbxplorer) GetBitcoinStatus(_ context.Context) (*ports.BitcoinStatus, error) {
	return nil, nil
}

func (f *fakeNbxplorer) GetTransaction(
	_ context.Context, _ string,
) (*ports.TransactionDetails, error) {
	return nil, nil
}

func (f *fakeNbxplorer) ScanUtxoSet(
	_ context.Context, _ string, _ int,
) <-chan ports.ScanUtxoSetProgress {
	return nil
}

func (f *fakeNbxplorer) Track(_ context.Context, _ string) error { return nil }

func (f *fakeNbxplorer) GetUtxos(_ context.Context, _ string) ([]ports.Utxo, error) {
	return nil, nil
}

func (f *fakeNbxplorer) GetNewUnusedAddress(
	_ context.Context, _ string, _ bool, _ int,
) (string, error) {
	return "", nil
}

func (f *fakeNbxplorer) EstimateFeeRate(_ context.Context) (chainfee.SatPerKVByte, error) {
	return 0, nil
}

func (f *fakeNbxplorer) BroadcastTransaction(_ context.Context, _ ...string) (string, error) {
	return "", nil
}

func (f *fakeNbxplorer) RescanUtxos(_ context.Context, _ []wire.OutPoint) error { return nil }

func (f *fakeNbxplorer) IsSpent(_ context.Context, _ wire.OutPoint) (bool, error) {
	return false, nil
}

func (f *fakeNbxplorer) WatchAddresses(_ context.Context, _ ...string) error   { return nil }
func (f *fakeNbxplorer) UnwatchAddresses(_ context.Context, _ ...string) error { return nil }

func (f *fakeNbxplorer) GetAddressNotifications(
	_ context.Context,
) (<-chan []ports.Utxo, error) {
	return nil, nil
}

func (f *fakeNbxplorer) Close() error { return nil }

func newTestWallet(t *testing.T, nbx ports.Nbxplorer) (*wallet, *keyManager) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x01
	}
	km, err := newKeyManager(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	w := &wallet{
		WalletOptions: WalletOptions{Nbxplorer: nbx, Network: "regtest"},
		keyMgr:        km,
		keyPaths:      newKeyPathCache(),
	}
	return w, km
}

func TestGetPrivateKeyFromScript(t *testing.T) {
	const script = "5120deadbeef"

	t.Run("locked wallet", func(t *testing.T) {
		w := &wallet{keyPaths: newKeyPathCache()}
		_, err := w.getPrivateKeyFromScript(context.Background(), script)
		require.ErrorIs(t, err, ErrWalletLocked)
	})

	t.Run("cache hit avoids nbxplorer lookup", func(t *testing.T) {
		fake := &fakeNbxplorer{}
		w, km := newTestWallet(t, fake)
		w.keyPaths.set(script, km.mainAccountDerivationScheme, "0/0")

		key, err := w.getPrivateKeyFromScript(context.Background(), script)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, 0, fake.getScriptCalls)
	})

	t.Run("cache miss falls back then backfills", func(t *testing.T) {
		fake := &fakeNbxplorer{}
		w, km := newTestWallet(t, fake)
		fake.scriptDetails = func(scheme, _ string) (*ports.ScriptPubKeyDetails, error) {
			if scheme == km.mainAccountDerivationScheme {
				return &ports.ScriptPubKeyDetails{KeyPath: "0/1"}, nil
			}
			return nil, fmt.Errorf("not found")
		}

		key, err := w.getPrivateKeyFromScript(context.Background(), script)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, 1, fake.getScriptCalls)

		// the second call must be served from the cache, no extra lookup.
		key2, err := w.getPrivateKeyFromScript(context.Background(), script)
		require.NoError(t, err)
		require.NotNil(t, key2)
		require.Equal(t, 1, fake.getScriptCalls)
	})

	t.Run("connector fallback performs two lookups", func(t *testing.T) {
		fake := &fakeNbxplorer{}
		w, km := newTestWallet(t, fake)
		fake.scriptDetails = func(scheme, _ string) (*ports.ScriptPubKeyDetails, error) {
			if scheme == km.connectorAccountDerivationScheme {
				return &ports.ScriptPubKeyDetails{KeyPath: "0/2"}, nil
			}
			return nil, fmt.Errorf("not found")
		}

		key, err := w.getPrivateKeyFromScript(context.Background(), script)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, 2, fake.getScriptCalls)
	})

	t.Run("empty key path from main scheme falls back to connector", func(t *testing.T) {
		fake := &fakeNbxplorer{}
		w, km := newTestWallet(t, fake)
		fake.scriptDetails = func(scheme, _ string) (*ports.ScriptPubKeyDetails, error) {
			if scheme == km.connectorAccountDerivationScheme {
				return &ports.ScriptPubKeyDetails{KeyPath: "0/3"}, nil
			}
			// main scheme answers without error but with an empty key path
			return &ports.ScriptPubKeyDetails{KeyPath: ""}, nil
		}

		key, err := w.getPrivateKeyFromScript(context.Background(), script)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, 2, fake.getScriptCalls)
	})

	t.Run("unknown script returns nil key after trying both schemes", func(t *testing.T) {
		fake := &fakeNbxplorer{}
		w, _ := newTestWallet(t, fake)

		key, err := w.getPrivateKeyFromScript(context.Background(), script)
		require.NoError(t, err)
		require.Nil(t, key)
		require.Equal(t, 2, fake.getScriptCalls)
	})
}

func TestCacheKeyPaths(t *testing.T) {
	w := &wallet{keyPaths: newKeyPathCache()}
	utxos := []ports.Utxo{
		{Script: "s1", KeyPath: "0/0"},
		{Script: "s2", KeyPath: "0/1"},
		{Script: "s3", KeyPath: ""}, // no key path: must not be cached
	}

	w.cacheKeyPaths("scheme-main", utxos)

	entry, ok := w.keyPaths.get("s1")
	require.True(t, ok)
	require.Equal(t, "scheme-main", entry.derivationScheme)
	require.Equal(t, "0/0", entry.keyPath)

	_, ok = w.keyPaths.get("s3")
	require.False(t, ok)
}
