package wallet

import (
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

type WalletOption func(*wallet)

func WithVerbose() WalletOption {
	return func(w *wallet) {
		w.verbose = true
	}
}

func WithExplorer(explorer clientlib.Explorer) WalletOption {
	return func(w *wallet) {
		w.explorer = explorer
	}
}

func WithIdentity(identitySvc clientlib.Identity) WalletOption {
	return func(w *wallet) {
		w.identity = identitySvc
	}
}

func WithoutFinalizePendingTxs() WalletOption {
	return func(w *wallet) {
		w.withFinalizePendingTxs = false
	}
}

func WithClientVersion(version string) WalletOption {
	return func(w *wallet) {
		w.clientVersion = version
	}
}
