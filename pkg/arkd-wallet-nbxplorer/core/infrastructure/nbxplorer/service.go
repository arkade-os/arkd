package nbxplorer

import (
	"context"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type nbxplorer struct {
	url string
}

func New(url string) ports.Nbxplorer {
	return &nbxplorer{
		url: url,
	}
}

// AddAddressToGroup implements ports.Nbxplorer.
func (n *nbxplorer) AddAddressToGroup(ctx context.Context, groupID string, addresses ...string) error {
	panic("unimplemented")
}

// BroadcastTransaction implements ports.Nbxplorer.
func (n *nbxplorer) BroadcastTransaction(ctx context.Context, txs ...string) (string, error) {
	panic("unimplemented")
}

// CreateGroup implements ports.Nbxplorer.
func (n *nbxplorer) CreateGroup(ctx context.Context, groupID string) error {
	panic("unimplemented")
}

// EstimateFeeRate implements ports.Nbxplorer.
func (n *nbxplorer) EstimateFeeRate(ctx context.Context) (chainfee.SatPerKVByte, error) {
	panic("unimplemented")
}

// GetBalance implements ports.Nbxplorer.
func (n *nbxplorer) GetBalance(ctx context.Context, derivationScheme string) (confirmed uint64, unconfirmed uint64, err error) {
	panic("unimplemented")
}

// GetBitcoinStatus implements ports.Nbxplorer.
func (n *nbxplorer) GetBitcoinStatus(ctx context.Context) (ports.BitcoinStatus, error) {
	panic("unimplemented")
}

// GetGroupNotifications implements ports.Nbxplorer.
func (n *nbxplorer) GetGroupNotifications(ctx context.Context, groupID string) (<-chan []ports.Utxo, error) {
	panic("unimplemented")
}

// GetNewUnusedAddress implements ports.Nbxplorer.
func (n *nbxplorer) GetNewUnusedAddress(ctx context.Context, derivationScheme string, change bool, skip int) (string, error) {
	panic("unimplemented")
}

// GetScriptPubKeyDetails implements ports.Nbxplorer.
func (n *nbxplorer) GetScriptPubKeyDetails(ctx context.Context, derivationScheme string, script string) (ports.ScriptPubKeyDetails, error) {
	panic("unimplemented")
}

// GetTransaction implements ports.Nbxplorer.
func (n *nbxplorer) GetTransaction(ctx context.Context, txid string) (ports.TransactionDetails, error) {
	panic("unimplemented")
}

// GetUtxos implements ports.Nbxplorer.
func (n *nbxplorer) GetUtxos(ctx context.Context, derivationScheme string) ([]ports.Utxo, error) {
	panic("unimplemented")
}

// RemoveAddressFromGroup implements ports.Nbxplorer.
func (n *nbxplorer) RemoveAddressFromGroup(ctx context.Context, groupID string, addresses ...string) error {
	panic("unimplemented")
}

// ScanUtxoSet implements ports.Nbxplorer.
func (n *nbxplorer) ScanUtxoSet(ctx context.Context, derivationScheme string, gapLimit int) <-chan ports.ScanUtxoSetProgress {
	panic("unimplemented")
}

// Track implements ports.Nbxplorer.
func (n *nbxplorer) Track(ctx context.Context, derivationScheme string) error {
	panic("unimplemented")
}
