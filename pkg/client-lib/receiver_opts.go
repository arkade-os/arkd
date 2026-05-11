package wallet

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/btcsuite/btcd/btcutil"
)

// ReceiverOption is the intersection of every option family that accepts a
// destination/change address override. A value satisfying ReceiverOption can
// be passed to any method taking SendOption, BatchSessionOption, or
// UnrollOption — so WithReceiver is defined once here instead of duplicated
// per family. See SignOption in sign_opts.go for the same pattern.
type ReceiverOption interface {
	SendOption
	BatchSessionOption
	UnrollOption
}

type receiverOpt struct {
	addr string
}

func (r receiverOpt) applySend(o *sendOptions) error {
	if r.addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	if o.receiver != "" {
		return fmt.Errorf("receiver already set")
	}
	o.receiver = r.addr
	return nil
}

func (r receiverOpt) applyBatch(o *batchSessionOptions) error {
	if r.addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	if o.receiver != "" {
		return fmt.Errorf("receiver already set")
	}
	o.receiver = r.addr
	return nil
}

func (r receiverOpt) applyUnroll(o *unrollOptions) error {
	if r.addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	if o.receiver != "" {
		return fmt.Errorf("receiver already set")
	}
	o.receiver = r.addr
	return nil
}

// WithReceiver overrides the destination/change address that the method would
// otherwise freshly derive via identity.NewKey. Accepts an offchain ark address
// or an onchain bitcoin address; the consuming method validates which kinds
// are permitted (e.g. SendOffChain requires offchain; OnboardAgainAllExpiredBoardings
// requires onchain; Settle / CollaborativeExit accept either).
//
// Note: directing change to a known address weakens unlinkability — caller's
// choice. Skipping the identity.NewKey call also means no new key is recorded in
// the wallet for the change output.
func WithReceiver(addr string) ReceiverOption {
	return receiverOpt{addr: addr}
}

// validateOffchainAddress rejects everything that is not a valid offchain ark
// address. Used by methods whose receiver MUST be a vtxo destination
// (SendOffChain change, asset ops, RedeemNotes).
func validateOffchainAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	if _, err := arklib.DecodeAddressV0(addr); err != nil {
		return fmt.Errorf("invalid offchain receiver address: %w", err)
	}
	return nil
}

// validateOnchainAddress rejects everything that is not a valid onchain
// bitcoin address on the given network. Used by OnboardAgainAllExpiredBoardings.
func validateOnchainAddress(addr string, network arklib.Network) error {
	if addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	netParams := utils.ToBitcoinNetwork(network)
	if _, err := btcutil.DecodeAddress(addr, &netParams); err != nil {
		return fmt.Errorf("invalid onchain receiver address: %w", err)
	}
	return nil
}

// validateOffchainOrOnchainAddress accepts either an ark offchain address or
// a bitcoin onchain address on the given network. Used by Settle /
// CollaborativeExit, where batch-session outputs may legally be either.
func validateOffchainOrOnchainAddress(addr string, network arklib.Network) error {
	if addr == "" {
		return fmt.Errorf("missing receiver address")
	}
	if _, offErr := arklib.DecodeAddressV0(addr); offErr == nil {
		return nil
	}
	netParams := utils.ToBitcoinNetwork(network)
	if _, onErr := btcutil.DecodeAddress(addr, &netParams); onErr == nil {
		return nil
	}
	return fmt.Errorf(
		"invalid receiver address: not a valid offchain or onchain bitcoin address",
	)
}
