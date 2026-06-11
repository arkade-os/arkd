package offchaintx

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
)

// Option customizes the behavior of an offchain-tx operation (Send,
// IssueAsset, ReissueAsset, BurnAsset, and their BuildAndSign* primitives).
// Use the With* helpers in this package to construct instances.
type Option interface {
	apply(*options) error
}

// WithExtraPacket appends extra extension.Packet values to the OP_RETURN
// extension blob included in the ark transaction alongside the asset packet
// (type 0x00). Type 0x00 is reserved and rejected. Duplicate packet types are
// not permitted.
func WithExtraPacket(packets ...extension.Packet) Option {
	return optFn(func(o *options) error {
		if len(packets) <= 0 {
			return fmt.Errorf("missing packet(s)")
		}
		seen := make(map[uint8]bool)
		for _, existing := range o.extraPackets {
			seen[existing.Type()] = true
		}
		for _, p := range packets {
			if p == nil {
				return fmt.Errorf("extension packet must not be nil")
			}
			if p.Type() == asset.PacketType {
				return fmt.Errorf(
					"packet type 0x%02x is reserved for the asset packet", asset.PacketType,
				)
			}
			if seen[p.Type()] {
				return fmt.Errorf("duplicated packet type 0x%02x", p.Type())
			}
			seen[p.Type()] = true
		}
		o.extraPackets = append(o.extraPackets, packets...)
		return nil
	})
}

// WithTxOutsTaprootTree sets the PSBT BIP-371 TaprootTapTree field on
// every output whose hex-encoded pkScript matches a key in the map. Callers
// pass the BIP-371-encoded tap tree bytes (via txutils.TapTree(scripts).Encode()).
// SendOffChain returns an error if any pkScript key matches no output of the
// ark tx, surfacing what would otherwise be a silent footgun for protocol-
// critical VTXO spending.
func WithTxOutsTaprootTree(tapTrees map[string][]byte) Option {
	return optFn(func(o *options) error {
		if len(tapTrees) <= 0 {
			return fmt.Errorf("missing taproot trees")
		}
		if o.outputsTapTree == nil {
			o.outputsTapTree = make(map[string][]byte, len(tapTrees))
		}
		for k, v := range tapTrees {
			if len(v) == 0 {
				return fmt.Errorf("receiver tap tree must not be empty")
			}
			if _, err := txutils.DecodeTapTree(v); err != nil {
				return fmt.Errorf("invalid bip-371 tap tree for tx out with script %s: %w", k, err)
			}
			cp := make([]byte, len(v))
			copy(cp, v)
			o.outputsTapTree[k] = cp
		}
		return nil
	})
}

type optFn func(*options) error

func (f optFn) apply(o *options) error { return f(o) }

type options struct {
	extraPackets   []extension.Packet
	outputsTapTree map[string][]byte // pkScript (hex) -> bip371 taptree
}

func newOptions() *options {
	return &options{}
}
