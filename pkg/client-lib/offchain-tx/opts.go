package offchaintx

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
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

type optFn func(*options) error

func (f optFn) apply(o *options) error { return f(o) }

type options struct {
	extraPackets []extension.Packet
}

func newOptions() *options {
	return &options{}
}
