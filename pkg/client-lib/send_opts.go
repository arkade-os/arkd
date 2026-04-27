package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type SendOption func(options *sendOptions) error

func WithoutExpirySorting() SendOption {
	return func(o *sendOptions) error {
		o.withoutExpirySorting = true
		return nil
	}
}

func WithVtxos(vtxos []types.VtxoWithTapTree) SendOption {
	return func(o *sendOptions) error {
		if len(o.vtxos) > 0 {
			return fmt.Errorf("vtxos already set")
		}
		if len(vtxos) <= 0 {
			return fmt.Errorf("missing vtxos")
		}
		o.vtxos = make([]types.VtxoWithTapTree, len(vtxos))
		copy(o.vtxos, vtxos)
		return nil
	}
}

// WithExtraPacket appends extra extension.Packet values to the
// OP_RETURN extension blob that is included in the ark transaction alongside
// the asset packet (type 0x00).
//
// Type 0x00 is reserved for the asset packet, automatically built depending on the Transaction.
// Passing type 0x00 returns an error.
//
// Duplicate packet types are not permitted.
func WithExtraPacket(packets ...extension.Packet) SendOption {
	return func(o *sendOptions) error {
		for _, p := range packets {
			if p == nil {
				return fmt.Errorf("extension packet must not be nil")
			}
			if p.Type() == asset.PacketType {
				return fmt.Errorf(
					"packet type 0x%02x is reserved for the asset packet",
					asset.PacketType,
				)
			}
		}
		o.extraPackets = append(o.extraPackets, packets...)
		return nil
	}
}

type sendOptions struct {
	withoutExpirySorting  bool
	vtxos                 []types.VtxoWithTapTree
	extraPackets []extension.Packet
}

func newDefaultSendOptions() *sendOptions {
	return &sendOptions{}
}
