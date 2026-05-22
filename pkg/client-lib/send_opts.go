package wallet

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

// SendOption is satisfied by any value whose applySend method mutates a
// sendOptions. Interface-typed options let a single definition satisfy
// multiple option families — see WithKeys in sign_opts.go.
type SendOption interface {
	applySend(*sendOptions) error
}

type sendOptFn func(*sendOptions) error

func (f sendOptFn) applySend(o *sendOptions) error { return f(o) }

func WithoutExpirySorting() SendOption {
	return sendOptFn(func(o *sendOptions) error {
		o.withoutExpirySorting = true
		return nil
	})
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
	return sendOptFn(func(o *sendOptions) error {
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
	})
}

// WithTxOutsTaprootTree sets the PSBT BIP-371 TaprootTapTree field on
// every output whose hex-encoded pkScript matches a key in the map. Callers
// pass the BIP-371-encoded tap tree bytes (via txutils.TapTree(scripts).Encode()).
// SendOffChain returns an error if any pkScript key matches no output of the
// ark tx, surfacing what would otherwise be a silent footgun for protocol-
// critical VTXO spending.
func WithTxOutsTaprootTree(tapTrees map[string][]byte) SendOption {
	return sendOptFn(func(o *sendOptions) error {
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

type sendOptions struct {
	withoutExpirySorting bool
	vtxos                []types.VtxoWithTapTree
	signingKeys          map[string]string
	extraPackets         []extension.Packet
	receiver             string
	outputsTapTree       map[string][]byte // pkScript (hex) -> bip371 taptree
}

func newDefaultSendOptions() *sendOptions {
	return &sendOptions{}
}
