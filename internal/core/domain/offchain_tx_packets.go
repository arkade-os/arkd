package domain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// PacketTypesFromMsgTx returns the ARK extension packet types carried by
// tx. A tx with no extension yields an empty slice and a nil error. Any
// other parse failure (e.g. malformed extension blob) is propagated so
// callers can reject the tx instead of silently persisting it as
// "no extension".
func PacketTypesFromMsgTx(tx *wire.MsgTx) ([]int, error) {
	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil {
		if errors.Is(err, extension.ErrExtensionNotFound) {
			return []int{}, nil
		}
		return nil, fmt.Errorf("parse extension: %w", err)
	}
	out := make([]int, 0, len(ext))
	for _, p := range ext {
		out = append(out, int(p.Type()))
	}
	return out, nil
}

// PacketTypesFromPSBT64 decodes a base64-encoded PSBT and returns the
// packet types carried by its unsigned tx's ARK extension. The empty
// extension case (ErrExtensionNotFound) yields an empty slice and nil
// error; malformed PSBT or extension bytes propagate as errors.
func PacketTypesFromPSBT64(b64 string) ([]int, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	if err != nil {
		return nil, fmt.Errorf("parse psbt: %w", err)
	}
	return PacketTypesFromMsgTx(ptx.UnsignedTx)
}

// MatchPackets reports whether off satisfies the WithPacket portion of
// the filter. It does not re-check WithTxids / WithExtension /
// time-range; those are pushed down by the repository (or applied in
// memory by the badger backend).
//
// For each (packetType, hexPayload) entry in WithPacket:
//   - off.Packets must contain packetType (carries-the-type check); and
//   - when hexPayload is non-empty, off.ArkTx (the persisted base64
//     PSBT) must embed an ARK extension whose packet of that type, when
//     serialized and hex-encoded, equals hexPayload exactly. This mirrors
//     the streaming SubscriptionFilter's `tx.extension[N] == 'hex'`
//     semantics so the unary and stream RPCs return the same set.
//
// A PSBT/extension parse error on a row that needs payload matching is
// surfaced as an error rather than swallowed; persisted data that fails
// to decode is a stored-data bug, not a clean filter miss.
func (f OffchainTxFilter) MatchPackets(off *OffchainTx) (bool, error) {
	if len(f.WithPacket) == 0 {
		return true, nil
	}
	carried := make(map[int]struct{}, len(off.Packets))
	for _, p := range off.Packets {
		carried[p] = struct{}{}
	}

	var ext extension.Extension
	for t, hexPayload := range f.WithPacket {
		if _, ok := carried[t]; !ok {
			return false, nil
		}
		if hexPayload == "" {
			continue
		}
		if ext == nil {
			parsed, err := decodeExtension(off.ArkTx)
			if err != nil {
				return false, fmt.Errorf("decode extension for txid %s: %w", off.ArkTxid, err)
			}
			ext = parsed
		}
		pkt := ext.GetPacketByType(uint8(t))
		if pkt == nil {
			return false, nil
		}
		data, err := pkt.Serialize()
		if err != nil {
			return false, fmt.Errorf("serialize packet %d for txid %s: %w", t, off.ArkTxid, err)
		}
		if hex.EncodeToString(data) != hexPayload {
			return false, nil
		}
	}
	return true, nil
}

func decodeExtension(b64 string) (extension.Extension, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	if err != nil {
		return nil, fmt.Errorf("parse psbt: %w", err)
	}
	ext, err := extension.NewExtensionFromTx(ptx.UnsignedTx)
	if err != nil {
		if errors.Is(err, extension.ErrExtensionNotFound) {
			return extension.Extension{}, nil
		}
		return nil, fmt.Errorf("parse extension: %w", err)
	}
	return ext, nil
}
