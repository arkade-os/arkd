package domain

import (
	"bytes"
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

// MaxPacketType is the upper bound on ARK extension packet types,
// which are uint8 in the wire format (see pkg/ark-lib/extension/packet.go).
const MaxPacketType = 0xff

// MatchPackets reports whether off satisfies the WithPacket and
// WithPacketContains portions of the filter. It does not re-check
// WithTxids / WithExtension / time-range; those are pushed down by the
// repository (or applied in memory by the badger backend).
//
// For each (packetType, hexPayload) entry in WithPacket:
//   - packetType must be in [0, MaxPacketType] (wire-format range);
//     out-of-range keys are a programming error and surface as an error.
//   - off.Packets must contain packetType (carries-the-type check).
//   - When hexPayload is non-empty, off.ArkTx (the persisted base64
//     PSBT) must embed an ARK extension whose packet of that type, when
//     serialized and hex-encoded, equals hexPayload exactly. This
//     mirrors the streaming SubscriptionFilter's `tx.extension[N] ==
//     'hex'` semantics so the unary and stream RPCs return the same
//     set.
//
// For each (packetType, hexSubstrings) entry in WithPacketContains the
// packet of that type must exist and its serialized bytes must contain
// every listed substring. The match is byte-aligned against the decoded
// packet (bytes.Contains), mirroring `tx.extension[N].contains('hex')`.
//
// A PSBT/extension parse error on a row that needs payload matching is
// surfaced as an error rather than swallowed; persisted data that fails
// to decode is a stored-data bug, not a clean filter miss.
func (f OffchainTxFilter) MatchPackets(off *OffchainTx) (bool, error) {
	if len(f.WithPacket) == 0 && len(f.WithPacketContains) == 0 {
		return true, nil
	}
	for t := range f.WithPacket {
		if t < 0 || t > MaxPacketType {
			return false, fmt.Errorf(
				"packet type %d out of range (must be 0..%d)", t, MaxPacketType,
			)
		}
	}
	for t := range f.WithPacketContains {
		if t < 0 || t > MaxPacketType {
			return false, fmt.Errorf(
				"packet type %d out of range (must be 0..%d)", t, MaxPacketType,
			)
		}
	}
	carried := make(map[int]struct{}, len(off.Packets))
	for _, p := range off.Packets {
		carried[p] = struct{}{}
	}

	// serializedPacket lazily decodes the extension once and returns the
	// serialized bytes of the packet of type t (ok=false when absent).
	var ext extension.Extension
	serializedPacket := func(t int) ([]byte, bool, error) {
		if ext == nil {
			parsed, err := decodeExtension(off.ArkTx)
			if err != nil {
				return nil, false, fmt.Errorf("decode extension for txid %s: %w", off.ArkTxid, err)
			}
			ext = parsed
		}
		pkt := ext.GetPacketByType(uint8(t))
		if pkt == nil {
			return nil, false, nil
		}
		data, err := pkt.Serialize()
		if err != nil {
			return nil, false, fmt.Errorf(
				"serialize packet %d for txid %s: %w",
				t,
				off.ArkTxid,
				err,
			)
		}
		return data, true, nil
	}

	// Exact-match constraints (tx.extension[N] == 'hex').
	for t, hexPayload := range f.WithPacket {
		if _, ok := carried[t]; !ok {
			return false, nil
		}
		if hexPayload == "" {
			continue
		}
		data, ok, err := serializedPacket(t)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		if hex.EncodeToString(data) != hexPayload {
			return false, nil
		}
	}

	// Substring constraints (tx.extension[N].contains('hex')).
	for t, subs := range f.WithPacketContains {
		if _, ok := carried[t]; !ok {
			return false, nil
		}
		data, ok, err := serializedPacket(t)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		for _, sub := range subs {
			subBytes, err := hex.DecodeString(sub)
			if err != nil {
				return false, fmt.Errorf(
					"contains payload for packet %d not hex: %w", t, err,
				)
			}
			if !bytes.Contains(data, subBytes) {
				return false, nil
			}
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
