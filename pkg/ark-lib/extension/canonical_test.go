package extension_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/stretchr/testify/require"
)

// A minimal valid extension script:
//
//	6a 0d                       OP_RETURN, push 13 bytes
//	41 52 4b                    magic "ARK"
//	00                          packet type 0x00 (asset)
//	08                          packet length prefix = 8
//	01 00000101000001           asset packet: 1 group (canonical issuance)
const canonicalExtensionHex = "6a0d41524b00080100000101000001"

// Same payload, but the packet length prefix 0x08 is encoded non-minimally as
// 0x88 0x00. The OP_RETURN push length grows from 0x0d (13) to 0x0e (14).
const overlongPrefixExtensionHex = "6a0e41524b0088000100000101000001"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestExtensionCanonicalIsAccepted(t *testing.T) {
	ext, err := extension.NewExtensionFromBytes(mustHex(t, canonicalExtensionHex))
	require.NoError(t, err)
	require.Len(t, ext, 1)
}

func TestExtensionRejectsOverlongPacketLengthPrefix(t *testing.T) {
	_, err := extension.NewExtensionFromBytes(mustHex(t, overlongPrefixExtensionHex))
	require.Error(t, err)
}

func TestExtensionRejectsTrailingBytes(t *testing.T) {
	// Canonical script followed by a stray OP_1 (0x51) after the payload push.
	_, err := extension.NewExtensionFromBytes(mustHex(t, canonicalExtensionHex+"51"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-canonical")
}

func TestExtensionRejectsNonMinimalPush(t *testing.T) {
	// Same 13-byte payload pushed via OP_PUSHDATA1 (0x4c 0x0d) instead of the
	// minimal direct push (0x0d).
	_, err := extension.NewExtensionFromBytes(mustHex(t, "6a4c0d41524b00080100000101000001"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-canonical")
}
