package domain_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// rawTxTwoPackets carries an ARK extension with packets of type 0 and
// type 255. Copied verbatim from
// internal/interface/grpc/handlers/txfilter/testdata/raw_txs.json so
// the unary matcher and the streaming filter share an authoritative
// fixture.
const (
	rawTxTwoPackets = "01000000000100000000000000001b6a1941524b000e01020200000001010000c0de810aff04deadbeef00000000"
	packet0Hex      = "01020200000001010000c0de810a"
	packet255Hex    = "deadbeef"
)

func TestOffchainTxFilterMatchPackets(t *testing.T) {
	t.Parallel()

	psbtB64 := psbtBase64FromTxHex(t, rawTxTwoPackets)

	off := &domain.OffchainTx{
		ArkTxid: "fixture-txid",
		ArkTx:   psbtB64,
		Packets: []int{0, 255},
	}

	t.Run("zero filter matches everything", func(t *testing.T) {
		match, err := domain.OffchainTxFilter{}.MatchPackets(off)
		require.NoError(t, err)
		require.True(t, match)
	})

	t.Run("hasPacket-only matches when type carried", func(t *testing.T) {
		match, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{0: ""},
		}.MatchPackets(off)
		require.NoError(t, err)
		require.True(t, match)
	})

	t.Run("hasPacket-only misses when type absent", func(t *testing.T) {
		match, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{17: ""},
		}.MatchPackets(off)
		require.NoError(t, err)
		require.False(t, match)
	})

	t.Run("equality matches exact hex payload", func(t *testing.T) {
		match, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{0: packet0Hex},
		}.MatchPackets(off)
		require.NoError(t, err)
		require.True(t, match)
	})

	t.Run("equality misses on different hex payload", func(t *testing.T) {
		match, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{0: packet255Hex},
		}.MatchPackets(off)
		require.NoError(t, err)
		require.False(t, match)
	})

	t.Run("equality matches second packet exactly", func(t *testing.T) {
		match, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{255: packet255Hex},
		}.MatchPackets(off)
		require.NoError(t, err)
		require.True(t, match)
	})

	t.Run("substring of payload does not match", func(t *testing.T) {
		// "ad" appears inside "deadbeef" but is not equal to it.
		// The old base64-substring implementation would return true here;
		// the exact-equality matcher must return false.
		match, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{255: "ad"},
		}.MatchPackets(off)
		require.NoError(t, err)
		require.False(t, match)
	})

	t.Run("malformed psbt surfaces an error", func(t *testing.T) {
		bad := &domain.OffchainTx{
			ArkTxid: "bad",
			ArkTx:   "not-a-psbt",
			Packets: []int{0},
		}
		_, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{0: packet0Hex},
		}.MatchPackets(bad)
		require.Error(t, err)
	})

	t.Run("out-of-range packet type surfaces an error", func(t *testing.T) {
		_, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{domain.MaxPacketType + 1: ""},
		}.MatchPackets(off)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})

	t.Run("negative packet type surfaces an error", func(t *testing.T) {
		_, err := domain.OffchainTxFilter{
			WithPacket: map[int]string{-1: ""},
		}.MatchPackets(off)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})
}

func TestPacketTypesFromMsgTx(t *testing.T) {
	t.Parallel()

	t.Run("returns packet types", func(t *testing.T) {
		tx := parseTx(t, rawTxTwoPackets)
		got, err := domain.PacketTypesFromMsgTx(tx)
		require.NoError(t, err)
		require.ElementsMatch(t, []int{0, 255}, got)
	})

	t.Run("no extension returns empty slice and nil error", func(t *testing.T) {
		// Tx with a single dummy output, no ARK extension.
		const noExtHex = "010000000001e803000000000000225120000000000000000000000000000000000000000000000000000000000000000000000000"
		tx := parseTx(t, noExtHex)
		got, err := domain.PacketTypesFromMsgTx(tx)
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func parseTx(t *testing.T, hexStr string) *wire.MsgTx {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	tx := wire.NewMsgTx(wire.TxVersion)
	require.NoError(t, tx.DeserializeNoWitness(bytes.NewReader(b)))
	return tx
}

// psbtBase64FromTxHex wraps a raw tx in a minimal PSBT envelope and
// returns the base64-encoded result, matching what the application
// layer persists in offchain_tx.tx.
func psbtBase64FromTxHex(t *testing.T, txHex string) string {
	t.Helper()
	tx := parseTx(t, txHex)
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
