package application

import (
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestNextScheduledSession(t *testing.T) {
	scheduledSessionStartTime := parseTime(t, "2023-10-10 13:00:00")
	scheduledSessionEndTime := parseTime(t, "2023-10-10 14:00:00")
	period := 1 * time.Hour

	testCases := []struct {
		now           time.Time
		expectedStart time.Time
		expectedEnd   time.Time
		description   string
	}{
		{
			now:           parseTime(t, "2023-10-10 13:00:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is exactly scheduled session start time",
		},
		{
			now:           parseTime(t, "2023-10-10 13:55:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is in the first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 14:00:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is exactly scheduled session end time",
		},
		{
			now:           parseTime(t, "2023-10-10 14:06:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is after first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 15:30:00"),
			expectedStart: parseTime(t, "2023-10-10 15:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 16:00:00"),
			description:   "now is after second scheduled session",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			startTime, endTime := calcNextScheduledSession(
				tc.now, scheduledSessionStartTime, scheduledSessionEndTime, period,
			)
			require.True(t, startTime.Equal(tc.expectedStart))
			require.True(t, endTime.Equal(tc.expectedEnd))
		})
	}
}

func TestResolveMinAmounts(t *testing.T) {
	const dust int64 = 330

	testCases := []struct {
		description       string
		vtxoMinAmount     int64
		utxoMinAmount     int64
		expectedVtxoMin   int64
		expectedUtxoMin   int64
	}{
		{
			description:     "sub-dust vtxo min is preserved for offchain",
			vtxoMinAmount:   1,
			utxoMinAmount:   100,
			expectedVtxoMin: 1,
			expectedUtxoMin: dust,
		},
		{
			description:     "default -1 is defaulted to dust",
			vtxoMinAmount:   -1,
			utxoMinAmount:   -1,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "arbitrary negative values are defaulted to dust",
			vtxoMinAmount:   -99,
			utxoMinAmount:   -50,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "above dust are kept as-is",
			vtxoMinAmount:   1000,
			utxoMinAmount:   2000,
			expectedVtxoMin: 1000,
			expectedUtxoMin: 2000,
		},
		{
			description:     "exactly dust are kept as-is",
			vtxoMinAmount:   dust,
			utxoMinAmount:   dust,
			expectedVtxoMin: dust,
			expectedUtxoMin: dust,
		},
		{
			description:     "zero vtxo min is preserved for offchain",
			vtxoMinAmount:   0,
			utxoMinAmount:   0,
			expectedVtxoMin: 0,
			expectedUtxoMin: dust,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			vtxoMin, utxoMin := resolveMinAmounts(
				tc.vtxoMinAmount, tc.utxoMinAmount, dust,
			)
			require.Equal(t, tc.expectedVtxoMin, vtxoMin)
			require.Equal(t, tc.expectedUtxoMin, utxoMin)
		})
	}
}

// TestCheckUnrolledVtxoExpiry verifies the expiry margin gate that decides
// whether an unrolled VTXO's remaining CSV time is long enough to safely
// rejoin a batch. The margin is always a concrete configured value (config
// validation rejects <= 0), so the function just compares csvExpiresAt to
// now + margin.
func TestCheckUnrolledVtxoExpiry(t *testing.T) {
	now := parseTime(t, "2023-10-10 12:00:00")
	margin := 5 * time.Minute

	tests := []struct {
		description  string
		csvExpiresAt time.Time
		expectErr    bool
	}{
		{
			description:  "CSV expires after margin",
			csvExpiresAt: now.Add(10 * time.Minute),
			expectErr:    false,
		},
		{
			description:  "CSV expires within margin",
			csvExpiresAt: now.Add(2 * time.Minute),
			expectErr:    true,
		},
		{
			description:  "CSV expires exactly at margin boundary",
			csvExpiresAt: now.Add(margin),
			expectErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			svc := &service{unrolledVtxoMinExpiryMargin: margin}

			err := svc.checkUnrolledVtxoExpiry(tc.csvExpiresAt, now)
			if tc.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unrolled vtxo CSV expires too soon")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func parseTime(t *testing.T, value string) time.Time {
	tm, err := time.ParseInLocation(time.DateTime, value, time.UTC)
	require.NoError(t, err)
	return tm
}

func testPubkey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key.PubKey()
}

func testSubdustScript(t *testing.T) []byte {
	t.Helper()
	s, err := script.SubDustScript(testPubkey(t))
	require.NoError(t, err)
	return s
}

func testP2TRScript(t *testing.T) []byte {
	t.Helper()
	s, err := script.P2TRScript(testPubkey(t))
	require.NoError(t, err)
	return s
}

// bareOpReturn builds an OP_RETURN script with arbitrary data that is neither
// a subdust script (which requires exactly 32-byte push) nor an asset packet.
func bareOpReturn(t *testing.T) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_RETURN).
		AddData([]byte("not-subdust-not-asset")).
		Script()
	require.NoError(t, err)
	return s
}

func testExtensionScript(t *testing.T) []byte {
	t.Helper()
	ext := extension.Extension{
		extension.UnknownPacket{PacketType: 0xFF, Data: []byte("test")},
	}
	s, err := ext.Serialize()
	require.NoError(t, err)
	return s
}

const testDust uint64 = 546

func TestValidateOffchainTxOutputs(t *testing.T) {
	anchor := txutils.AnchorOutput()

	tests := []struct {
		description             string
		txOuts                  []*wire.TxOut
		dust                    uint64
		vtxoMaxAmount           int64
		vtxoMinOffchainTxAmount int64
		wantErr                 bool
		wantErrCode             uint16
		wantErrContains         string
		wantOutputCount         int
		wantAmount              int // expected Amount in AmountTooLowMetadata (only checked when wantErrCode == AMOUNT_TOO_LOW)
		maxOpReturnOutputs      uint32
	}{
		{
			description: "valid: anchor + regular output",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		{
			description: "valid: subdust OP_RETURN below dust",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 100, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		{
			description: "valid: subdust OP_RETURN with zero value",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 0, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		{
			description: "valid: bare OP_RETURN with zero value",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 0, PkScript: bareOpReturn(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		// subdust OP_RETURN with value >= dust must be rejected
		{
			description: "reject: subdust OP_RETURN with value == dust",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: int64(testDust), PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "subdust OP_RETURN output",
		},
		{
			description: "reject: subdust OP_RETURN with value > dust",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 10000, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "subdust OP_RETURN output",
		},
		// non-subdust OP_RETURN with value > 0 must be rejected
		{
			description: "reject: bare OP_RETURN with non-zero value",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: bareOpReturn(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "not a subdust output",
		},
		{
			description: "reject: bare OP_RETURN with value == 1",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1, PkScript: bareOpReturn(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "not a subdust output",
		},
		{
			description: "reject: missing anchor",
			txOuts: []*wire.TxOut{
				{Value: 1000, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "missing anchor",
		},
		{
			description: "reject: multiple anchors",
			txOuts: []*wire.TxOut{
				anchor,
				anchor,
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "multiple anchor",
		},
		{
			description: "reject: multiple OP_RETURN outputs",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 0, PkScript: bareOpReturn(t)},
				{Value: 0, PkScript: bareOpReturn(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			maxOpReturnOutputs:      1,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "OP_RETURN outputs, max",
		},
		{
			description: "reject: regular output exceeds max amount",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 5000, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           1000,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.AMOUNT_TOO_HIGH.Code,
			wantErrContains:         "higher than max vtxo amount",
		},
		{
			description: "reject: regular output below min amount",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 600, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 1000,
			wantErr:                 true,
			wantErrCode:             errors.AMOUNT_TOO_LOW.Code,
			wantErrContains:         "lower than min vtxo amount",
			wantAmount:              600,
		},
		{
			description: "reject: non-OP_RETURN below dust without subdust script",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 100, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.AMOUNT_TOO_LOW.Code,
			wantErrContains:         "below dust limit",
		},
		// Subdust outputs are subject to min amount check
		{
			description: "reject: subdust output below min amount",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 100, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 1000,
			wantErr:                 true,
			wantErrCode:             errors.AMOUNT_TOO_LOW.Code,
			wantErrContains:         "lower than min vtxo amount",
			wantAmount:              100,
		},
		{
			description: "valid: anchor only, no other outputs",
			txOuts: []*wire.TxOut{
				anchor,
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         0,
		},
		// Boundary: subdust at dust-1 (max valid subdust value)
		{
			description: "valid: subdust OP_RETURN with value == dust-1",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: int64(testDust) - 1, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		// Boundary: regular output at exact max (> not >=, should pass)
		{
			description: "valid: regular output value == vtxoMaxAmount",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           1000,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		// Boundary: regular output at exact min (< not <=, should pass)
		{
			description: "valid: regular output value == vtxoMinOffchainTxAmount",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 1000,
			wantOutputCount:         1,
		},
		// Boundary: regular output exactly at dust (not below, should pass)
		{
			description: "valid: regular output value == dust",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: int64(testDust), PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		// Multiple valid regular outputs all collected
		{
			description: "valid: multiple regular outputs",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: testP2TRScript(t)},
				{Value: 2000, PkScript: testP2TRScript(t)},
				{Value: 3000, PkScript: testP2TRScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         3,
		},
		// Mixed: regular + subdust coexist
		{
			description: "valid: regular output + subdust OP_RETURN",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: testP2TRScript(t)},
				{Value: 100, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         2,
		},
		// Mixed: regular + bare OP_RETURN coexist
		{
			description: "valid: regular output + bare OP_RETURN with zero value",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: testP2TRScript(t)},
				{Value: 0, PkScript: bareOpReturn(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         2,
		},
		// Two OP_RETURN variants still trigger duplicate check
		{
			description: "reject: subdust OP_RETURN then bare OP_RETURN",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 100, PkScript: testSubdustScript(t)},
				{Value: 0, PkScript: bareOpReturn(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			maxOpReturnOutputs:      1,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "OP_RETURN outputs, max",
		},
		// Empty txOuts → missing anchor
		{
			description: "reject: empty outputs",
			txOuts:                  []*wire.TxOut{},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "missing anchor",
		},
		// Minimal OP_RETURN: just the opcode, no data push
		{
			description: "valid: OP_RETURN opcode only with zero value",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 0, PkScript: []byte{txscript.OP_RETURN}},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		// Extension OP_RETURN must have value == 0
		{
			description: "reject: extension OP_RETURN with non-zero value",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1000, PkScript: testExtensionScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "extension OP_RETURN output",
		},
		{
			description: "reject: extension OP_RETURN with value == 1",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 1, PkScript: testExtensionScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "extension OP_RETURN output",
		},
		{
			description: "valid: extension OP_RETURN with zero value",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 0, PkScript: testExtensionScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
		// Subdust output not subject to max amount check
		{
			description: "valid: subdust output is not subject to max amount check",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 100, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           50,
			vtxoMinOffchainTxAmount: 0,
			wantOutputCount:         1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			maxOpRet := tc.maxOpReturnOutputs
			if maxOpRet == 0 {
				maxOpRet = 3
			}
			outputs, _, err := validateOffchainTxOutputs(
				tc.txOuts, tc.dust,
				tc.vtxoMaxAmount, tc.vtxoMinOffchainTxAmount,
				int64(maxOpRet), "signed-tx-hex", "test-txid",
			)

			if tc.wantErr {
				require.NotNil(t, err, "expected error")
				require.Equal(t, tc.wantErrCode, err.Code())
				require.Contains(t, err.Error(), tc.wantErrContains)
				if tc.wantErrCode == errors.AMOUNT_TOO_LOW.Code && tc.wantAmount != 0 {
					metadata := err.Metadata()
					require.Equal(t, fmt.Sprintf("%d", tc.wantAmount), metadata["amount"])
				}
				return
			}

			require.Nil(t, err, "unexpected error")
			require.Len(t, outputs, tc.wantOutputCount)
		})
	}
}
