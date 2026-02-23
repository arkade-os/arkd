package application

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

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
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "multiple op return",
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
		// Subdust outputs skip min/max amount checks
		{
			description: "valid: subdust output is not subject to min amount check",
			txOuts: []*wire.TxOut{
				anchor,
				{Value: 100, PkScript: testSubdustScript(t)},
			},
			dust:                    testDust,
			vtxoMaxAmount:           -1,
			vtxoMinOffchainTxAmount: 1000,
			wantOutputCount:         1,
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
			wantErr:                 true,
			wantErrCode:             errors.MALFORMED_ARK_TX.Code,
			wantErrContains:         "multiple op return",
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
			outputs, err := validateOffchainTxOutputs(
				tc.txOuts, tc.dust,
				tc.vtxoMaxAmount, tc.vtxoMinOffchainTxAmount,
				"signed-tx-hex", "test-txid",
			)

			if tc.wantErr {
				require.NotNil(t, err, "expected error")
				require.Equal(t, tc.wantErrCode, err.Code())
				require.Contains(t, err.Error(), tc.wantErrContains)
				return
			}

			require.Nil(t, err, "unexpected error")
			require.Len(t, outputs, tc.wantOutputCount)
		})
	}
}
