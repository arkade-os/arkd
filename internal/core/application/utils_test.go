package application

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

const bitcoinBlockWeight = 4_000_000

func TestMaxAssetsPerVtxo(t *testing.T) {
	tests := []struct {
		maxTxWeight uint64
		threshold   float64
		expected    int
	}{
		{maxTxWeight: 0.01 * bitcoinBlockWeight, threshold: 0.5, expected: 110},
		{maxTxWeight: 0.1 * bitcoinBlockWeight, threshold: 0.5, expected: 1110},
		{maxTxWeight: 0.5 * bitcoinBlockWeight, threshold: 0.5, expected: 5555},
		{maxTxWeight: bitcoinBlockWeight, threshold: 0.5, expected: 11110},
		{maxTxWeight: 0.01 * bitcoinBlockWeight, threshold: 0.25, expected: 55},
		{maxTxWeight: 0, threshold: 0.5, expected: 0},
	}

	for _, test := range tests {
		t.Run(
			fmt.Sprintf("maxTxWeight_%d_threshold_%.2f", test.maxTxWeight, test.threshold),
			func(t *testing.T) {
				got := maxAssetsPerVtxo(test.maxTxWeight, test.threshold)
				require.Equal(t, test.expected, got)
			},
		)
	}
}

func TestDecodeTx(t *testing.T) {
	zeroHash := chainhash.Hash{}

	validArkTx := mustEncodePSBTB64(t, newTestTx(
		[]wire.OutPoint{{Hash: zeroHash, Index: 0}},
		[][]byte{{0x51, 0x20, 0x01, 0x02}},
	))
	validCheckpointTx := mustEncodePSBTB64(t, newTestTx(
		[]wire.OutPoint{{Hash: zeroHash, Index: 1}},
		[][]byte{{0x51}},
	))

	tests := []struct {
		name        string
		offchainTx  domain.OffchainTx
		errorSubstr string
		check       func(t *testing.T, txid string, ins []domain.Outpoint, outs []domain.Vtxo)
	}{
		{
			name: "rejects checkpoint with no inputs",
			offchainTx: domain.OffchainTx{
				ArkTx: validArkTx,
				CheckpointTxs: map[string]string{
					"cp0": mustEncodePSBTB64(t, newTestTx(nil, [][]byte{{0x51}})),
				},
			},
			errorSubstr: "missing inputs",
		},
		{
			name: "rejects short output script",
			offchainTx: domain.OffchainTx{
				ArkTx: mustEncodePSBTB64(t, newTestTx(
					[]wire.OutPoint{{Hash: zeroHash, Index: 0}},
					[][]byte{{0x6a}},
				)),
				CheckpointTxs: map[string]string{
					"cp0": validCheckpointTx,
				},
			},
			errorSubstr: "script too short",
		},
		{
			name: "decodes valid transaction",
			offchainTx: domain.OffchainTx{
				ArkTx: validArkTx,
				CheckpointTxs: map[string]string{
					"cp0": validCheckpointTx,
				},
				StartingTimestamp: 123,
				ExpiryTimestamp:   456,
			},
			check: func(t *testing.T, txid string, ins []domain.Outpoint, outs []domain.Vtxo) {
				require.NotEmpty(t, txid)
				require.Len(t, ins, 1)
				require.Equal(t, uint32(1), ins[0].VOut)
				require.Len(t, outs, 1)
				require.Equal(t, txid, outs[0].Txid)
				require.Equal(t, uint32(0), outs[0].VOut)
				require.Equal(t, "0102", outs[0].PubKey)
				require.EqualValues(t, 123, outs[0].CreatedAt)
				require.EqualValues(t, 456, outs[0].ExpiresAt)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txid, ins, outs, err := decodeTx(tt.offchainTx)

			if tt.errorSubstr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorSubstr)
				return
			}

			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, txid, ins, outs)
			}
		})
	}
}

func newTestTx(inputs []wire.OutPoint, scripts [][]byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	for _, in := range inputs {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: in,
			Sequence:         wire.MaxTxInSequenceNum,
		})
	}
	for _, script := range scripts {
		tx.AddTxOut(&wire.TxOut{
			Value:    1_000,
			PkScript: script,
		})
	}
	return tx
}

func mustEncodePSBTB64(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := p.B64Encode()
	require.NoError(t, err)
	return b64
}
