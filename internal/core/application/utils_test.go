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

	t.Run("invalid", func(t *testing.T) {
		invalidFixtures := []struct {
			name        string
			offchainTx  domain.OffchainTx
			errorSubstr string
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
		}

		for _, fixture := range invalidFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				_, _, _, err := decodeTx(fixture.offchainTx)
				require.Error(t, err)
				require.Contains(t, err.Error(), fixture.errorSubstr)
			})
		}
	})

	t.Run("valid", func(t *testing.T) {
		validFixtures := []struct {
			name              string
			offchainTx        domain.OffchainTx
			expectedInsLen    int
			expectedInsVOut   uint32
			expectedOutsLen   int
			expectedOutsVOut  uint32
			expectedOutPubKey string
			expectedCreatedAt int64
			expectedExpiresAt int64
		}{
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
				expectedInsLen:    1,
				expectedInsVOut:   1,
				expectedOutsLen:   1,
				expectedOutsVOut:  0,
				expectedOutPubKey: "0102",
				expectedCreatedAt: 123,
				expectedExpiresAt: 456,
			},
		}

		for _, fixture := range validFixtures {
			t.Run(fixture.name, func(t *testing.T) {
				txid, ins, outs, err := decodeTx(fixture.offchainTx)
				require.NoError(t, err)
				require.NotEmpty(t, txid)
				require.Len(t, ins, fixture.expectedInsLen)
				require.Equal(t, fixture.expectedInsVOut, ins[0].VOut)
				require.Len(t, outs, fixture.expectedOutsLen)
				require.Equal(t, txid, outs[0].Txid)
				require.Equal(t, fixture.expectedOutsVOut, outs[0].VOut)
				require.Equal(t, fixture.expectedOutPubKey, outs[0].PubKey)
				require.EqualValues(t, fixture.expectedCreatedAt, outs[0].CreatedAt)
				require.EqualValues(t, fixture.expectedExpiresAt, outs[0].ExpiresAt)
			})
		}
	})
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
