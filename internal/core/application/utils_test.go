package application

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// makeP2TRLeafTx creates a valid base64-encoded PSBT with P2TR outputs
// for the given schnorr public keys and amounts.
func makeP2TRLeafTx(t *testing.T, outputs []struct {
	pubkey *btcec.PublicKey
	amount int64
}) string {
	t.Helper()
	hash, err := chainhash.NewHashFromStr(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	require.NoError(t, err)

	txOuts := make([]*wire.TxOut, 0, len(outputs))
	for _, out := range outputs {
		pkScript := make([]byte, 34)
		pkScript[0] = 0x51 // OP_1
		pkScript[1] = 0x20 // 32-byte push
		copy(pkScript[2:], schnorr.SerializePubKey(out.pubkey))

		txOuts = append(txOuts, &wire.TxOut{
			Value:    out.amount,
			PkScript: pkScript,
		})
	}

	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *hash, Index: 0}},
		txOuts,
		3,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

func TestGetNewVtxosFromRound_MarkerIDsAndDepth(t *testing.T) {
	// Generate two distinct keys for two outputs
	privKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pub1 := privKey1.PubKey()
	pub2 := privKey2.PubKey()

	leafTx := makeP2TRLeafTx(t, []struct {
		pubkey *btcec.PublicKey
		amount int64
	}{
		{pubkey: pub1, amount: 50000},
		{pubkey: pub2, amount: 30000},
	})

	round := &domain.Round{
		CommitmentTxid:     "test-commitment-txid",
		VtxoTreeExpiration: 3600,
		EndingTimestamp:     1700000000,
		Stage:              domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
		VtxoTree: tree.FlatTxTree{
			{
				Txid:     "leaf-tx-id",
				Tx:       leafTx,
				Children: nil, // leaf node
			},
		},
	}

	vtxos := getNewVtxosFromRound(round)

	require.Len(t, vtxos, 2)

	for i, vtxo := range vtxos {
		// All batch VTXOs must have Depth = 0
		require.Equal(t, uint32(0), vtxo.Depth, "vtxo %d should have depth 0", i)

		// MarkerIDs must be exactly []string{outpoint.String()}
		expectedMarkerID := vtxo.Outpoint.String()
		require.Equal(t, []string{expectedMarkerID}, vtxo.MarkerIDs,
			"vtxo %d MarkerIDs should be [outpoint.String()]", i)

		// CommitmentTxids should reference the round's commitment
		require.Equal(t, []string{"test-commitment-txid"}, vtxo.CommitmentTxids)
		require.Equal(t, "test-commitment-txid", vtxo.RootCommitmentTxid)

		// Amount must match
		if i == 0 {
			require.Equal(t, uint64(50000), vtxo.Amount)
		} else {
			require.Equal(t, uint64(30000), vtxo.Amount)
		}

		// PubKey must be non-empty
		require.NotEmpty(t, vtxo.PubKey)
	}

	// VOut should be sequential (0, 1)
	require.Equal(t, uint32(0), vtxos[0].VOut)
	require.Equal(t, uint32(1), vtxos[1].VOut)

	// Both should have the same txid (from the same PSBT)
	require.Equal(t, vtxos[0].Txid, vtxos[1].Txid)
}

func TestGetNewVtxosFromRound_EmptyVtxoTree(t *testing.T) {
	round := &domain.Round{
		CommitmentTxid: "empty-round",
		VtxoTree:       nil,
	}

	vtxos := getNewVtxosFromRound(round)
	require.Nil(t, vtxos)
}

func TestGetNewVtxosFromRound_SingleOutput(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	leafTx := makeP2TRLeafTx(t, []struct {
		pubkey *btcec.PublicKey
		amount int64
	}{
		{pubkey: privKey.PubKey(), amount: 100000},
	})

	round := &domain.Round{
		CommitmentTxid:     "single-output-commitment",
		VtxoTreeExpiration: 7200,
		EndingTimestamp:     1700000000,
		Stage:              domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
		VtxoTree: tree.FlatTxTree{
			{
				Txid:     "single-leaf",
				Tx:       leafTx,
				Children: nil,
			},
		},
	}

	vtxos := getNewVtxosFromRound(round)
	require.Len(t, vtxos, 1)

	vtxo := vtxos[0]
	require.Equal(t, uint32(0), vtxo.Depth)
	require.Equal(t, []string{vtxo.Outpoint.String()}, vtxo.MarkerIDs)
	require.Equal(t, uint64(100000), vtxo.Amount)
	require.Equal(t, uint32(0), vtxo.VOut)
}
