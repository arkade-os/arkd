package handlers

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestVtxoListToProto_DepthAndNewFields(t *testing.T) {
	vtxos := vtxoList{
		{
			Outpoint:        domain.Outpoint{Txid: "aaa", VOut: 0},
			PubKey:          "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
			Amount:          50000,
			CommitmentTxids: []string{"commit-1"},
			Spent:           false,
			ExpiresAt:       1700000000,
			SpentBy:         "spender-tx",
			Swept:           false,
			Preconfirmed:    true,
			Unrolled:        false,
			CreatedAt:       1699000000,
			SettledBy:       "settler-tx",
			ArkTxid:         "ark-tx-1",
			Depth:           42,
		},
		{
			Outpoint:        domain.Outpoint{Txid: "bbb", VOut: 1},
			PubKey:          "33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0",
			Amount:          100000,
			CommitmentTxids: []string{"commit-2", "commit-3"},
			Spent:           true,
			ExpiresAt:       1700100000,
			SpentBy:         "",
			Swept:           true,
			Preconfirmed:    false,
			Unrolled:        true,
			CreatedAt:       1699100000,
			SettledBy:       "",
			ArkTxid:         "",
			Depth:           200,
		},
		{
			Outpoint: domain.Outpoint{Txid: "ccc", VOut: 2},
			PubKey:   "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
			Amount:   0,
			Depth:    0,
		},
	}

	protos := vtxos.toProto()
	require.Len(t, protos, 3)

	// First VTXO: all fields populated
	p0 := protos[0]
	require.Equal(t, "aaa", p0.Outpoint.Txid)
	require.Equal(t, uint32(0), p0.Outpoint.Vout)
	require.Equal(t, uint64(50000), p0.Amount)
	require.Equal(t, []string{"commit-1"}, p0.CommitmentTxids)
	require.False(t, p0.IsSpent)
	require.Equal(t, int64(1700000000), p0.ExpiresAt)
	require.Equal(t, "spender-tx", p0.SpentBy)
	require.False(t, p0.IsSwept)
	require.True(t, p0.IsPreconfirmed)
	require.False(t, p0.IsUnrolled)
	require.Equal(t, int64(1699000000), p0.CreatedAt)
	require.Equal(t, "settler-tx", p0.SettledBy)
	require.Equal(t, "ark-tx-1", p0.ArkTxid)
	require.Equal(t, uint32(42), p0.Depth)
	require.Equal(t, "512025a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967", p0.Script)

	// Second VTXO: different depth, spent/swept/unrolled flags
	p1 := protos[1]
	require.Equal(t, "bbb", p1.Outpoint.Txid)
	require.Equal(t, uint32(1), p1.Outpoint.Vout)
	require.Equal(t, uint32(200), p1.Depth)
	require.True(t, p1.IsSpent)
	require.True(t, p1.IsSwept)
	require.True(t, p1.IsUnrolled)
	require.Equal(t, []string{"commit-2", "commit-3"}, p1.CommitmentTxids)

	// Third VTXO: zero depth (batch vtxo)
	p2 := protos[2]
	require.Equal(t, uint32(0), p2.Depth)
	require.Equal(t, uint64(0), p2.Amount)
}

func TestNewIndexerVtxo_DepthMapping(t *testing.T) {
	vtxo := domain.Vtxo{
		Outpoint:        domain.Outpoint{Txid: "idx-tx", VOut: 3},
		PubKey:          "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
		Amount:          75000,
		CommitmentTxids: []string{"commit-a"},
		CreatedAt:       1699500000,
		ExpiresAt:       1700500000,
		Preconfirmed:    true,
		Swept:           false,
		Unrolled:        false,
		Spent:           false,
		SpentBy:         "spender",
		SettledBy:       "settler",
		ArkTxid:         "ark-tx-idx",
		Depth:           150,
	}

	proto := newIndexerVtxo(vtxo)

	require.Equal(t, "idx-tx", proto.Outpoint.Txid)
	require.Equal(t, uint32(3), proto.Outpoint.Vout)
	require.Equal(t, uint64(75000), proto.Amount)
	require.Equal(t, int64(1699500000), proto.CreatedAt)
	require.Equal(t, int64(1700500000), proto.ExpiresAt)
	require.True(t, proto.IsPreconfirmed)
	require.False(t, proto.IsSwept)
	require.False(t, proto.IsUnrolled)
	require.False(t, proto.IsSpent)
	require.Equal(t, "spender", proto.SpentBy)
	require.Equal(t, "settler", proto.SettledBy)
	require.Equal(t, "ark-tx-idx", proto.ArkTxid)
	require.Equal(t, uint32(150), proto.Depth)
	require.Equal(t, []string{"commit-a"}, proto.CommitmentTxids)
	require.Equal(t, "512025a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967", proto.Script)
}

func TestNewIndexerVtxo_ZeroDepth(t *testing.T) {
	vtxo := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: "batch-tx", VOut: 0},
		PubKey:   "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
		Depth:    0,
	}

	proto := newIndexerVtxo(vtxo)
	require.Equal(t, uint32(0), proto.Depth)
}

func TestTxEventToProto_DepthPreserved(t *testing.T) {
	event := txEvent{
		TxData: application.TxData{
			Tx:   "raw-tx-data",
			Txid: "event-txid",
		},
		SpentVtxos: []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{Txid: "spent-1", VOut: 0},
				PubKey:   "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
				Depth:    99,
				Amount:   10000,
			},
		},
		SpendableVtxos: []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{Txid: "new-1", VOut: 0},
				PubKey:   "33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0",
				Depth:    100,
				Amount:   9000,
			},
			{
				Outpoint: domain.Outpoint{Txid: "new-1", VOut: 1},
				PubKey:   "33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0",
				Depth:    100,
				Amount:   500,
			},
		},
		CheckpointTxs: map[string]application.TxData{
			"cp-1": {Txid: "cp-txid-1", Tx: "cp-raw-1"},
		},
	}

	proto := event.toProto()

	require.Equal(t, "event-txid", proto.Txid)
	require.Equal(t, "raw-tx-data", proto.Tx)

	// Spent VTXOs preserve depth
	require.Len(t, proto.SpentVtxos, 1)
	require.Equal(t, uint32(99), proto.SpentVtxos[0].Depth)
	require.Equal(t, "spent-1", proto.SpentVtxos[0].Outpoint.Txid)

	// Spendable VTXOs preserve depth
	require.Len(t, proto.SpendableVtxos, 2)
	require.Equal(t, uint32(100), proto.SpendableVtxos[0].Depth)
	require.Equal(t, uint32(100), proto.SpendableVtxos[1].Depth)

	// Checkpoint txs mapped correctly
	require.Len(t, proto.CheckpointTxs, 1)
	require.Equal(t, "cp-txid-1", proto.CheckpointTxs["cp-1"].Txid)
	require.Equal(t, "cp-raw-1", proto.CheckpointTxs["cp-1"].Tx)
}

func TestTxEventToProto_EmptyCheckpointTxs(t *testing.T) {
	event := txEvent{
		TxData: application.TxData{
			Txid: "simple-event",
		},
		SpentVtxos: []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{Txid: "s1", VOut: 0},
				PubKey:   "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
				Depth:    0,
			},
		},
		SpendableVtxos: []domain.Vtxo{},
	}

	proto := event.toProto()
	require.Nil(t, proto.CheckpointTxs)
	require.Len(t, proto.SpentVtxos, 1)
	require.Equal(t, uint32(0), proto.SpentVtxos[0].Depth)
	require.Empty(t, proto.SpendableVtxos)
}
