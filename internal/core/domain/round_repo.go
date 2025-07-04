package domain

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

type RoundRepository interface {
	AddOrUpdateRound(ctx context.Context, round Round) error
	GetRoundWithId(ctx context.Context, id string) (*Round, error)
	GetRoundWithCommitmentTxid(ctx context.Context, txid string) (*Round, error)
	GetRoundStats(ctx context.Context, commitmentTxid string) (*RoundStats, error)
	GetRoundForfeitTxs(ctx context.Context, commitmentTxid string) ([]ForfeitTx, error)
	GetRoundConnectorTree(ctx context.Context, commitmentTxid string) (tree.FlatTxTree, error)
	GetRoundVtxoTree(ctx context.Context, txid string) (tree.FlatTxTree, error)
	GetSweepableRounds(ctx context.Context) ([]string, error)
	GetRoundIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error)
	GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error)
	GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error)
	GetRoundsWithCommitmentTxids(ctx context.Context, txids []string) (map[string]any, error)
	Close()
}

type RoundStats struct {
	Swept              bool
	TotalForfeitAmount uint64
	TotalInputVtxos    int32
	TotalBatchAmount   uint64
	TotalOutputVtxos   int32
	ExpiresAt          int64
	Started            int64
	Ended              int64
}
