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
	GetSweepTxs(ctx context.Context, commitmentTxid string) (map[string]string, error)
	GetRoundConnectorTree(ctx context.Context, commitmentTxid string) (tree.FlatTxTree, error)
	GetRoundVtxoTree(ctx context.Context, txid string) (tree.FlatTxTree, error)
	GetSweepableRounds(ctx context.Context) ([]string, error)
	// GetExpiredRounds returns the list of info about batches that expired but haven't been
	// swept because of uneconomical conditions (amount too low to cover network fees)
	GetExpiredRounds(ctx context.Context, expiredBefore int64) ([]ExpiredRound, error)
	GetRoundIds(
		ctx context.Context,
		startedAfter, startedBefore int64,
		withFailed, withCompleted bool,
	) ([]string, error)
	// TODO return only connector addresses with unspent utxos
	GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error)
	GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error)
	GetRoundsWithCommitmentTxids(ctx context.Context, txids []string) (map[string]any, error)
	GetIntentByTxid(ctx context.Context, txid string) (*Intent, error)
	// PatchCollectedFees sets the collected fees of the given rounds (by id),
	// used to lazily persist fees recomputed for rounds finalized before fee
	// persistence was introduced (https://github.com/arkade-os/arkd/pull/933).
	PatchCollectedFees(ctx context.Context, feesByRoundId map[string]uint64) error
	// PatchForfeitTxs replaces the stored tx (PSBT) of the given forfeit txs,
	// keyed by txid. Used to backfill the operator signature on forfeit txs that
	// were persisted before collection-time signing was introduced. Signing only
	// adds witness data, so the txid is unchanged and safely keys the update.
	PatchForfeitTxs(ctx context.Context, txByTxid map[string]string) error
	Close()
}

type ExpiredRound struct {
	RoundId        string
	CommitmentTxid string
	ExpiredAt      int64
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
