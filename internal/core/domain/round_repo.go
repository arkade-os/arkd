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
	// GetScheduledSweeps returns the batches awaiting a sweep, soonest due first,
	// capped at limit (0 means no limit). The due time is derived in the query
	// from ending_timestamp + vtxo_tree_expiration, so this costs one round trip
	// and never touches the chain. The sweeper's own findSweepableOutputs is the
	// chain-accurate path and stays as is: it builds a real transaction.
	GetScheduledSweeps(ctx context.Context, limit int64) ([]ScheduledSweep, error)
	// GetExpiredRounds returns the list of info about batches that expired but haven't been
	// swept because of uneconomical conditions (amount too low to cover network fees)
	GetExpiredRounds(ctx context.Context, expiredBefore int64) ([]ExpiredRound, error)
	// GetRoundSummaries returns the listing view of the rounds started in the given
	// range (0 means unbounded), most recent first, capped at limit (0 means no
	// limit). Filtering, ordering and the limit are applied by the query, so
	// listing N rounds costs one round trip rather than loading each one.
	GetRoundSummaries(
		ctx context.Context,
		startedAfter, startedBefore int64,
		withFailed, withCompleted, onlyFailed bool,
		limit int64,
	) ([]RoundSummary, error)
	// TODO return only connector addresses with unspent utxos
	GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error)
	GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error)
	GetRoundsWithCommitmentTxids(ctx context.Context, txids []string) (map[string]any, error)
	GetIntentByTxid(ctx context.Context, txid string) (*Intent, error)
	// PatchForfeitTxs replaces the stored tx (PSBT) of the given forfeit txs,
	// keyed by txid. Used to backfill the operator signature on forfeit txs that
	// were persisted before collection-time signing was introduced. Signing only
	// adds witness data, so the txid is unchanged and safely keys the update.
	PatchForfeitTxs(ctx context.Context, txByTxid map[string]string) error
	// SumCollectedFees totals the fees recorded against batches that finalized in
	// the given range (0 means unbounded). It reports what storage holds: batches
	// finalized before fees were persisted count as zero.
	SumCollectedFees(ctx context.Context, after, before int64) (uint64, error)
	Close()
}

// ScheduledSweep is the listing view of a batch awaiting its sweep: when it
// falls due and how much unswept leaf value it still carries.
type ScheduledSweep struct {
	RoundId        string
	CommitmentTxid string
	SweepAt        int64
	TotalAmount    uint64
	VtxoCount      int64
}

type ExpiredRound struct {
	RoundId        string
	CommitmentTxid string
	ExpiredAt      int64
}

// RoundSummary is the listing view of a round: everything the admin batch list
// renders, without loading the round's intents, txs or trees.
type RoundSummary struct {
	RoundId        string
	CommitmentTxid string
	StartedAt      int64
	EndedAt        int64
	Stage          string
	Ended          bool
	Failed         bool
	Swept          bool
	FailReason     string
	TotalIntents   int64
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
