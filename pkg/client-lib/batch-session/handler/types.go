package batchsessionhandler

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

type Handler interface {
	OnBatchStarted(
		ctx context.Context, event clientlib.BatchStartedEvent,
	) (bool, time.Duration, error)
	OnBatchFinalized(ctx context.Context, event clientlib.BatchFinalizedEvent) error
	OnBatchFailed(ctx context.Context, event clientlib.BatchFailedEvent) error
	OnTreeTxEvent(ctx context.Context, event clientlib.TreeTxEvent) error
	OnTreeSignatureEvent(ctx context.Context, event clientlib.TreeSignatureEvent) error
	OnTreeSigningStarted(
		ctx context.Context, event clientlib.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
	) (bool, error)
	OnTreeNoncesAggregated(
		ctx context.Context,
		event clientlib.TreeNoncesAggregatedEvent,
	) (signed bool, err error)
	OnTreeNonces(ctx context.Context, event clientlib.TreeNoncesEvent) (signed bool, err error)
	OnBatchFinalization(
		ctx context.Context,
		event clientlib.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
	) ([]string, error)
	OnStreamStarted(
		ctx context.Context, event clientlib.StreamStartedEvent,
	) error
}
