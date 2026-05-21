package batchsessionhandler

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	log "github.com/sirupsen/logrus"
)

const (
	start = iota
	batchStarted
	treeSigningStarted
	treeNoncesAggregated
	batchFinalization
)

func JoinBatchSession(
	ctx context.Context, eventsCh <-chan clientlib.BatchEventChannel,
	eventsHandler Handler, opts ...HandlerOption,
) (string, string, time.Duration, []string, *tree.TxTree, error) {
	options := newOptions()

	for _, opt := range opts {
		opt(options)
	}

	step := start

	// the txs of the tree are received one after the other via TxTreeEvent
	// we collect them and then build the tree when necessary.
	flatVtxoTree := make([]tree.TxTreeNode, 0)
	flatConnectorTree := make([]tree.TxTreeNode, 0)

	var vtxoTree, connectorTree *tree.TxTree
	var forfeitTxs []string
	var batchExpiry time.Duration
	var commitmentTx string
	for {
		select {
		case <-options.cancelCh:
			return "", "", -1, nil, nil, fmt.Errorf("canceled")
		case <-ctx.Done():
			return "", "", -1, nil, nil, fmt.Errorf("context done %s", ctx.Err())
		case notify, ok := <-eventsCh:
			if !ok {
				return "", "", -1, nil, nil, fmt.Errorf("event stream closed")
			}
			if notify.Err != nil {
				return "", "", -1, nil, nil, notify.Err
			}
			if notify.Connection != nil {
				continue
			}

			if options.replayEventsCh != nil {
				select {
				case options.replayEventsCh <- notify.Event:
				default:
				}
			}

			switch event := notify.Event; event.(type) {
			case clientlib.StreamStartedEvent:
				streamStartedEvent := event.(clientlib.StreamStartedEvent)
				if err := eventsHandler.OnStreamStarted(ctx, streamStartedEvent); err != nil {
					return "", "", -1, nil, nil, err
				}
			case clientlib.BatchStartedEvent:
				e := event.(clientlib.BatchStartedEvent)
				skip, expiry, err := eventsHandler.OnBatchStarted(ctx, e)
				if err != nil {
					return "", "", -1, nil, nil, err
				}
				if !skip {
					step++

					// if we don't want to sign the vtxo tree, we can skip the tree signing phase
					if !options.signVtxoTree {
						step = treeNoncesAggregated
					}
					batchExpiry = expiry
					continue
				}
			case clientlib.BatchFinalizedEvent:
				if step != batchFinalization {
					continue
				}
				event := event.(clientlib.BatchFinalizedEvent)
				if err := eventsHandler.OnBatchFinalized(ctx, event); err != nil {
					return "", "", -1, nil, nil, err
				}
				return event.Txid, commitmentTx, batchExpiry, forfeitTxs, vtxoTree, nil
			// the batch session failed, return error only if we joined.
			case clientlib.BatchFailedEvent:
				e := event.(clientlib.BatchFailedEvent)
				if err := eventsHandler.OnBatchFailed(ctx, e); err != nil {
					return "", "", -1, nil, nil, err
				}
				continue
			// we received a tree tx event msg, let's update the vtxo/connector tree.
			case clientlib.TreeTxEvent:
				if step != batchStarted && step != treeNoncesAggregated {
					continue
				}

				treeTxEvent := event.(clientlib.TreeTxEvent)

				if err := eventsHandler.OnTreeTxEvent(ctx, treeTxEvent); err != nil {
					return "", "", -1, nil, nil, err
				}

				if treeTxEvent.BatchIndex == 0 {
					flatVtxoTree = append(flatVtxoTree, treeTxEvent.Node)
				} else {
					flatConnectorTree = append(flatConnectorTree, treeTxEvent.Node)
				}

				continue
			case clientlib.TreeSignatureEvent:
				if step != treeNoncesAggregated {
					continue
				}
				if vtxoTree == nil {
					return "", "", -1, nil, nil, fmt.Errorf("vtxo tree not initialized")
				}

				event := event.(clientlib.TreeSignatureEvent)
				if err := eventsHandler.OnTreeSignatureEvent(ctx, event); err != nil {
					return "", "", -1, nil, nil, err
				}

				if err := addSignatureToTxTree(event, vtxoTree); err != nil {
					return "", "", -1, nil, nil, err
				}
				continue
			// the musig2 session started, let's send our nonces.
			case clientlib.TreeSigningStartedEvent:
				if step != batchStarted {
					continue
				}

				var err error
				vtxoTree, err = tree.NewTxTree(flatVtxoTree)
				if err != nil {
					return "", "", -1, nil, nil, fmt.Errorf("failed to create branch of vtxo tree: %s", err)
				}

				event := event.(clientlib.TreeSigningStartedEvent)
				skip, err := eventsHandler.OnTreeSigningStarted(ctx, event, vtxoTree)
				if err != nil {
					return "", "", -1, nil, nil, err
				}

				if !skip {
					step++
				}
				continue
			// we received the aggregated nonces, let's send our signatures.
			case clientlib.TreeNoncesAggregatedEvent:
				if step != treeSigningStarted {
					continue
				}

				event := event.(clientlib.TreeNoncesAggregatedEvent)
				signed, err := eventsHandler.OnTreeNoncesAggregated(ctx, event)
				if err != nil {
					return "", "", -1, nil, nil, err
				}

				if signed {
					step++
				}
				continue
			// we received the fully signed vtxo and connector trees, let's send our signed forfeit
			// txs and optionally signed boarding utxos included in the commitment tx.
			case clientlib.TreeNoncesEvent:
				if step != treeSigningStarted {
					continue
				}

				event := event.(clientlib.TreeNoncesEvent)
				signed, err := eventsHandler.OnTreeNonces(ctx, event)
				if err != nil {
					return "", "", -1, nil, nil, err
				}
				if signed {
					step++
				}
				continue
			case clientlib.BatchFinalizationEvent:
				if step != treeNoncesAggregated {
					continue
				}

				if options.signVtxoTree && vtxoTree == nil {
					return "", "", -1, nil, nil, fmt.Errorf("vtxo tree not initialized")
				}

				if len(flatConnectorTree) > 0 {
					var err error
					connectorTree, err = tree.NewTxTree(flatConnectorTree)
					if err != nil {
						return "", "", -1, nil, nil, fmt.Errorf("failed to create branch of connector tree: %s", err)
					}
				}

				event := event.(clientlib.BatchFinalizationEvent)
				txs, err := eventsHandler.OnBatchFinalization(
					ctx, event, vtxoTree, connectorTree,
				)
				if err != nil {
					return "", "", -1, nil, nil, err
				}
				forfeitTxs = txs
				commitmentTx = event.Tx

				log.Debug("done.")
				log.Debug("waiting for batch finalization...")
				step++
				continue
			}
		}
	}
}
