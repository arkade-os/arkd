package offchaintx

import (
	"context"
	"fmt"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	log "github.com/sirupsen/logrus"
)

// FinalizePendingTxs asks the server for pending offchain txs tied to
// args.Vtxos via the intent proof, then signs and finalizes each.
func FinalizePendingTxs(
	ctx context.Context, args FinalizePendingTxsArgs,
) ([]string, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	proofTx, message, err := batchsession.BuildAndSignGetPendingTxIntent(
		ctx, batchsession.IntentArgs{BaseArgs: batchsession.BaseArgs{
			Vtxos:  args.Vtxos,
			SignTx: clientlib.SignFn(args.SignTx),
		}},
	)
	if err != nil {
		return nil, err
	}

	pendingTxs, err := args.Client.GetPendingTx(ctx, proofTx, message)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(pendingTxs))
	for _, tx := range pendingTxs {
		txid, _, err := finalizeTx(ctx, args.Client, args.SignTx, tx)
		if err != nil {
			log.WithError(err).Errorf("failed to finalize pending tx: %s", tx.Txid)
			continue
		}
		txids = append(txids, txid)
	}

	return txids, nil
}
