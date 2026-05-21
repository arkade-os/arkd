package batchsession

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/btcsuite/btcd/btcutil"
)

// CollaborativeExitArgs configures a CollaborativeExit call: the Vtxos to spend
// and the on-chain Receiver to credit. FeeEstimator is used to size the on-chain
// output, SignTx signs the intent proof, and ServerInfo/Client are used to talk
// to the server.
type CollaborativeExitArgs struct {
	Client       clientlib.Client
	FeeEstimator *arkfee.Estimator
	ServerInfo   clientlib.Info
	SignTx       batchsessionhandler.SignFn
	Vtxos        []clientlib.Vtxo
	Receiver     clientlib.Receiver
	ChangeAddr   string
}

func (a CollaborativeExitArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx function")
	}
	if a.FeeEstimator == nil {
		return fmt.Errorf("missing fee estimator")
	}
	if len(a.Vtxos) <= 0 {
		return fmt.Errorf("missing funds for collaborative exit")
	}
	if len(a.Receiver.To) <= 0 {
		return fmt.Errorf("missing receiver address")
	}
	if len(a.ServerInfo.Network) <= 0 || a.ServerInfo.Dust == 0 {
		return fmt.Errorf("missing server info")
	}
	if a.Receiver.Amount < a.ServerInfo.Dust {
		return fmt.Errorf("invalid receiver amount, must be at least %d", a.ServerInfo.Dust)
	}
	netParams := clientlib.ToBitcoinNetwork(clientlib.NetworkFromString(a.ServerInfo.Network))
	if _, err := btcutil.DecodeAddress(a.Receiver.To, &netParams); err != nil {
		return fmt.Errorf("invalid receiver address")
	}
	if len(a.ChangeAddr) <= 0 {
		return fmt.Errorf("missing change address")
	}
	return nil
}

// CollaborativeExit performs the full lifecycle of an on-chain exit through a
// batch session: selects vtxos to fund the on-chain output, then builds,
// signs, submits, handles batch events, and finalizes the resulting commitment
// transaction via JoinBatch.
func CollaborativeExit(
	ctx context.Context, args CollaborativeExitArgs, opts ...Option,
) (*BatchTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	vtxos, _, outputs, err := selectFunds(
		ctx, args.FeeEstimator, args.Vtxos, nil, []clientlib.Receiver{args.Receiver},
		args.ChangeAddr, o.expiryThreshold, args.ServerInfo.Dust,
	)
	if err != nil {
		return nil, err
	}

	return joinBatchWithRetry(ctx, JoinBatchArgs{
		BaseArgs: BaseArgs{
			Vtxos:   vtxos,
			Outputs: outputs,
			SignTx:  args.SignTx,
		},
		Client:     args.Client,
		ServerInfo: args.ServerInfo,
	}, opts...)
}
