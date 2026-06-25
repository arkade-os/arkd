package batchsession

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcutil"
)

// CollaborativeExitArgs configures a CollaborativeExit call: the Vtxos to spend and the on-chain
// Receiver to credit.
// FeeEstimator is used to size the on-chain output, SignTx signs the intent proof, and
// ServerParams/Client are used to talk to the server.
type CollaborativeExitArgs struct {
	Client       clientlib.Client
	ServerParams clientlib.ServerParams
	SignTx       clientlib.SignFn
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
	if len(a.Vtxos) <= 0 {
		return fmt.Errorf("missing funds for collaborative exit")
	}
	if len(a.Receiver.To) <= 0 {
		return fmt.Errorf("missing receiver address")
	}
	if len(a.ServerParams.Network.Name) <= 0 || a.ServerParams.Dust == 0 {
		return fmt.Errorf("missing server info")
	}
	if a.Receiver.Amount < a.ServerParams.Dust {
		return fmt.Errorf("invalid receiver amount, must be at least %d", a.ServerParams.Dust)
	}
	netParams := clientlib.ToBitcoinNetwork(a.ServerParams.Network)
	if _, err := btcutil.DecodeAddress(a.Receiver.To, &netParams); err != nil {
		return fmt.Errorf("invalid receiver address")
	}
	if len(a.ChangeAddr) <= 0 {
		return fmt.Errorf("missing change address")
	}
	return nil
}

// CollaborativeExit performs the full lifecycle of an on-chain exit through a batch session:
// selects vtxos to fund the on-chain output, builds, signs, and submits the intent, and then
// joins the batch session.
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

	feeEstimator, err := arkfee.New(args.ServerParams.Fees.IntentFees)
	if err != nil {
		return nil, err
	}

	vtxos, _, outputs, err := selectFunds(
		ctx, feeEstimator, args.Vtxos, nil, []clientlib.Receiver{args.Receiver},
		args.ChangeAddr, o.expiryThreshold, args.ServerParams.Dust,
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
		Client:       args.Client,
		ServerParams: args.ServerParams,
	}, opts...)
}
