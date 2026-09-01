package offchaintx

import (
	"context"
	"fmt"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

// Send builds, signs, submits, verifies, and finalizes an offchain
// payment transaction.
func Send(ctx context.Context, args SendArgs, opts ...Option) (*OffchainTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	buildArgs := args.toBuildArgs()
	signers := args.ServerParams.AllSigners()

	build, err := BuildAndSignTx(ctx, buildArgs, opts...)
	if err != nil {
		return nil, err
	}

	txid, signedArk, finalCps, err := submitAndFinalize(
		ctx, args.Client, args.SignTx, signers, build,
	)
	if err != nil {
		return nil, err
	}

	outs := make([]clientlib.Receiver, 0)
	if build.ChangeReceiver != nil {
		outs = append(outs, *build.ChangeReceiver)
	}

	return &OffchainTxRes{
		Txid:          txid,
		Tx:            signedArk,
		CheckpointTxs: finalCps,
		Inputs:        build.SelectedCoins,
		Outputs:       outs,
		Extension:     build.Extension,
	}, nil
}
