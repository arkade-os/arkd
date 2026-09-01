package offchaintx

import (
	"context"
	"fmt"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

// IssueAsset builds, signs, submits, verifies, and finalizes an offchain ark
// transaction that issues one (or two, when a new control asset is created)
// asset groups. Returns the finalized tx along with the IDs of the newly
// minted assets.
func IssueAsset(
	ctx context.Context, args IssueAssetArgs, opts ...Option,
) (*IssueAssetRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	buildArgs := args.toBuildArgs()
	signers := args.ServerParams.AllSigners()

	build, err := BuildAndSignIssuanceTx(ctx, buildArgs, opts...)
	if err != nil {
		return nil, err
	}

	txid, tx, checkpointTxs, err := submitAndFinalize(
		ctx, args.Client, args.SignTx, signers, &build.BuildAndSignTxRes,
	)
	if err != nil {
		return nil, err
	}

	// The result receiver is the caller's change address decorated with the
	// newly minted asset IDs. For the ExistingControlAsset case the receiver
	// also carries one unit of the existing control asset.
	receiver := clientlib.Receiver{
		To:     args.ChangeAddr,
		Amount: args.ServerParams.Dust,
	}
	if existing, ok := args.ControlAsset.(clientlib.ExistingControlAsset); ok {
		receiver.Assets = append(receiver.Assets, clientlib.Asset{
			AssetId: existing.Id,
			Amount:  existing.Amount,
		})
	}
	for i, id := range build.IssuedAssets {
		receiver.Assets = append(receiver.Assets, clientlib.Asset{
			AssetId: id.String(),
			Amount:  assetGroupOutputAmount(build, i),
		})
	}

	outs := []clientlib.Receiver{receiver}
	if build.ChangeReceiver != nil {
		outs = append(outs, *build.ChangeReceiver)
	}

	return &IssueAssetRes{
		OffchainTxRes: OffchainTxRes{
			Txid:          txid,
			Tx:            tx,
			CheckpointTxs: checkpointTxs,
			Inputs:        build.SelectedCoins,
			Outputs:       outs,
			Extension:     build.Extension,
		},
		IssuedAssets: build.IssuedAssets,
	}, nil
}

// assetGroupOutputAmount reads the (single-output-per-group) amount the
// primitive recorded for the i-th issued asset.
func assetGroupOutputAmount(build *BuildAndSignIssuanceTxRes, i int) uint64 {
	if i >= len(build.AssetPacket) {
		return 0
	}
	if len(build.AssetPacket[i].Outputs) == 0 {
		return 0
	}
	return build.AssetPacket[i].Outputs[0].Amount
}

// ReissueAsset builds, signs, submits, verifies, and finalizes an offchain ark
// transaction that mints additional units of an existing asset, authorized by
// the control asset vtxo held by the caller.
func ReissueAsset(
	ctx context.Context, args ReissueAssetArgs, opts ...Option,
) (*OffchainTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	buildArgs := args.toBuildArgs()
	signers := args.ServerParams.AllSigners()

	build, err := BuildAndSignReissuanceTx(ctx, buildArgs, opts...)
	if err != nil {
		return nil, err
	}

	txid, tx, checkpointTxs, err := submitAndFinalize(
		ctx, args.Client, args.SignTx, signers, build,
	)
	if err != nil {
		return nil, err
	}

	receiver := clientlib.Receiver{
		To:     args.ChangeAddr,
		Amount: args.ServerParams.Dust,
		Assets: []clientlib.Asset{args.ControlAsset, args.Asset},
	}

	outs := []clientlib.Receiver{receiver}
	if build.ChangeReceiver != nil {
		outs = append(outs, *build.ChangeReceiver)
	}

	return &OffchainTxRes{
		Txid:          txid,
		Tx:            tx,
		CheckpointTxs: checkpointTxs,
		Inputs:        build.SelectedCoins,
		Outputs:       outs,
		Extension:     build.Extension,
	}, nil
}

// BurnAsset builds, signs, submits, verifies, and finalizes an offchain ark
// transaction that destroys a given amount of an asset, returning any
// remaining asset balance and BTC change to the caller's change address.
func BurnAsset(ctx context.Context, args BurnAssetArgs, opts ...Option) (*OffchainTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	buildArgs := args.toBuildArgs()
	signers := args.ServerParams.AllSigners()

	build, err := BuildAndSignBurnTx(ctx, buildArgs, opts...)
	if err != nil {
		return nil, err
	}

	txid, tx, checkpointTxs, err := submitAndFinalize(
		ctx, args.Client, args.SignTx, signers, build,
	)
	if err != nil {
		return nil, err
	}

	// Two-output layout:
	//   first output: burn receiver at Dust, carrying change's assets if any
	//   second output (optional): plain BTC change at change amount
	burnAssets := []clientlib.Asset(nil)
	if build.ChangeReceiver != nil {
		burnAssets = build.ChangeReceiver.Assets
	}

	outs := []clientlib.Receiver{{
		To:     args.ChangeAddr,
		Amount: args.ServerParams.Dust,
		Assets: burnAssets,
	}}
	if build.ChangeReceiver != nil {
		outs = append(outs, clientlib.Receiver{
			To:     build.ChangeReceiver.To,
			Amount: build.ChangeReceiver.Amount,
		})
	}

	return &OffchainTxRes{
		Txid:          txid,
		Tx:            tx,
		CheckpointTxs: checkpointTxs,
		Inputs:        build.SelectedCoins,
		Outputs:       outs,
		Extension:     build.Extension,
	}, nil
}
