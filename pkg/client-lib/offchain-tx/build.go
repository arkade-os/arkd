package offchaintx

import (
	"context"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// BuildAndSignTx builds and signs an offchain transaction (plus its checkpoint transactions)
// ready for submission. It does NOT submit the txs to the server — callers can use the result
// with a custom submit flow, while SendOffChain wraps the full lifecycle.
func BuildAndSignTx(
	ctx context.Context, args BuildAndSignTxArgs, opts ...Option,
) (*BuildAndSignTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := createOffchainTx(
		ctx, args.BaseArgs, args.Receivers,
	)
	if err != nil {
		return nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return nil, err
	}

	// Pass the ORIGINAL receivers (without change) to createAssetPacket and
	// hand changeReceiver as a separate argument — createOffchainTx already
	// appended the change to its own copy of the receivers slice.
	assetPacket, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins),
		args.Receivers,
		changeReceiver,
	)
	if err != nil {
		return nil, err
	}

	if err := addExtension(arkPtx, assetPacket, o.extraPackets); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedArkTx, err := args.SignTx(ctx, arkTx)
	if err != nil {
		return nil, err
	}

	ext := make(extension.Extension, 0, 1+len(o.extraPackets))
	if len(assetPacket) > 0 {
		ext = append(ext, assetPacket)
	}
	ext = append(ext, o.extraPackets...)

	return &BuildAndSignTxRes{
		Txid:           arkPtx.UnsignedTx.TxID(),
		ArkTx:          arkTx,
		SignedArkTx:    signedArkTx,
		CheckpointTxs:  checkpointTxs,
		SelectedCoins:  selectedCoins,
		ChangeReceiver: changeReceiver,
		AssetPacket:    assetPacket,
		Extension:      ext,
	}, nil
}

// BuildAndSignIssuanceTx builds and signs an offchain ark transaction that
// issues a new asset (and, optionally, a fresh control asset). It does NOT
// submit the tx to the server — IssueAsset wraps the full lifecycle.
func BuildAndSignIssuanceTx(
	ctx context.Context, args BuildAndSignIssuanceTxArgs, opts ...Option,
) (*BuildAndSignIssuanceTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	receiverAsset := make([]clientlib.Asset, 0)
	if existing, ok := args.ControlAsset.(clientlib.ExistingControlAsset); ok {
		receiverAsset = append(receiverAsset, clientlib.Asset{
			AssetId: existing.Id,
			Amount:  existing.Amount,
		})
	}

	receiver := clientlib.Receiver{
		To:     args.ChangeAddr,
		Amount: args.ServerInfo.Dust,
		Assets: receiverAsset,
	}

	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := createOffchainTx(
		ctx, args.BaseArgs, []clientlib.Receiver{receiver},
	)
	if err != nil {
		return nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return nil, err
	}

	assetGroups := make([]asset.AssetGroup, 0)
	var assetRef *asset.AssetRef

	packet, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins),
		[]clientlib.Receiver{receiver},
		changeReceiver,
	)
	if err != nil {
		return nil, err
	}

	switch ca := args.ControlAsset.(type) {
	case clientlib.NewControlAsset:
		controlAssetOutput, err := asset.NewAssetOutput(0, ca.Amount)
		if err != nil {
			return nil, err
		}
		controlAssetGroup, err := asset.NewAssetGroup(
			nil, nil, nil,
			[]asset.AssetOutput{*controlAssetOutput}, args.Metadata,
		)
		if err != nil {
			return nil, err
		}
		assetGroups = append(assetGroups, *controlAssetGroup)
		assetRef = &asset.AssetRef{Type: asset.AssetRefByGroup, GroupIndex: 0}
	case clientlib.ExistingControlAsset:
		controlAssetId, err := asset.NewAssetIdFromString(ca.Id)
		if err != nil {
			return nil, err
		}
		assetRef = &asset.AssetRef{Type: asset.AssetRefByID, AssetId: *controlAssetId}
	}

	issuedAssetOutput, err := asset.NewAssetOutput(0, args.Amount)
	if err != nil {
		return nil, err
	}
	issuedAssetGroup, err := asset.NewAssetGroup(
		nil, assetRef, nil,
		[]asset.AssetOutput{*issuedAssetOutput}, args.Metadata,
	)
	if err != nil {
		return nil, err
	}
	assetGroups = append(assetGroups, *issuedAssetGroup)

	assetPacket, err := asset.NewPacket(append(assetGroups, packet...))
	if err != nil {
		return nil, err
	}

	if err := addExtension(arkPtx, assetPacket, o.extraPackets); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	txid := arkPtx.UnsignedTx.TxID()

	// Derive asset IDs from the (now stable) txid + group index.
	issuedAssets := make([]asset.AssetId, 0, len(assetGroups))
	groupIdx := uint16(0)
	if _, ok := args.ControlAsset.(clientlib.NewControlAsset); ok {
		controlId, err := asset.NewAssetId(txid, groupIdx)
		if err != nil {
			return nil, err
		}
		issuedAssets = append(issuedAssets, *controlId)
		groupIdx++
	}
	issuedId, err := asset.NewAssetId(txid, groupIdx)
	if err != nil {
		return nil, err
	}
	issuedAssets = append(issuedAssets, *issuedId)

	signedArkTx, err := args.SignTx(ctx, arkTx)
	if err != nil {
		return nil, err
	}

	ext := append(extension.Extension{assetPacket}, o.extraPackets...)

	return &BuildAndSignIssuanceTxRes{
		BuildAndSignTxRes: BuildAndSignTxRes{
			Txid:           txid,
			ArkTx:          arkTx,
			SignedArkTx:    signedArkTx,
			CheckpointTxs:  checkpointTxs,
			SelectedCoins:  selectedCoins,
			ChangeReceiver: changeReceiver,
			AssetPacket:    assetPacket,
			Extension:      ext,
		},
		IssuedAssets: issuedAssets,
	}, nil
}

// BuildAndSignReissuanceTx builds and signs an offchain ark transaction that
// mints additional units of an existing asset, authorized by the control
// asset. It does NOT submit the tx to the server — ReissueAsset wraps the
// full lifecycle.
func BuildAndSignReissuanceTx(
	ctx context.Context, args BuildAndSignReissuanceTxArgs, opts ...Option,
) (*BuildAndSignTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	receiver := clientlib.Receiver{
		To:     args.ChangeAddr,
		Amount: args.ServerInfo.Dust,
		Assets: []clientlib.Asset{args.ControlAsset},
	}

	receivers := []clientlib.Receiver{receiver}

	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := createOffchainTx(
		ctx, args.BaseArgs, receivers,
	)
	if err != nil {
		return nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return nil, err
	}

	assetPacket, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins), receivers, changeReceiver,
	)
	if err != nil {
		return nil, err
	}
	if len(assetPacket) == 0 {
		return nil, fmt.Errorf("failed to create asset packet")
	}

	issuedAssetOutput, err := asset.NewAssetOutput(0, args.Asset.Amount)
	if err != nil {
		return nil, err
	}

	groupIndex := -1
	for i, g := range assetPacket {
		if g.AssetId == nil {
			continue
		}
		if g.AssetId.String() == args.Asset.AssetId {
			groupIndex = i
		}
	}

	if groupIndex == -1 {
		reissueAssetId, err := asset.NewAssetIdFromString(args.Asset.AssetId)
		if err != nil {
			return nil, err
		}
		issuedAssetGroup, err := asset.NewAssetGroup(
			reissueAssetId, nil, nil, []asset.AssetOutput{*issuedAssetOutput}, nil,
		)
		if err != nil {
			return nil, err
		}
		assetPacket = append(assetPacket, *issuedAssetGroup)
	} else {
		assetPacket[groupIndex].Outputs = append(
			assetPacket[groupIndex].Outputs, *issuedAssetOutput,
		)
	}

	if err := addExtension(arkPtx, assetPacket, o.extraPackets); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedArkTx, err := args.SignTx(ctx, arkTx)
	if err != nil {
		return nil, err
	}

	ext := append(extension.Extension{assetPacket}, o.extraPackets...)

	return &BuildAndSignTxRes{
		Txid:           arkPtx.UnsignedTx.TxID(),
		ArkTx:          arkTx,
		SignedArkTx:    signedArkTx,
		CheckpointTxs:  checkpointTxs,
		SelectedCoins:  selectedCoins,
		ChangeReceiver: changeReceiver,
		AssetPacket:    assetPacket,
		Extension:      ext,
	}, nil
}

// BuildAndSignBurnTx builds and signs an offchain ark transaction that
// destroys a given amount of an asset, carrying any remaining asset change
// and BTC change back to the caller. It does NOT submit the tx to the
// server — BurnAsset wraps the full lifecycle.
func BuildAndSignBurnTx(
	ctx context.Context, args BuildAndSignBurnTxArgs, opts ...Option,
) (*BuildAndSignTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	burnReceiver := clientlib.Receiver{
		To:     args.ChangeAddr,
		Amount: args.ServerInfo.Dust,
		Assets: []clientlib.Asset{{
			AssetId: args.AssetId,
			Amount:  args.Amount,
		}},
	}

	receivers := []clientlib.Receiver{burnReceiver}
	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := createOffchainTx(
		ctx, args.BaseArgs, receivers,
	)
	if err != nil {
		return nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return nil, err
	}

	// remove the burned asset from receivers; carry the change's assets back
	if changeReceiver != nil {
		receivers[0].Assets = changeReceiver.Assets
		receivers[0].Amount += changeReceiver.Amount
	} else {
		receivers[0].Assets = nil
	}

	assetPacket, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins), receivers, nil,
	)
	if err != nil {
		return nil, err
	}

	if err := addExtension(arkPtx, assetPacket, o.extraPackets); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedArkTx, err := args.SignTx(ctx, arkTx)
	if err != nil {
		return nil, err
	}

	ext := append(extension.Extension{assetPacket}, o.extraPackets...)

	return &BuildAndSignTxRes{
		Txid:           arkPtx.UnsignedTx.TxID(),
		ArkTx:          arkTx,
		SignedArkTx:    signedArkTx,
		CheckpointTxs:  checkpointTxs,
		SelectedCoins:  selectedCoins,
		ChangeReceiver: changeReceiver,
		AssetPacket:    assetPacket,
		Extension:      ext,
	}, nil
}
