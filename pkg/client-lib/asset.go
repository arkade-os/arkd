package arksdk

import (
	"context"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func (a *service) IssueAsset(
	ctx context.Context, amount uint64, controlAsset types.ControlAsset,
	metadata []asset.Metadata, opts ...SendOption,
) (string, []asset.AssetId, error) {
	if err := a.safeCheck(); err != nil {
		return "", nil, err
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", nil, err
	}

	if amount == 0 {
		return "", nil, fmt.Errorf("amount must be > 0")
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	receiverAsset := make([]types.Asset, 0)
	if existing, ok := controlAsset.(types.ExistingControlAsset); ok {
		// if the control asset is an existing one, we need to coinselect it
		// thus we add it to the receiver asset list
		receiverAsset = append(receiverAsset, types.Asset{
			AssetId: existing.ID,
			Amount:  1,
		})
	}

	receiver := types.Receiver{
		To: offchainAddrs[0].Address, Amount: a.Dust,
		Assets: receiverAsset,
	}

	// create an ark tx sending small amount of btc to wallet's address
	// we'll attach new asset outputs to this vout
	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, []types.Receiver{receiver}, opts...,
	)
	if err != nil {
		return "", nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return "", nil, err
	}

	assetGroups := make([]asset.AssetGroup, 0)
	var assetRef *asset.AssetRef

	packet, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins),
		[]types.Receiver{receiver},
		changeReceiver,
	)
	if err != nil {
		return "", nil, err
	}

	switch ca := controlAsset.(type) {
	case types.NewControlAsset:
		controlAssetOutput, err := asset.NewAssetOutput(0, ca.Amount)
		if err != nil {
			return "", nil, err
		}
		controlAssetGroup, err := asset.NewAssetGroup(
			nil,
			nil,
			make([]asset.AssetInput, 0),
			[]asset.AssetOutput{*controlAssetOutput},
			metadata,
		)
		if err != nil {
			return "", nil, err
		}

		assetGroups = append(assetGroups, *controlAssetGroup)
		assetRef = &asset.AssetRef{
			Type:       asset.AssetRefByGroup,
			GroupIndex: 0,
		}
	case types.ExistingControlAsset:
		controlAssetId, err := asset.NewAssetIdFromString(ca.ID)
		if err != nil {
			return "", nil, err
		}
		assetRef = &asset.AssetRef{
			Type:    asset.AssetRefByID,
			AssetId: *controlAssetId,
		}
	}

	issuedAssetOutput, err := asset.NewAssetOutput(0, amount)
	if err != nil {
		return "", nil, err
	}

	issuedAssetGroup, err := asset.NewAssetGroup(
		nil,
		assetRef,
		make([]asset.AssetInput, 0),
		[]asset.AssetOutput{*issuedAssetOutput},
		metadata,
	)
	if err != nil {
		return "", nil, err
	}
	assetGroups = append(assetGroups, *issuedAssetGroup)

	assetPacket, err := asset.NewPacket(append(assetGroups, packet...))
	if err != nil {
		return "", nil, err
	}

	if err := addAssetPacket(arkPtx, assetPacket); err != nil {
		return "", nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx)
	if err != nil {
		return "", nil, err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return "", nil, err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return "", nil, err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return "", nil, err
	}

	txid, err := a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
	if err != nil {
		return "", nil, err
	}

	assetIds := make([]asset.AssetId, 0)
	groupIdx := uint16(0)
	if _, ok := controlAsset.(types.NewControlAsset); ok {
		assetId, err := asset.NewAssetId(txid, groupIdx)
		if err != nil {
			return "", nil, err
		}
		assetIds = append(assetIds, *assetId)
		groupIdx++
	}

	assetId, err := asset.NewAssetId(txid, groupIdx)
	if err != nil {
		return "", nil, err
	}
	assetIds = append(assetIds, *assetId)

	return txid, assetIds, nil
}

func (a *service) ReissueAsset(
	ctx context.Context, assetId string, amount uint64, opts ...SendOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	if amount == 0 {
		return "", fmt.Errorf("amount must be > 0")
	}

	controlAssetId, err := a.getControlAssetId(ctx, assetId)
	if err != nil {
		return "", fmt.Errorf("failed to get control asset: %w", err)
	}

	if len(controlAssetId) == 0 {
		return "", fmt.Errorf("%s can't be reissued, no control asset", assetId)
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	receiver := types.Receiver{
		To: offchainAddrs[0].Address, Amount: a.Dust,
		Assets: []types.Asset{{
			AssetId: controlAssetId,
			Amount:  1, // TODO: should send all denominated amount of the asset vtxo
		}},
	}

	receivers := []types.Receiver{receiver}

	// create an ark tx sending small amount of btc to wallet's address
	// we'll attach new asset outputs to this vout
	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, receivers, opts...,
	)
	if err != nil {
		return "", err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return "", err
	}

	// create the asset packet for the local control asset inputs and receiver
	assetPacket, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins), receivers, changeReceiver,
	)
	if err != nil {
		return "", err
	}

	if len(assetPacket) == 0 {
		return "", fmt.Errorf("failed to create asset packet")
	}

	// add the reissued asset output to the asset packet
	issuedAssetOutput, err := asset.NewAssetOutput(0, amount)
	if err != nil {
		return "", err
	}

	// it may be possible some assetId are already in the tx,
	// thus we just need to add a new output without creating a new asset group
	groupIndex := -1
	for i, g := range assetPacket {
		if g.AssetId == nil {
			// skip issued asset group
			continue
		}

		if g.AssetId.String() == assetId {
			groupIndex = i
		}
	}

	// if group not found: add a new one
	if groupIndex == -1 {
		reissueAssetId, err := asset.NewAssetIdFromString(assetId)
		if err != nil {
			return "", err
		}

		issuedAssetGroup, err := asset.NewAssetGroup(
			reissueAssetId, nil, nil, []asset.AssetOutput{*issuedAssetOutput}, nil,
		)
		if err != nil {
			return "", err
		}
		assetPacket = append(assetPacket, *issuedAssetGroup)
	} else {
		// if group found: add a new output to the existing group
		assetPacket[groupIndex].Outputs = append(assetPacket[groupIndex].Outputs, *issuedAssetOutput)
	}

	if err := addAssetPacket(arkPtx, assetPacket); err != nil {
		return "", err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx)
	if err != nil {
		return "", err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return "", err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return "", err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return "", err
	}

	return a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
}

func (a *service) BurnAsset(
	ctx context.Context, assetId string, amount uint64, opts ...SendOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if amount == 0 {
		return "", fmt.Errorf("amount must be > 0")
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}
	if len(offchainAddrs) <= 0 {
		return "", fmt.Errorf("no offchain addresses")
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	burnReceiver := types.Receiver{
		To:     offchainAddrs[0].Address,
		Amount: a.Dust,
		Assets: []types.Asset{{
			AssetId: assetId,
			Amount:  amount,
		}},
	}

	receivers := []types.Receiver{burnReceiver}
	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, receivers, opts...,
	)
	if err != nil {
		return "", err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return "", err
	}

	// before creating the packet, remove the asset from the receivers in order to burn it
	// replace it by the change receiver assets
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
		return "", err
	}

	if err := addAssetPacket(arkPtx, assetPacket); err != nil {
		return "", err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx)
	if err != nil {
		return "", err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return "", err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return "", err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return "", err
	}

	return a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
}

func (a *service) getControlAssetId(ctx context.Context, assetId string) (string, error) {
	indexerAssetInfo, err := a.indexer.GetAsset(ctx, assetId)
	if err != nil {
		return "", fmt.Errorf("failed to fetch asset from indexer: %w", err)
	}

	return indexerAssetInfo.ControlAssetId, nil
}
