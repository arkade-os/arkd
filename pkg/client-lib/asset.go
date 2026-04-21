package arksdk

import (
	"context"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func (a *service) IssueAsset(
	ctx context.Context, amount uint64, controlAsset types.ControlAsset,
	metadata []asset.Metadata, opts ...SendOption,
) (*IssueAssetRes, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	o := newDefaultSendOptions()
	for _, opt := range opts {
		if err := opt.applySend(o); err != nil {
			return nil, err
		}
	}

	_, changeAddr, _, err := a.newAddress(ctx)
	if err != nil {
		return nil, err
	}

	if amount == 0 {
		return nil, fmt.Errorf("amount must be > 0")
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
		To: changeAddr.Address, Amount: a.Dust,
		Assets: receiverAsset,
	}

	// create an ark tx sending small amount of btc to wallet's address
	// we'll attach new asset outputs to this vout
	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, []types.Receiver{receiver}, o,
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
		[]types.Receiver{receiver},
		changeReceiver,
	)
	if err != nil {
		return nil, err
	}

	switch ca := controlAsset.(type) {
	case types.NewControlAsset:
		controlAssetOutput, err := asset.NewAssetOutput(0, ca.Amount)
		if err != nil {
			return nil, err
		}
		controlAssetGroup, err := asset.NewAssetGroup(
			nil,
			nil,
			make([]asset.AssetInput, 0),
			[]asset.AssetOutput{*controlAssetOutput},
			metadata,
		)
		if err != nil {
			return nil, err
		}

		assetGroups = append(assetGroups, *controlAssetGroup)
		assetRef = &asset.AssetRef{
			Type:       asset.AssetRefByGroup,
			GroupIndex: 0,
		}
	case types.ExistingControlAsset:
		controlAssetId, err := asset.NewAssetIdFromString(ca.ID)
		if err != nil {
			return nil, err
		}
		assetRef = &asset.AssetRef{
			Type:    asset.AssetRefByID,
			AssetId: *controlAssetId,
		}
	}

	issuedAssetOutput, err := asset.NewAssetOutput(0, amount)
	if err != nil {
		return nil, err
	}

	issuedAssetGroup, err := asset.NewAssetGroup(
		nil,
		assetRef,
		make([]asset.AssetInput, 0),
		[]asset.AssetOutput{*issuedAssetOutput},
		metadata,
	)
	if err != nil {
		return nil, err
	}
	assetGroups = append(assetGroups, *issuedAssetGroup)

	assetPacket, err := asset.NewPacket(append(assetGroups, packet...))
	if err != nil {
		return nil, err
	}

	if err := addAssetPacket(arkPtx, assetPacket); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx, o.signingKeys)
	if err != nil {
		return nil, err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return nil, err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return nil, err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return nil, err
	}

	txid, checkpointTxs, err := a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
	if err != nil {
		return nil, err
	}

	assetIds := make([]asset.AssetId, 0)
	groupIdx := uint16(0)
	if _, ok := controlAsset.(types.NewControlAsset); ok {
		assetId, err := asset.NewAssetId(txid, groupIdx)
		if err != nil {
			return nil, err
		}
		assetIds = append(assetIds, *assetId)
		groupIdx++
	}

	assetId, err := asset.NewAssetId(txid, groupIdx)
	if err != nil {
		return nil, err
	}
	assetIds = append(assetIds, *assetId)

	// Add assets info to receiver and returns as outputs together with the optional change
	for groupIndex, assetGroup := range assetGroups {
		// we know there's only one output per asset
		output := assetGroup.Outputs[0]
		//nolint
		assetId, _ := asset.NewAssetId(txid, uint16(groupIndex))

		receiver.Assets = append(receiver.Assets, types.Asset{
			AssetId: assetId.String(),
			Amount:  output.Amount,
		})
	}

	ins := make([]types.Vtxo, 0, len(selectedCoins))
	for _, c := range selectedCoins {
		ins = append(ins, c.Vtxo)
	}

	outs := make([]types.Receiver, 0)
	outs = append(outs, receiver)
	if changeReceiver != nil {
		outs = append(outs, *changeReceiver)
	}

	return &IssueAssetRes{
		OffchainTxRes: OffchainTxRes{
			Txid:        txid,
			Tx:          signedArkTx,
			Checkpoints: checkpointTxs,
			Inputs:      ins,
			Outputs:     outs,
			Extension:   extension.Extension{assetPacket},
		},
		IssuedAssets: assetIds,
	}, nil
}

func (a *service) ReissueAsset(
	ctx context.Context, assetId string, amount uint64, opts ...SendOption,
) (*ReissueAssetRes, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	o := newDefaultSendOptions()
	for _, opt := range opts {
		if err := opt.applySend(o); err != nil {
			return nil, err
		}
	}

	_, changeAddr, _, err := a.newAddress(ctx)
	if err != nil {
		return nil, err
	}

	if amount == 0 {
		return nil, fmt.Errorf("amount must be > 0")
	}

	controlAssetId, err := a.getControlAssetId(ctx, assetId)
	if err != nil {
		return nil, fmt.Errorf("failed to get control asset: %w", err)
	}

	if len(controlAssetId) == 0 {
		return nil, fmt.Errorf("%s can't be reissued, no control asset", assetId)
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	receiver := types.Receiver{
		To: changeAddr.Address, Amount: a.Dust,
		Assets: []types.Asset{{
			AssetId: controlAssetId,
			Amount:  1, // TODO: should send all denominated amount of the asset vtxo
		}},
	}

	receivers := []types.Receiver{receiver}

	// create an ark tx sending small amount of btc to wallet's address
	// we'll attach new asset outputs to this vout
	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, receivers, o,
	)
	if err != nil {
		return nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return nil, err
	}

	// create the asset packet for the local control asset inputs and receiver
	assetPacket, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins), receivers, changeReceiver,
	)
	if err != nil {
		return nil, err
	}

	if len(assetPacket) == 0 {
		return nil, fmt.Errorf("failed to create asset packet")
	}

	// add the reissued asset output to the asset packet
	issuedAssetOutput, err := asset.NewAssetOutput(0, amount)
	if err != nil {
		return nil, err
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
		// if group found: add a new output to the existing group
		assetPacket[groupIndex].Outputs = append(assetPacket[groupIndex].Outputs, *issuedAssetOutput)
	}

	if err := addAssetPacket(arkPtx, assetPacket); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx, o.signingKeys)
	if err != nil {
		return nil, err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return nil, err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return nil, err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return nil, err
	}

	txid, checkpointTxs, err := a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
	if err != nil {
		return nil, err
	}

	ins := make([]types.Vtxo, 0, len(selectedCoins))
	for _, c := range selectedCoins {
		ins = append(ins, c.Vtxo)
	}

	receiver.Assets = append(receiver.Assets, types.Asset{
		AssetId: assetId,
		Amount:  amount,
	})

	outs := make([]types.Receiver, 0)
	outs = append(outs, receiver)
	if changeReceiver != nil {
		outs = append(outs, *changeReceiver)
	}

	return &ReissueAssetRes{
		Txid:        txid,
		Tx:          signedArkTx,
		Checkpoints: checkpointTxs,
		Inputs:      ins,
		Outputs:     outs,
		Extension:   extension.Extension{assetPacket},
	}, nil
}

func (a *service) BurnAsset(
	ctx context.Context, assetId string, amount uint64, opts ...SendOption,
) (*BurnAssetRes, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	if amount == 0 {
		return nil, fmt.Errorf("amount must be > 0")
	}

	o := newDefaultSendOptions()
	for _, opt := range opts {
		if err := opt.applySend(o); err != nil {
			return nil, err
		}
	}

	_, changeAddr, _, err := a.newAddress(ctx)
	if err != nil {
		return nil, err
	}
	if len(changeAddr.Address) <= 0 {
		return nil, fmt.Errorf("no offchain addresses")
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	burnReceiver := types.Receiver{
		To:     changeAddr.Address,
		Amount: a.Dust,
		Assets: []types.Asset{{
			AssetId: assetId,
			Amount:  amount,
		}},
	}

	receivers := []types.Receiver{burnReceiver}
	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, receivers, o,
	)
	if err != nil {
		return nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if err := addAssetPacket(arkPtx, assetPacket); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx, o.signingKeys)
	if err != nil {
		return nil, err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return nil, err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return nil, err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return nil, err
	}

	txid, checkpointTxs, err := a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
	if err != nil {
		return nil, err
	}

	ins := make([]types.Vtxo, 0, len(selectedCoins))
	for _, c := range selectedCoins {
		ins = append(ins, c.Vtxo)
	}
	outs := []types.Receiver{
		{To: receivers[0].To, Amount: burnReceiver.Amount, Assets: receivers[0].Assets},
	}
	if changeReceiver != nil {
		outs = append(outs, types.Receiver{To: changeReceiver.To, Amount: changeReceiver.Amount})
	}

	return &BurnAssetRes{
		Txid:        txid,
		Tx:          signedArkTx,
		Checkpoints: checkpointTxs,
		Inputs:      ins,
		Outputs:     outs,
		Extension:   extension.Extension{assetPacket},
	}, nil
}

func (a *service) getControlAssetId(ctx context.Context, assetId string) (string, error) {
	indexerAssetInfo, err := a.indexer.GetAsset(ctx, assetId)
	if err != nil {
		return "", fmt.Errorf("failed to fetch asset from indexer: %w", err)
	}

	return indexerAssetInfo.ControlAssetId, nil
}
