package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type delegateBatchEventsHandler struct {
	intentId         string
	signerSession    tree.SignerSession
	partialForfeitTx string
	delegatorWallet  wallet.WalletService
	client           client.TransportClient
	forfeitPubKey    *btcec.PublicKey
	batchExpiry      arklib.RelativeLocktime

	cacheBatchId string
}

func (h *delegateBatchEventsHandler) OnStreamStarted(
	ctx context.Context, event client.StreamStartedEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnBatchStarted(
	ctx context.Context, event client.BatchStartedEvent,
) (bool, error) {
	buf := sha256.Sum256([]byte(h.intentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, hash := range event.HashedIntentIds {
		if hash == hashedIntentId {
			if err := h.client.ConfirmRegistration(ctx, h.intentId); err != nil {
				return false, err
			}
			h.cacheBatchId = event.Id
			h.batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
			return false, nil
		}
	}

	return true, nil
}

func (h *delegateBatchEventsHandler) OnBatchFinalized(
	ctx context.Context, event client.BatchFinalizedEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnBatchFailed(
	ctx context.Context, event client.BatchFailedEvent,
) error {
	if event.Id == h.cacheBatchId {
		return fmt.Errorf("batch failed: %s", event.Reason)
	}
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeTxEvent(
	ctx context.Context, event client.TreeTxEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSignatureEvent(
	ctx context.Context, event client.TreeSignatureEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSigningStarted(
	ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	myPubkey := h.signerSession.GetPublicKey()
	if !slices.Contains(event.CosignersPubkeys, myPubkey) {
		return true, nil
	}

	sweepClosure := script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{h.forfeitPubKey}},
		Locktime:        h.batchExpiry,
	}

	script, err := sweepClosure.Script()
	if err != nil {
		return false, err
	}

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}

	batchOutput := commitmentTx.UnsignedTx.TxOut[0]
	batchOutputAmount := batchOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	generateAndSendNonces := func(session tree.SignerSession) error {
		if err := session.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
			return err
		}

		nonces, err := session.GetNonces()
		if err != nil {
			return err
		}

		return h.client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces)
	}

	if err := generateAndSendNonces(h.signerSession); err != nil {
		return false, err
	}

	return false, nil
}

func (h *delegateBatchEventsHandler) OnTreeNonces(
	ctx context.Context,
	event client.TreeNoncesEvent,
) (bool, error) {
	return false, nil
}

func (h *delegateBatchEventsHandler) OnTreeNoncesAggregated(
	ctx context.Context,
	event client.TreeNoncesAggregatedEvent,
) (bool, error) {
	h.signerSession.SetAggregatedNonces(event.Nonces)

	sigs, err := h.signerSession.Sign()
	if err != nil {
		return false, err
	}

	err = h.client.SubmitTreeSignatures(
		ctx,
		event.Id,
		h.signerSession.GetPublicKey(),
		sigs,
	)
	return err == nil, err
}

func (h *delegateBatchEventsHandler) OnBatchFinalization(
	ctx context.Context,
	event client.BatchFinalizationEvent,
	vtxoTree *tree.TxTree,
	connectorTree *tree.TxTree,
) error {
	forfeitPtx, err := psbt.NewFromRawBytes(strings.NewReader(h.partialForfeitTx), true)
	if err != nil {
		return err
	}

	updater, err := psbt.NewUpdater(forfeitPtx)
	if err != nil {
		return err
	}

	// add the connector input to the forfeit tx
	connectors := connectorTree.Leaves()
	connector := connectors[0]
	updater.Upsbt.UnsignedTx.TxIn = append(updater.Upsbt.UnsignedTx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  connector.UnsignedTx.TxHash(),
			Index: 0,
		},
		Sequence: wire.MaxTxInSequenceNum,
	})
	updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    connector.UnsignedTx.TxOut[0].Value,
			PkScript: connector.UnsignedTx.TxOut[0].PkScript,
		},
	})

	if err := updater.AddInSighashType(txscript.SigHashDefault, 0); err != nil {
		return err
	}

	encodedForfeitTx, err := updater.Upsbt.B64Encode()
	if err != nil {
		return err
	}

	// sign the forfeit tx
	signedForfeitTx, err := h.delegatorWallet.SignTransaction(
		context.Background(),
		nil,
		encodedForfeitTx,
	)
	if err != nil {
		return err
	}

	return h.client.SubmitSignedForfeitTxs(
		ctx, []string{signedForfeitTx}, "",
	)
}

type customBatchEventsHandler struct {
	onStreamStarted        func(ctx context.Context, event client.StreamStartedEvent) error
	onBatchStarted         func(ctx context.Context, event client.BatchStartedEvent) (bool, error)
	onBatchFinalization    func(ctx context.Context, event client.BatchFinalizationEvent, vtxoTree *tree.TxTree, connectorTree *tree.TxTree) error
	onBatchFinalized       func(ctx context.Context, event client.BatchFinalizedEvent) error
	onBatchFailed          func(ctx context.Context, event client.BatchFailedEvent) error
	onTreeTxEvent          func(ctx context.Context, event client.TreeTxEvent) error
	onTreeSignatureEvent   func(ctx context.Context, event client.TreeSignatureEvent) error
	onTreeSigningStarted   func(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error)
	onTreeNoncesAggregated func(ctx context.Context, event client.TreeNoncesAggregatedEvent) (bool, error)
}

func (h *customBatchEventsHandler) OnStreamStarted(
	ctx context.Context,
	event client.StreamStartedEvent,
) error {
	if h.onStreamStarted != nil {
		return h.onStreamStarted(ctx, event)
	}
	return nil
}

func (h *customBatchEventsHandler) OnBatchStarted(
	ctx context.Context,
	event client.BatchStartedEvent,
) (bool, error) {
	if h.onBatchStarted != nil {
		return h.onBatchStarted(ctx, event)
	}
	return false, nil
}

func (h *customBatchEventsHandler) OnBatchFinalization(
	ctx context.Context,
	event client.BatchFinalizationEvent,
	vtxoTree *tree.TxTree,
	connectorTree *tree.TxTree,
) error {
	if h.onBatchFinalization != nil {
		return h.onBatchFinalization(ctx, event, vtxoTree, connectorTree)
	}
	return nil
}

func (h *customBatchEventsHandler) OnBatchFinalized(
	ctx context.Context,
	event client.BatchFinalizedEvent,
) error {
	if h.onBatchFinalized != nil {
		return h.onBatchFinalized(ctx, event)
	}
	return nil
}

func (h *customBatchEventsHandler) OnBatchFailed(
	ctx context.Context,
	event client.BatchFailedEvent,
) error {
	if h.onBatchFailed != nil {
		return h.onBatchFailed(ctx, event)
	}
	return errors.New(event.Reason)
}

func (h *customBatchEventsHandler) OnTreeTxEvent(
	ctx context.Context,
	event client.TreeTxEvent,
) error {
	if h.onTreeTxEvent != nil {
		return h.onTreeTxEvent(ctx, event)
	}
	return nil
}

func (h *customBatchEventsHandler) OnTreeSignatureEvent(
	ctx context.Context,
	event client.TreeSignatureEvent,
) error {
	if h.onTreeSignatureEvent != nil {
		return h.onTreeSignatureEvent(ctx, event)
	}
	return nil
}

func (h *customBatchEventsHandler) OnTreeSigningStarted(
	ctx context.Context,
	event client.TreeSigningStartedEvent,
	vtxoTree *tree.TxTree,
) (bool, error) {
	if h.onTreeSigningStarted != nil {
		return h.onTreeSigningStarted(ctx, event, vtxoTree)
	}
	return false, nil
}

func (h *customBatchEventsHandler) OnTreeNoncesAggregated(
	ctx context.Context,
	event client.TreeNoncesAggregatedEvent,
) (bool, error) {
	if h.onTreeNoncesAggregated != nil {
		return h.onTreeNoncesAggregated(ctx, event)
	}
	return false, nil
}

func (h *customBatchEventsHandler) OnTreeNonces(
	ctx context.Context,
	event client.TreeNoncesEvent,
) (bool, error) {
	return false, nil
}
