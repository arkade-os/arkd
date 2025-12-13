package arksdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

const (
	start = iota
	batchStarted
	treeSigningStarted
	treeNoncesAggregated
	batchFinalization
)

func GetEventStreamTopics(
	spentOutpoints []types.Outpoint, signerSessions []tree.SignerSession,
) []string {
	topics := make([]string, 0, len(spentOutpoints))
	for _, outpoint := range spentOutpoints {
		topics = append(topics, outpoint.String())
	}
	for _, signer := range signerSessions {
		topics = append(topics, signer.GetPublicKey())
	}
	return topics
}

type BatchEventsHandler interface {
	OnBatchStarted(ctx context.Context, event client.BatchStartedEvent) (bool, error)
	OnBatchFinalized(ctx context.Context, event client.BatchFinalizedEvent) error
	OnBatchFailed(ctx context.Context, event client.BatchFailedEvent) error
	OnTreeTxEvent(ctx context.Context, event client.TreeTxEvent) error
	OnTreeSignatureEvent(ctx context.Context, event client.TreeSignatureEvent) error
	OnTreeSigningStarted(
		ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
	) (bool, error)
	OnTreeNoncesAggregated(
		ctx context.Context,
		event client.TreeNoncesAggregatedEvent,
	) (signed bool, err error)
	OnTreeNonces(ctx context.Context, event client.TreeNoncesEvent) (signed bool, err error)
	OnBatchFinalization(
		ctx context.Context,
		event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
	) error
}

type BatchSessionOption func(*options)

func WithSkipVtxoTreeSigning() BatchSessionOption {
	return func(o *options) {
		o.signVtxoTree = false
	}
}

func WithReplay(ch chan<- any) BatchSessionOption {
	return func(o *options) {
		o.replayEventsCh = ch
	}
}

func WithCancel(cancelCh <-chan struct{}) BatchSessionOption {
	return func(o *options) {
		o.cancelCh = cancelCh
	}
}

func JoinBatchSession(
	ctx context.Context, eventsCh <-chan client.BatchEventChannel,
	eventsHandler BatchEventsHandler, opts ...BatchSessionOption,
) (string, error) {
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

	for {
		select {
		case <-options.cancelCh:
			return "", fmt.Errorf("canceled")
		case <-ctx.Done():
			return "", fmt.Errorf("context done %s", ctx.Err())
		case notify, ok := <-eventsCh:
			if !ok {
				return "", fmt.Errorf("event stream closed")
			}
			if notify.Err != nil {
				return "", notify.Err
			}

			if options.replayEventsCh != nil {
				go func() {
					select {
					case options.replayEventsCh <- notify.Event:
					default:
					}
				}()
			}

			switch event := notify.Event; event.(type) {
			case client.BatchStartedEvent:
				e := event.(client.BatchStartedEvent)
				skip, err := eventsHandler.OnBatchStarted(ctx, e)
				if err != nil {
					return "", err
				}
				if !skip {
					step++

					// if we don't want to sign the vtxo tree, we can skip the tree signing phase
					if !options.signVtxoTree {
						step = treeNoncesAggregated
					}
					continue
				}
			case client.BatchFinalizedEvent:
				if step != batchFinalization {
					continue
				}
				event := event.(client.BatchFinalizedEvent)
				if err := eventsHandler.OnBatchFinalized(ctx, event); err != nil {
					return "", err
				}
				return event.Txid, nil
			// the batch session failed, return error only if we joined.
			case client.BatchFailedEvent:
				e := event.(client.BatchFailedEvent)
				if err := eventsHandler.OnBatchFailed(ctx, e); err != nil {
					return "", err
				}
				continue
			// we received a tree tx event msg, let's update the vtxo/connector tree.
			case client.TreeTxEvent:
				if step != batchStarted && step != treeNoncesAggregated {
					continue
				}

				treeTxEvent := event.(client.TreeTxEvent)

				if err := eventsHandler.OnTreeTxEvent(ctx, treeTxEvent); err != nil {
					return "", err
				}

				if treeTxEvent.BatchIndex == 0 {
					flatVtxoTree = append(flatVtxoTree, treeTxEvent.Node)
				} else {
					flatConnectorTree = append(flatConnectorTree, treeTxEvent.Node)
				}

				continue
			case client.TreeSignatureEvent:
				if step != treeNoncesAggregated {
					continue
				}
				if vtxoTree == nil {
					return "", fmt.Errorf("vtxo tree not initialized")
				}

				event := event.(client.TreeSignatureEvent)
				if err := eventsHandler.OnTreeSignatureEvent(ctx, event); err != nil {
					return "", err
				}

				if err := addSignatureToTxTree(event, vtxoTree); err != nil {
					return "", err
				}
				continue
			// the musig2 session started, let's send our nonces.
			case client.TreeSigningStartedEvent:
				if step != batchStarted {
					continue
				}

				var err error
				vtxoTree, err = tree.NewTxTree(flatVtxoTree)
				if err != nil {
					return "", fmt.Errorf("failed to create branch of vtxo tree: %s", err)
				}

				event := event.(client.TreeSigningStartedEvent)
				skip, err := eventsHandler.OnTreeSigningStarted(ctx, event, vtxoTree)
				if err != nil {
					return "", err
				}

				if !skip {
					step++
				}
				continue
			// we received the aggregated nonces, let's send our signatures.
			case client.TreeNoncesAggregatedEvent:
				if step != treeSigningStarted {
					continue
				}

				event := event.(client.TreeNoncesAggregatedEvent)
				signed, err := eventsHandler.OnTreeNoncesAggregated(ctx, event)
				if err != nil {
					return "", err
				}

				if signed {
					step++
				}
				continue
			// we received the fully signed vtxo and connector trees, let's send our signed forfeit
			// txs and optionally signed boarding utxos included in the commitment tx.
			case client.TreeNoncesEvent:
				if step != treeSigningStarted {
					continue
				}

				event := event.(client.TreeNoncesEvent)
				signed, err := eventsHandler.OnTreeNonces(ctx, event)
				if err != nil {
					return "", err
				}
				if signed {
					step++
				}
				continue
			case client.BatchFinalizationEvent:
				if step != treeNoncesAggregated {
					continue
				}

				if options.signVtxoTree && vtxoTree == nil {
					return "", fmt.Errorf("vtxo tree not initialized")
				}

				if len(flatConnectorTree) > 0 {
					var err error
					connectorTree, err = tree.NewTxTree(flatConnectorTree)
					if err != nil {
						return "", fmt.Errorf("failed to create branch of connector tree: %s", err)
					}
				}

				event := event.(client.BatchFinalizationEvent)
				if err := eventsHandler.OnBatchFinalization(ctx, event, vtxoTree, connectorTree); err != nil {
					return "", err
				}

				log.Debug("done.")
				log.Debug("waiting for batch finalization...")
				step++
				continue
			}
		}
	}
}

func addSignatureToTxTree(
	event client.TreeSignatureEvent, txTree *tree.TxTree,
) error {
	if event.BatchIndex != 0 {
		return fmt.Errorf("batch index %d is not 0", event.BatchIndex)
	}

	decodedSig, err := hex.DecodeString(event.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %s", err)
	}

	sig, err := schnorr.ParseSignature(decodedSig)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %s", err)
	}

	return txTree.Apply(func(g *tree.TxTree) (bool, error) {
		if g.Root.UnsignedTx.TxID() != event.Txid {
			return true, nil
		}

		g.Root.Inputs[0].TaprootKeySpendSig = sig.Serialize()
		return false, nil
	})
}

type options struct {
	signVtxoTree   bool            // default: true
	replayEventsCh chan<- any      // default: nil
	cancelCh       <-chan struct{} // default: nil
}

func newOptions() *options {
	return &options{
		signVtxoTree:   true,
		replayEventsCh: nil,
		cancelCh:       nil,
	}
}

type defaultBatchEventsHandler struct {
	*arkClient

	intentId       string
	vtxos          []client.TapscriptsVtxo
	boardingUtxos  []types.Utxo
	receivers      []types.Receiver
	signerSessions []tree.SignerSession

	batchSessionId string
	batchExpiry    arklib.RelativeLocktime
	// internal count to handle TreeNoncesEvent
	countSigningDone int
}

func newBatchEventsHandler(
	arkClient *arkClient,
	intentId string,
	vtxos []client.TapscriptsVtxo,
	boardingUtxos []types.Utxo,
	receivers []types.Receiver,
	signerSessions []tree.SignerSession,
) *defaultBatchEventsHandler {
	vtxosToSign := make([]client.TapscriptsVtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		// exclude recoverable vtxos as they don't need any signing step
		if vtxo.IsRecoverable() {
			continue
		}
		vtxosToSign = append(vtxosToSign, vtxo)
	}

	return &defaultBatchEventsHandler{
		arkClient:        arkClient,
		intentId:         intentId,
		vtxos:            vtxosToSign,
		boardingUtxos:    boardingUtxos,
		receivers:        receivers,
		signerSessions:   signerSessions,
		batchSessionId:   "",
		countSigningDone: 0,
	}
}

func (h *defaultBatchEventsHandler) OnBatchStarted(
	ctx context.Context, event client.BatchStartedEvent,
) (bool, error) {
	buf := sha256.Sum256([]byte(h.intentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, hash := range event.HashedIntentIds {
		if hash == hashedIntentId {
			if err := h.client.ConfirmRegistration(ctx, h.intentId); err != nil {
				return false, err
			}
			h.batchSessionId = event.Id
			h.batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
			return false, nil
		}
	}
	log.Debug("intent id not found in batch proposal, waiting for next one...")
	return true, nil
}

func (h *defaultBatchEventsHandler) OnBatchFinalized(
	ctx context.Context, event client.BatchFinalizedEvent,
) error {
	if event.Id == h.batchSessionId {
		log.Debugf("batch completed in commitment tx %s", event.Txid)
	}
	return nil
}

func (h *defaultBatchEventsHandler) OnBatchFailed(
	ctx context.Context, event client.BatchFailedEvent,
) error {
	return fmt.Errorf("batch failed: %s", event.Reason)
}

func (h *defaultBatchEventsHandler) OnTreeTxEvent(
	ctx context.Context, event client.TreeTxEvent,
) error {
	return nil
}

func (h *defaultBatchEventsHandler) OnTreeSignatureEvent(
	ctx context.Context, event client.TreeSignatureEvent,
) error {
	return nil
}

func (h *defaultBatchEventsHandler) OnTreeSigningStarted(
	ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	foundPubkeys := make([]string, 0, len(h.signerSessions))
	for _, session := range h.signerSessions {
		myPubkey := session.GetPublicKey()
		if slices.Contains(event.CosignersPubkeys, myPubkey) {
			foundPubkeys = append(foundPubkeys, myPubkey)
		}
	}

	if len(foundPubkeys) <= 0 {
		log.Debug("no signer found in cosigner list, waiting for next one...")
		return true, nil
	}

	if len(foundPubkeys) != len(h.signerSessions) {
		return false, fmt.Errorf("not all signers found in cosigner list")
	}

	sweepClosure := script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{h.ForfeitPubKey}},
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

	errChan := make(chan error, len(h.signerSessions))
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(len(h.signerSessions))

	for _, session := range h.signerSessions {
		go func(session tree.SignerSession) {
			defer waitGroup.Done()
			if err := generateAndSendNonces(session); err != nil {
				errChan <- err
			}
		}(session)
	}

	waitGroup.Wait()

	close(errChan)

	for err := range errChan {
		if err != nil {
			return false, err
		}
	}

	return false, nil
}

func (h *defaultBatchEventsHandler) OnTreeNonces(
	ctx context.Context, event client.TreeNoncesEvent,
) (bool, error) {
	log.Debugf("tree nonces event received for tx %s", event.Txid)
	if len(h.signerSessions) <= 0 {
		return false, fmt.Errorf("tree signer session not set")
	}

	handler := func(session tree.SignerSession) (bool, error) {
		hasAllNonces, err := session.AggregateNonces(event.Txid, event.Nonces)
		if err != nil {
			return false, err
		}

		if !hasAllNonces {
			return false, nil
		}

		log.Debugf("all nonces aggregated, signing...")
		sigs, err := session.Sign()
		if err != nil {
			return false, err
		}

		if err := h.client.SubmitTreeSignatures(
			ctx,
			event.Id,
			session.GetPublicKey(),
			sigs,
		); err != nil {
			return false, err
		}

		return true, nil
	}

	type res struct {
		signed bool
		err    error
	}

	resChan := make(chan res, len(h.signerSessions))
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(len(h.signerSessions))

	for _, session := range h.signerSessions {
		go func(session tree.SignerSession) {
			defer waitGroup.Done()
			signed, err := handler(session)
			resChan <- res{signed, err}
		}(session)
	}

	waitGroup.Wait()
	close(resChan)

	for res := range resChan {
		if res.err != nil {
			return false, res.err
		}
		if res.signed {
			h.countSigningDone++
			if h.countSigningDone == len(h.signerSessions) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (h *defaultBatchEventsHandler) OnTreeNoncesAggregated(
	ctx context.Context, event client.TreeNoncesAggregatedEvent,
) (bool, error) {
	// ignore TreeNoncesAggregatedEvent as we handle it in OnTreeNoncesEvent
	return false, nil
}

func (h *defaultBatchEventsHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) error {
	log.Debug("vtxo and connector trees fully signed, sending forfeit transactions...")
	if err := h.validateVtxoTree(event, vtxoTree, connectorTree); err != nil {
		return fmt.Errorf("failed to verify vtxo tree: %s", err)
	}

	var forfeits []string
	var signedCommitmentTx string

	vtxos := h.vtxosToForfeit()

	// if we spend vtxos, we must create and sign forfeits.
	if len(vtxos) > 0 && connectorTree != nil {
		signedForfeits, err := h.createAndSignForfeits(
			ctx, vtxos, connectorTree.Leaves(),
		)
		if err != nil {
			return err
		}

		forfeits = signedForfeits
	}

	// if we spend boarding inputs, we must sign the commitment transaction.
	if len(h.boardingUtxos) > 0 {
		commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
		if err != nil {
			return err
		}

		for _, boardingUtxo := range h.boardingUtxos {
			boardingVtxoScript, err := script.ParseVtxoScript(boardingUtxo.Tapscripts)
			if err != nil {
				return err
			}

			forfeitClosures := boardingVtxoScript.ForfeitClosures()
			if len(forfeitClosures) <= 0 {
				return fmt.Errorf("no forfeit closures found")
			}

			forfeitClosure := forfeitClosures[0]

			forfeitScript, err := forfeitClosure.Script()
			if err != nil {
				return err
			}

			_, taprootTree, err := boardingVtxoScript.TapTree()
			if err != nil {
				return err
			}

			forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
			forfeitProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
			if err != nil {
				return fmt.Errorf(
					"failed to get taproot merkle proof for boarding utxo: %s", err,
				)
			}

			tapscript := &psbt.TaprootTapLeafScript{
				ControlBlock: forfeitProof.ControlBlock,
				Script:       forfeitProof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			}

			for i := range commitmentPtx.Inputs {
				prevout := commitmentPtx.UnsignedTx.TxIn[i].PreviousOutPoint

				if boardingUtxo.Txid == prevout.Hash.String() &&
					boardingUtxo.VOut == prevout.Index {
					commitmentPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
						tapscript,
					}
					break
				}
			}
		}

		b64, err := commitmentPtx.B64Encode()
		if err != nil {
			return err
		}

		signedCommitmentTx, err = h.wallet.SignTransaction(ctx, h.explorer, b64)
		if err != nil {
			return err
		}
	}

	if len(forfeits) > 0 || len(signedCommitmentTx) > 0 {
		if err := h.client.SubmitSignedForfeitTxs(
			ctx, forfeits, signedCommitmentTx,
		); err != nil {
			return err
		}
	}

	return nil
}

func (h *defaultBatchEventsHandler) vtxosToForfeit() []client.TapscriptsVtxo {
	withoutRecoverable := make([]client.TapscriptsVtxo, 0, len(h.vtxos))
	for _, vtxo := range h.vtxos {
		if !vtxo.IsRecoverable() {
			withoutRecoverable = append(withoutRecoverable, vtxo)
		}
	}

	return withoutRecoverable
}

func (h *defaultBatchEventsHandler) validateVtxoTree(
	event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) error {
	commitmentTx := event.Tx
	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		return err
	}

	// validate the vtxo tree is well formed
	if !utils.IsOnchainOnly(h.receivers) {
		if err := tree.ValidateVtxoTree(
			vtxoTree, commitmentPtx, h.ForfeitPubKey, h.batchExpiry,
		); err != nil {
			return err
		}

		rootParentTxid := vtxoTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
		rootParentVout := vtxoTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Index

		if rootParentTxid != commitmentPtx.UnsignedTx.TxID() {
			return fmt.Errorf(
				"root's parent txid is not the same as the commitment txid: %s != %s",
				rootParentTxid,
				commitmentPtx.UnsignedTx.TxID(),
			)
		}

		if rootParentVout != 0 {
			return fmt.Errorf(
				"root's parent vout is not the same as the shared output index: %d != %d",
				rootParentVout,
				0,
			)
		}
	}

	// validate it contains our outputs
	if err := validateReceivers(h.Network, commitmentPtx, h.receivers, vtxoTree); err != nil {
		return err
	}

	vtxos := h.vtxosToForfeit()

	if len(vtxos) > 0 {
		if connectorTree != nil {
			if err := connectorTree.Validate(); err != nil {
				return err
			}
		}

		if connectorTree != nil {
			connectorsLeaves := connectorTree.Leaves()
			if len(connectorsLeaves) != len(vtxos) {
				return fmt.Errorf(
					"unexpected num of connectors received: expected %d, got %d",
					len(vtxos),
					len(connectorsLeaves),
				)
			}
		}
	}

	return nil
}

func (h *defaultBatchEventsHandler) createAndSignForfeits(
	ctx context.Context, vtxosToSign []client.TapscriptsVtxo, connectorsLeaves []*psbt.Packet,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(h.ForfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := txscript.PayToAddrScript(parsedForfeitAddr)
	if err != nil {
		return nil, err
	}

	signedForfeitTxs := make([]string, 0, len(vtxosToSign))
	for i, vtxo := range vtxosToSign {
		connectorTx := connectorsLeaves[i]

		var connector *wire.TxOut
		var connectorOutpoint *wire.OutPoint
		for outIndex, output := range connectorTx.UnsignedTx.TxOut {
			if bytes.Equal(txutils.ANCHOR_PKSCRIPT, output.PkScript) {
				continue
			}

			connector = output
			connectorOutpoint = &wire.OutPoint{
				Hash:  connectorTx.UnsignedTx.TxHash(),
				Index: uint32(outIndex),
			}
			break
		}

		if connector == nil {
			return nil, fmt.Errorf("connector not found for vtxo %s", vtxo.Outpoint.String())
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		vtxoOutputScript, err := script.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, err
		}

		vtxoInput := &wire.OutPoint{
			Hash:  *vtxoTxHash,
			Index: vtxo.VOut,
		}

		forfeitClosures := vtxoScript.ForfeitClosures()
		if len(forfeitClosures) <= 0 {
			return nil, fmt.Errorf("no forfeit closures found")
		}

		forfeitClosure := forfeitClosures[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		leafProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, err
		}

		tapscript := psbt.TaprootTapLeafScript{
			ControlBlock: leafProof.ControlBlock,
			Script:       leafProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		vtxoLocktime := arklib.AbsoluteLocktime(0)
		if cltv, ok := forfeitClosure.(*script.CLTVMultisigClosure); ok {
			vtxoLocktime = cltv.Locktime
		}

		vtxoPrevout := &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoOutputScript,
		}

		vtxoSequence := wire.MaxTxInSequenceNum
		if vtxoLocktime != 0 {
			vtxoSequence = wire.MaxTxInSequenceNum - 1
		}

		forfeitTx, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{vtxoInput, connectorOutpoint},
			[]uint32{vtxoSequence, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{vtxoPrevout, connector},
			forfeitPkScript,
			uint32(vtxoLocktime),
		)
		if err != nil {
			return nil, err
		}

		forfeitTx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&tapscript}

		b64, err := forfeitTx.B64Encode()
		if err != nil {
			return nil, err
		}

		signedForfeitTx, err := h.wallet.SignTransaction(ctx, h.explorer, b64)
		if err != nil {
			return nil, err
		}

		signedForfeitTxs = append(signedForfeitTxs, signedForfeitTx)
	}

	return signedForfeitTxs, nil
}
