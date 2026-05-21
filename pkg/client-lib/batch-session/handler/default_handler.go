package batchsessionhandler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

type Args struct {
	Client     clientlib.Client
	ServerInfo clientlib.Info
	SignTx     clientlib.SignFn

	IntentId       string
	Vtxos          []clientlib.Vtxo
	BoardingUtxos  []clientlib.Utxo
	Receivers      []clientlib.Receiver
	SignerSessions []tree.SignerSession

	vtxosToSign    []clientlib.Vtxo
	forfeitPubkey  *btcec.PublicKey
	forfeitAddress string
	network        arklib.Network
}

func (a *Args) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx function")
	}
	if len(a.ServerInfo.Network) <= 0 || len(a.ServerInfo.ForfeitPubKey) <= 0 ||
		len(a.ServerInfo.ForfeitAddress) <= 0 {
		return fmt.Errorf("missing server info")
	}
	if len(a.IntentId) <= 0 {
		return fmt.Errorf("missing intent id")
	}
	if len(a.Receivers) <= 0 {
		return fmt.Errorf("missing receivers")
	}

	buf, err := hex.DecodeString(a.ServerInfo.ForfeitPubKey)
	if err != nil {
		return fmt.Errorf(
			"expected hex format for forfeit pubkey, got %s", a.ServerInfo.ForfeitPubKey,
		)
	}
	pubkey, err := btcec.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse forfeit pubkey: %w", err)
	}

	a.forfeitPubkey = pubkey

	vtxosToSign := make([]clientlib.Vtxo, 0, len(a.Vtxos))
	for _, vtxo := range a.Vtxos {
		// exclude recoverable vtxos as they don't need any signing step
		if vtxo.IsRecoverable() {
			continue
		}
		vtxosToSign = append(vtxosToSign, vtxo)
	}
	a.vtxosToSign = vtxosToSign
	a.network = clientlib.NetworkFromString(a.ServerInfo.Network)

	return nil
}

type defaultHandler struct {
	Args

	batchSessionId string
	batchExpiry    arklib.RelativeLocktime
	// internal count to handle TreeNoncesEvent
	countSigningDone int
}

func NewDefaultHandler(args Args) (Handler, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}
	return &defaultHandler{Args: args}, nil
}

func (h *defaultHandler) OnStreamStarted(
	ctx context.Context, event clientlib.StreamStartedEvent,
) error {
	return nil
}

func (h *defaultHandler) OnBatchStarted(
	ctx context.Context, event clientlib.BatchStartedEvent,
) (bool, time.Duration, error) {
	buf := sha256.Sum256([]byte(h.IntentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, hash := range event.HashedIntentIds {
		if hash == hashedIntentId {
			if err := h.Client.ConfirmRegistration(ctx, h.IntentId); err != nil {
				return false, -1, err
			}
			h.batchSessionId = event.Id
			h.batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
			expiry := time.Duration(event.BatchExpiry) * time.Second
			if h.batchExpiry.Type == arklib.LocktimeTypeBlock {
				expiry = time.Duration(event.BatchExpiry*arklib.SECONDS_PER_BLOCK) * time.Second
			}
			return false, expiry, nil
		}
	}
	log.Debug("intent id not found in batch proposal, waiting for next one...")
	return true, -1, nil
}

func (h *defaultHandler) OnBatchFinalized(
	ctx context.Context, event clientlib.BatchFinalizedEvent,
) error {
	if event.Id == h.batchSessionId {
		log.Debugf("batch completed in commitment tx %s", event.Txid)
	}
	return nil
}

func (h *defaultHandler) OnBatchFailed(
	ctx context.Context, event clientlib.BatchFailedEvent,
) error {
	return fmt.Errorf("batch failed: %s", event.Reason)
}

func (h *defaultHandler) OnTreeTxEvent(
	ctx context.Context, event clientlib.TreeTxEvent,
) error {
	return nil
}

func (h *defaultHandler) OnTreeSignatureEvent(
	ctx context.Context, event clientlib.TreeSignatureEvent,
) error {
	return nil
}

func (h *defaultHandler) OnTreeSigningStarted(
	ctx context.Context, event clientlib.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	foundPubkeys := make([]string, 0, len(h.SignerSessions))
	for _, session := range h.SignerSessions {
		myPubkey := session.GetPublicKey()
		if slices.Contains(event.CosignersPubkeys, myPubkey) {
			foundPubkeys = append(foundPubkeys, myPubkey)
		}
	}

	if len(foundPubkeys) <= 0 {
		log.Debug("no signer found in cosigner list, waiting for next one...")
		return true, nil
	}

	if len(foundPubkeys) != len(h.SignerSessions) {
		return false, fmt.Errorf("not all signers found in cosigner list")
	}

	sweepClosure := script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{h.forfeitPubkey}},
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

		return h.Client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces)
	}

	errChan := make(chan error, len(h.SignerSessions))
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(len(h.SignerSessions))

	for _, session := range h.SignerSessions {
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

func (h *defaultHandler) OnTreeNonces(
	ctx context.Context, event clientlib.TreeNoncesEvent,
) (bool, error) {
	log.Debugf("tree nonces event received for tx %s", event.Txid)
	if len(h.SignerSessions) <= 0 {
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

		if err := h.Client.SubmitTreeSignatures(
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

	resChan := make(chan res, len(h.SignerSessions))
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(len(h.SignerSessions))

	for _, session := range h.SignerSessions {
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
			if h.countSigningDone == len(h.SignerSessions) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (h *defaultHandler) OnTreeNoncesAggregated(
	ctx context.Context, event clientlib.TreeNoncesAggregatedEvent,
) (bool, error) {
	// ignore TreeNoncesAggregatedEvent as we handle it in OnTreeNoncesEvent
	return false, nil
}

func (h *defaultHandler) OnBatchFinalization(
	ctx context.Context, event clientlib.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) ([]string, error) {
	log.Debug("vtxo and connector trees fully signed, sending forfeit transactions...")
	if err := h.validateVtxoTree(event, vtxoTree, connectorTree); err != nil {
		return nil, fmt.Errorf("failed to verify vtxo tree: %s", err)
	}

	var forfeitTxs []string
	var signedCommitmentTx string

	vtxos := h.vtxosToForfeit()

	// If vtxos are refreshed, we must create and sign forfeit txs.
	if len(vtxos) > 0 && connectorTree != nil {
		signedForfeitTxs, err := h.createAndSignForfeits(
			ctx, vtxos, connectorTree.Leaves(),
		)
		if err != nil {
			return nil, err
		}

		forfeitTxs = signedForfeitTxs
	}

	// If boarding utxos are settled, we must sign the commitment transaction.
	if len(h.BoardingUtxos) > 0 {
		commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
		if err != nil {
			return nil, err
		}

		for _, boardingUtxo := range h.BoardingUtxos {
			boardingVtxoScript, err := script.ParseVtxoScript(boardingUtxo.Tapscripts)
			if err != nil {
				return nil, err
			}

			forfeitClosures := boardingVtxoScript.ForfeitClosures()
			if len(forfeitClosures) <= 0 {
				return nil, fmt.Errorf("no forfeit closures found")
			}

			forfeitClosure := forfeitClosures[0]

			forfeitScript, err := forfeitClosure.Script()
			if err != nil {
				return nil, err
			}

			_, taprootTree, err := boardingVtxoScript.TapTree()
			if err != nil {
				return nil, err
			}

			forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
			forfeitProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
			if err != nil {
				return nil, fmt.Errorf(
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
			return nil, err
		}

		signedCommitmentTx, err = h.SignTx(ctx, b64)
		if err != nil {
			return nil, err
		}
	}

	if len(forfeitTxs) > 0 || len(signedCommitmentTx) > 0 {
		if err := h.Client.SubmitSignedForfeitTxs(
			ctx, forfeitTxs, signedCommitmentTx,
		); err != nil {
			return nil, err
		}
	}

	return forfeitTxs, nil
}

func (h *defaultHandler) vtxosToForfeit() []clientlib.Vtxo {
	withoutRecoverable := make([]clientlib.Vtxo, 0, len(h.Vtxos))
	for _, vtxo := range h.Vtxos {
		if !vtxo.IsRecoverable() {
			withoutRecoverable = append(withoutRecoverable, vtxo)
		}
	}

	return withoutRecoverable
}

func (h *defaultHandler) validateVtxoTree(
	event clientlib.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) error {
	commitmentTx := event.Tx
	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		return err
	}

	// validate the vtxo tree is well formed
	if !utils.IsOnchainOnly(h.Receivers) {
		if err := tree.ValidateVtxoTree(
			vtxoTree, commitmentPtx, h.forfeitPubkey, h.batchExpiry,
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
	if err := validateReceivers(h.network, commitmentPtx, h.Receivers, vtxoTree); err != nil {
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

func (h *defaultHandler) createAndSignForfeits(
	ctx context.Context, vtxosToSign []clientlib.Vtxo, connectorsLeaves []*psbt.Packet,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(h.ServerInfo.ForfeitAddress, nil)
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

		signedForfeitTx, err := h.SignTx(ctx, b64)
		if err != nil {
			return nil, err
		}

		signedForfeitTxs = append(signedForfeitTxs, signedForfeitTx)
	}

	return signedForfeitTxs, nil
}
