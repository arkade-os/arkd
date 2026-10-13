package application

import (
	"bytes"
	"context"
	"encoding/hex"
	terrors "errors"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
)

// Includes foreign inputs, since their funding transactions must also be checked.
const maxCosignOnchainTxInputs = 64

func (s *service) CosignOnchainTx(
	ctx context.Context, tx string,
) (vTxid string, vErr errors.Error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", errors.INVALID_ARK_PSBT.New("failed to parse tx: %w", err).
			WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	inputsToCosign, inputIndexes, vErr := s.validateOnchainTx(ctx, tx, ptx)
	if vErr != nil {
		return "", vErr
	}

	outpointsToCosign := make([]domain.Outpoint, 0, len(inputsToCosign))
	for _, in := range inputsToCosign {
		outpointsToCosign = append(outpointsToCosign, in.Outpoint)
	}

	cache := s.cache.CosignedUtxos()
	db := s.repoManager.Events()

	// Make sure to do the checks over cache and db while being in sync with RegisterIntent to
	// prevent one to try cosigning a boarding utxo and join a batch at the same time.
	if err := s.lockUtxos(ctx, tx, outpointsToCosign); err != nil {
		return "", err
	}
	defer func() {
		if vErr == nil {
			return
		}

		if err := cache.RemoveUtxos(s.ctx, outpointsToCosign); err != nil {
			log.WithError(err).WithField("utxos", outpointsToCosign).Error(
				"failed to remove cosigned utxos from cache, please remove them manually",
			)
		}
	}()

	// Cosign the tx
	signedTx, err := s.signer.SignTransactionTapscript(ctx, tx, inputIndexes)
	if err != nil {
		log.WithError(err).Error("failed to cosign tx")
		return "", errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}

	// Check if broadcastable.
	rawTx, err := s.builder.FinalizeAndExtract(signedTx)
	if err != nil {
		log.WithError(err).Error("failed to finalize and extract tx")
		return "", errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}

	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(hex.NewDecoder(strings.NewReader(rawTx))); err != nil {
		return "", errors.INTERNAL_ERROR.New("failed to deserialize finalized tx: %w", err).
			WithMetadata(map[string]any{
				"tx": rawTx,
			})
	}
	txid := msgTx.TxID()

	onchainTx := domain.NewOnchainTx()
	event, err := onchainTx.Broadcast(txid, signedTx, outpointsToCosign)
	if err != nil {
		log.WithError(err).Error("failed to raise onchain tx broadcasted domain event")
		return "", errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}

	if _, err := s.wallet.BroadcastTransaction(ctx, rawTx); err != nil {
		log.WithError(err).Error("failed to broadcast tx")
		return "", errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}

	if err := db.Save(s.ctx, domain.OnchainTxTopic, txid, []domain.Event{event}); err != nil {
		log.WithError(err).Errorf("failed to save onchain tx event: %+v", *onchainTx)
		return "", errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}

	log.Debugf("cosigned %d utxos and broadcasted tx %s", len(outpointsToCosign), txid)

	// Spawn a go routing that waits for the confirmation to then update the db with the
	// confirmation info. If the service is stopped
	go s.waitForSpendConfirmationAndUpdateUtxos(onchainTx)
	return txid, nil
}

// unlockUtxos removes the given cosigned utxos of a broadcasted onchain tx from
// the cache. It runs once the tx is projected, so the utxos stay in cache until the db records
// them and prevent a concurrent request to not find them neither in cache nor in db.
func (s *service) unlockUtxos(onchainTx domain.OnchainTx) {
	// Nothing to do if the event is not onchain tx broadcasted.
	if !onchainTx.IsBroadcasted() {
		return
	}

	outpoints := make([]domain.Outpoint, 0, len(onchainTx.SignedInputs))
	for in := range onchainTx.SignedInputs {
		outpoint := &domain.Outpoint{}
		if err := outpoint.FromString(in); err != nil {
			log.WithError(err).Errorf(
				"failed to decode outpoint %s for onchain tx %s", in, onchainTx.Txid,
			)
			return
		}
		outpoints = append(outpoints, *outpoint)
	}
	if err := s.cache.CosignedUtxos().RemoveUtxos(context.Background(), outpoints); err != nil {
		log.WithError(err).Warnf(
			"failed to remove cosigned utxos from cache for onchain tx %s", onchainTx.Txid,
		)
	}
}

// lockUtxos adds the utxos to the cache and verifies none of them is already cosigned, tracked
// offchain, a checkpoint output or registered in the intents queue.
// On error the utxos are released, the caller must release them otherwise.
func (s *service) lockUtxos(
	ctx context.Context, tx string, inputsToCosign []domain.Outpoint,
) (vErr errors.Error) {
	s.cosignMu.Lock()
	defer s.cosignMu.Unlock()

	cache := s.cache.CosignedUtxos()
	db := s.repoManager.CosignedUtxos()

	// Add utxos to the cache until the request is completed.
	// This is atomic, for 2 concurrent reqs, one of them will get rejected here because the other
	// got the precedence and had its inputs added to the cache.
	if err := cache.AddUtxos(ctx, inputsToCosign); err != nil {
		if terrors.Is(err, ports.ErrUtxosAlreadyExist) {
			return errors.INVALID_ARK_PSBT.New(
				"one or more inputs already co-signed: %s",
				strings.Join(outpointsToString(inputsToCosign), ", "),
			)
		}
		log.WithError(err).Error("failed to add cosigned utxos to cache")
		return errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}
	// Release the utxos if any of the checks below fails.
	defer func() {
		if vErr == nil {
			return
		}
		if err := cache.RemoveUtxos(s.ctx, inputsToCosign); err != nil {
			log.WithError(err).WithField("utxos", inputsToCosign).Error(
				"failed to remove cosigned utxos from cache, please remove them manually",
			)
		}
	}()

	// Check against db to prevent signing twice already signed utxos.
	alreadySigned, err := db.GetUtxos(ctx, inputsToCosign)
	if err != nil {
		log.WithError(err).Error("failed to check if inputs are already signed in db")
		return errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}
	if len(alreadySigned) > 0 {
		return errors.INVALID_ARK_PSBT.New(
			"inputs already signed: %s", strings.Join(outpointsToString(inputsToCosign), ", "),
		).WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	// SubmitOffchainTx reads its vtxos and adds its tx to the offchain cache while holding this
	// lock: either its tx is found in the cache below, or it reads the vtxo as unrolled and
	// rejects the spend.
	s.offchainTxMu.Lock()
	defer s.offchainTxMu.Unlock()

	// The cache goes first: an offchain tx leaves it only once its spent vtxos are marked spent
	// in the db, so a spend is always visible in one of the two.
	spentOffchain, err := s.cache.OffchainTxs().IncludesAny(ctx, inputsToCosign)
	if err != nil {
		log.WithError(err).Error("failed to check if inputs are spent by offchain txs")
		return errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}
	if len(spentOffchain) > 0 {
		return errors.INVALID_ARK_PSBT.New(
			"inputs already spent offchain: %s",
			strings.Join(outpointsToString(spentOffchain), ", "),
		).WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	// Ensure no inputs are already registered in intents queue - they might be boarding utxos.
	// Check cached claims before the DB: settlement marks VTXOs spent before releasing their claims.
	intents, err := s.cache.Intents().IncludesAny(ctx, inputsToCosign)
	if err != nil {
		log.WithError(err).Error(
			"failed to check if inputs are already registered in intents queue",
		)
		return errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}
	if len(intents) > 0 {
		return errors.INVALID_ARK_PSBT.New(
			"inputs already registered in intents queue: %s",
			strings.Join(outpointsToString(intents), ", "),
		).WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	// Reject signing inputs tracked as vtxos, unless unrolled and still unspent: a vtxo spent
	// offchain is in the middle of a chain being unrolled and gets claimed by its checkpoint or
	// forfeit tx, an expired one gets swept by us.
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, inputsToCosign)
	if err != nil {
		log.WithError(err).Error("failed to check if inputs are already spent in db")
		return errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}
	for _, v := range vtxos {
		if !v.Unrolled {
			return errors.INVALID_ARK_PSBT.New(
				"input %s is tracked offchain", v.Outpoint,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		if v.Spent {
			return errors.INVALID_ARK_PSBT.New(
				"input %s is an unrolled vtxo already spent offchain", v.Outpoint,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		if v.Swept || v.IsExpired() {
			return errors.INVALID_ARK_PSBT.New(
				"input %s is an unrolled vtxo already expired", v.Outpoint,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
	}

	// Reject signing inputs that are checkpoint outputs.
	txids := getTxidsFromOutpoints(inputsToCosign)
	checkpointTxs, err := s.repoManager.OffchainTxs().GetCheckpointTxs(ctx, txids)
	if err != nil {
		log.WithError(err).Error("failed to check if inputs are checkpoint outputs")
		return errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}
	if len(checkpointTxs) > 0 {
		return errors.INVALID_ARK_PSBT.New(
			"one or more inputs are checkpoint outputs: %s",
			strings.Join(outpointsToString(inputsToCosign), ", "),
		).WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	return nil
}

func (s *service) validateOnchainTx(
	ctx context.Context, tx string, ptx *psbt.Packet,
) ([]domain.Utxo, []int, errors.Error) {
	if len(ptx.Inputs) > maxCosignOnchainTxInputs {
		return nil, nil, errors.INVALID_ARK_PSBT.New(
			"too many inputs: got %d, max %d", len(ptx.Inputs), maxCosignOnchainTxInputs,
		).WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	settings, err := s.cache.Settings().Get(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get settings")
		return nil, nil, errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}

	if err := blockchain.CheckTransactionSanity(btcutil.NewTx(ptx.UnsignedTx)); err != nil {
		return nil, nil, errors.INVALID_ARK_PSBT.Wrap(err).WithMetadata(errors.PsbtMetadata{
			Tx: tx,
		})
	}

	// Reject if tx is too heavy before inspecting its inputs or making any node calls.
	if weight := computeWeight(ptx.UnsignedTx); weight > settings.MaxTxWeight {
		return nil, nil, errors.TX_TOO_LARGE.New("tx is too heavy").
			WithMetadata(errors.TxTooLargeMetadata{
				Weight:    int(weight),
				MaxWeight: int(settings.MaxTxWeight),
			})
	}

	now := time.Now()
	spendingTxid := ptx.UnsignedTx.TxID()
	// Allow cosigning with any known signer pubkey, included those deprecated and passed the
	// cutoff date.
	signerPubkeys := []*btcec.PublicKey{settings.SignerPubkey}
	for _, signer := range settings.DeprecatedSignerPubkeys {
		signerPubkeys = append(signerPubkeys, signer.PubKey)
	}
	signers := make(map[string]struct{}, len(signerPubkeys))
	for _, signer := range signerPubkeys {
		signers[hex.EncodeToString(schnorr.SerializePubKey(signer))] = struct{}{}
	}

	// An unrolled vtxo is locked by a vtxo script, whose exit delay is validated against the
	// unilateral one rather than the boarding one.
	outpoints := make([]domain.Outpoint, 0, len(ptx.UnsignedTx.TxIn))
	for _, in := range ptx.UnsignedTx.TxIn {
		outpoints = append(outpoints, domain.Outpoint{
			Txid: in.PreviousOutPoint.Hash.String(), VOut: in.PreviousOutPoint.Index,
		})
	}
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, outpoints)
	if err != nil {
		log.WithError(err).Error("failed to get vtxos of inputs")
		return nil, nil, errors.INTERNAL_ERROR.New("something went wrong, please retry")
	}
	unrolledVtxos := make(map[domain.Outpoint]struct{}, len(vtxos))
	for _, v := range vtxos {
		if v.Unrolled {
			unrolledVtxos[v.Outpoint] = struct{}{}
		}
	}

	sumOfInputs := int64(0)
	txsToCheckConfirmed := make(map[string]struct{})
	exitDelaysToCheckExpired := make(map[int]inputExitDelay) // input index -> exit delay
	inputsToCosign := make([]domain.Utxo, 0, len(ptx.Inputs))
	inputIndexes := make([]int, 0, len(ptx.Inputs))
	for i, input := range ptx.Inputs {
		// Reject malformed inputs.
		if input.WitnessUtxo == nil {
			return nil, nil, errors.INVALID_ARK_PSBT.New("missing prevout for input %d", i).
				WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		// Reject unsigned inputs.
		if isUnsignedInput(input) {
			return nil, nil, errors.INVALID_ARK_PSBT.New("missing signatures for input %d", i).
				WithMetadata(errors.PsbtMetadata{Tx: tx})
		}

		// Check the claimed amounts locally; funding outputs are verified below before signing.
		prevout := input.WitnessUtxo
		if prevout.Value < 0 || prevout.Value > btcutil.MaxSatoshi-sumOfInputs {
			return nil, nil, errors.INVALID_ARK_PSBT.New("input amounts out of range").
				WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		sumOfInputs += prevout.Value

		// Skip non-taproot inputs.
		if len(input.TaprootScriptSpendSig) <= 0 {
			continue
		}

		fields, err := txutils.GetArkPsbtFields(ptx, i, txutils.VtxoTaprootTreeField)
		if err != nil {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"failed to decode taptree for input %d: %w", i, err,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		// Skip inputs that don't reveal the whole taproot tree.
		if len(fields) <= 0 {
			continue
		}

		taptree := fields[0]
		vtxoScript, err := script.ParseVtxoScript(taptree)
		if err != nil {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"failed to parse taptree for input %d: %w", i, err,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		// Skip taproot inputs that don't include any collaborative closure.
		if len(vtxoScript.ForfeitClosures()) == 0 {
			continue
		}

		// Reject inputs with invalid number of tapleaf scripts.
		if len(input.TaprootLeafScript) != 1 {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"expected exactly 1 tapleaf script for input %d, got %d",
				i, len(input.TaprootLeafScript),
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		leaf := input.TaprootLeafScript[0]

		// Reject inputs with taproot tree not matching prevout script.
		tapKey, _, err := vtxoScript.TapTree()
		if err != nil {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"failed to validate taproot tree for input %d: %w", i, err,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		expectedPkScript, err := script.P2TRScript(tapKey)
		if err != nil {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"failed to compute P2TR script for input %d: %w", i, err,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		if !bytes.Equal(input.WitnessUtxo.PkScript, expectedPkScript) {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"taptree of input %d doesn't match prevout script: got %x expected %x",
				i, expectedPkScript, input.WitnessUtxo.PkScript,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}

		// Check whether inputs require our signature.
		var leafKeys []*btcec.PublicKey
		for _, closure := range vtxoScript.ForfeitClosures() {
			closureScript, err := closure.Script()
			if err != nil || !bytes.Equal(closureScript, leaf.Script) {
				continue
			}
			switch c := closure.(type) {
			case *script.MultisigClosure:
				leafKeys = c.PubKeys
			case *script.CLTVMultisigClosure:
				leafKeys = c.PubKeys
			case *script.ConditionMultisigClosure:
				leafKeys = c.PubKeys
			}
			break
		}
		signerKeyFound := false
		for _, key := range leafKeys {
			if _, ok := signers[hex.EncodeToString(schnorr.SerializePubKey(key))]; !ok {
				continue
			}
			signerKeyFound = true
			break
		}
		// Skip inputs that don't require our signature.
		if !signerKeyFound {
			continue
		}

		// Reject inputs with duplicated pubkeys in the collaborative closure.
		seen := make(map[string]struct{})
		for _, key := range leafKeys {
			seen[hex.EncodeToString(schnorr.SerializePubKey(key))] = struct{}{}
		}
		if len(seen) < len(leafKeys) {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"spending leaf of input %d includes duplicate signer pubkeys", i,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}

		// Reject inputs that don't have at least 2 cosigners.
		if len(leafKeys) < 2 {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"spending leaf of input %d must include at least another signer", i,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}

		// Reject inputs that miss other signatures than just ours, we must be the last signer.
		if len(input.TaprootScriptSpendSig) != len(leafKeys)-1 {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"missing signatures for input %d: expected %d, got %d",
				i, len(leafKeys)-1, len(input.TaprootScriptSpendSig),
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		// Reject inputs that don't have sighash type ALL or DEFAULT, our signature must commit to
		// the whole tx.
		if err := script.CheckSigHashType(input.SighashType); err != nil {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"invalid sighash type for input %d: %w", i, err,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		// Reject inputs whose signatures don't belong to the other cosigners of the spending leaf,
		// or that are signed with invalid sighash type.
		leafHash := txscript.NewBaseTapLeaf(leaf.Script).TapHash()
		signedBy := make(map[string]struct{})
		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.LeafHash, leafHash[:]) {
				return nil, nil, errors.INVALID_ARK_PSBT.New(
					"input %d has a signature for a leaf other than the spending one", i,
				).WithMetadata(errors.PsbtMetadata{Tx: tx})
			}
			pubkey := hex.EncodeToString(sig.XOnlyPubKey)
			if _, ok := signers[pubkey]; ok {
				return nil, nil, errors.INVALID_ARK_PSBT.New(
					"input %d includes a signature that commits to signer pubkey %s", i, pubkey,
				).WithMetadata(errors.PsbtMetadata{Tx: tx})
			}
			if _, ok := seen[pubkey]; !ok {
				return nil, nil, errors.INVALID_ARK_PSBT.New(
					"input %d is signed by pubkey %s not included in the spending leaf", i, pubkey,
				).WithMetadata(errors.PsbtMetadata{Tx: tx})
			}
			if _, ok := signedBy[pubkey]; ok {
				return nil, nil, errors.INVALID_ARK_PSBT.New(
					"input %d includes more than one signature for pubkey %s", i, pubkey,
				).WithMetadata(errors.PsbtMetadata{Tx: tx})
			}
			signedBy[pubkey] = struct{}{}
			if sig.SigHash != input.SighashType {
				return nil, nil, errors.INVALID_ARK_PSBT.New(
					"input %d is signed with an unexpected sighash type: expected %#x, got %#x",
					i, input.SighashType, sig.SigHash,
				).WithMetadata(errors.PsbtMetadata{Tx: tx})
			}
		}

		// Reject inputs with a vtxo script that is not valid for any of our signer pubkeys, ie.
		// missing from any collaborative closure, exit delay too short or of the wrong type.
		minExitDelay := settings.BoardingExitDelay
		if _, ok := unrolledVtxos[outpoints[i]]; ok {
			minExitDelay = settings.UnilateralExitDelay
		}
		validScript := false
		for _, signer := range signerPubkeys {
			if err := vtxoScript.Validate(
				signer, minExitDelay, settings.AllowCSVBlockType(),
			); err == nil {
				validScript = true
				break
			}
		}
		if !validScript {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"invalid vtxo script for input %d", i,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}

		// Track inputs exit closures to check later if any is mature.
		exitDelay, err := vtxoScript.SmallestExitDelay()
		if err != nil && err != script.ErrNoExitLeaf {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"failed to get exit delay for input %d: %w", i, err,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		if exitDelay != nil {
			// Reject inputs with exit delay in blocks if only seconds are allowed.
			if exitDelay.Type == arklib.LocktimeTypeBlock && !settings.AllowCSVBlockType() {
				return nil, nil, errors.INVALID_ARK_PSBT.New(
					"invalid exit delay for input %d: expected value in seconds, got it in blocks",
					i,
				).WithMetadata(errors.PsbtMetadata{Tx: tx})
			}
			exitDelaysToCheckExpired[i] = inputExitDelay{
				txid:  ptx.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
				delay: *exitDelay,
			}
		}

		inputsToCosign = append(inputsToCosign, domain.Utxo{
			Outpoint: domain.Outpoint{
				Txid: ptx.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
				VOut: ptx.UnsignedTx.TxIn[i].PreviousOutPoint.Index,
			},
			Amount:    uint64(input.WitnessUtxo.Value),
			PubKey:    hex.EncodeToString(input.WitnessUtxo.PkScript[2:]),
			Spend:     domain.UtxoSpend{Txid: spendingTxid},
			CreatedAt: now.Unix(),
		})
		inputIndexes = append(inputIndexes, i)

		txsToCheckConfirmed[ptx.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String()] = struct{}{}
	}

	if len(inputsToCosign) == 0 {
		return nil, nil, errors.INVALID_ARK_PSBT.New("tx has no inputs to cosign").
			WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	sumOfOutputs := int64(0)
	for _, output := range ptx.UnsignedTx.TxOut {
		sumOfOutputs += int64(output.Value)
	}

	// Reject if sum of outputs is greater than sum of inputs.
	if sumOfOutputs > sumOfInputs {
		return nil, nil, errors.INVALID_ARK_PSBT.New(
			"sum of outputs greater than sum of inputs (%d > %d)", sumOfOutputs, sumOfInputs,
		)
	}

	// Reject if the signatures of the other cosigners are not valid. Broadcasting would catch
	// it, but only after our signature is made and the utxos reserved, so anyone knowing an
	// outpoint could burn a signer call and lock the utxos of somebody else for a moment.
	// Foreign inputs are left out of the check, they are the client's business.
	if err := verifyCosignersSigs(ptx, inputIndexes, signerPubkeys); err != nil {
		return nil, nil, errors.INVALID_ARK_PSBT.New("invalid signatures: %w", err).
			WithMetadata(errors.PsbtMetadata{Tx: tx})
	}

	// Only after all local checks pass, verify every client-supplied prevout against its
	// funding output. Deduplicate lookups; the input cap bounds the number of node calls.
	fundingTxs := make(map[string]*wire.MsgTx)
	for i, input := range ptx.Inputs {
		outpoint := ptx.UnsignedTx.TxIn[i].PreviousOutPoint
		txid := outpoint.Hash.String()
		fundingTx := fundingTxs[txid]
		if fundingTx == nil {
			txhex, err := s.wallet.GetTransaction(ctx, txid)
			if err != nil {
				return nil, nil, errors.TX_NOT_FOUND.New(
					"failed to get funding tx %s: %w", txid, err,
				).WithMetadata(errors.TxNotFoundMetadata{Txid: txid})
			}
			fundingTx = &wire.MsgTx{}
			if err := fundingTx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
				return nil, nil, errors.INTERNAL_ERROR.New(
					"failed to deserialize funding tx %s: %w", txid, err,
				)
			}
			fundingTxs[txid] = fundingTx
		}
		if uint64(outpoint.Index) >= uint64(len(fundingTx.TxOut)) {
			return nil, nil, errors.INVALID_ARK_PSBT.New("invalid vout index for input %d", i).
				WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
		prevout := fundingTx.TxOut[outpoint.Index]
		if prevout.Value != input.WitnessUtxo.Value ||
			!bytes.Equal(prevout.PkScript, input.WitnessUtxo.PkScript) {
			return nil, nil, errors.INVALID_ARK_PSBT.New("prevout mismatch for input %d", i).
				WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
	}

	// Reject if any input to cosign is already spent, either in blockchain or in mempool.
	// This catches spends we don't know about, like a pending tx that could be replaced by ours.
	for _, in := range inputsToCosign {
		spent, err := s.wallet.GetOutpointStatus(ctx, in.Outpoint)
		if err != nil {
			log.WithError(err).Errorf("failed to check spent status of utxo %s", in.Outpoint)
			return nil, nil, errors.INTERNAL_ERROR.New("something went wrong, please retry")
		}
		if spent {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"input %s is already spent", in.Outpoint,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
	}

	// Unconfirmed inputs are accepted: their exit closures can't be mature yet.
	confirmations := make(map[string]ports.BlockTimestamp)
	for txid := range txsToCheckConfirmed {
		isConfirmed, conf, err := s.scanner.IsTransactionConfirmed(ctx, txid)
		if err != nil {
			log.WithError(err).Errorf("failed to check confirmation status of tx %s", txid)
			return nil, nil, errors.INTERNAL_ERROR.New("something went wrong, please retry")
		}
		if isConfirmed {
			confirmations[txid] = *conf
		}
	}

	var tip *ports.BlockTimestamp
	// Reject if any confirmed input has a mature exit closure.
	for inIndex, input := range exitDelaysToCheckExpired {
		conf, ok := confirmations[input.txid]
		if !ok {
			continue
		}
		// The tip is required only for delays in blocks (regtest only), they can't be
		// compared against a clock.
		if input.delay.Type == arklib.LocktimeTypeBlock && tip == nil {
			if tip, err = s.wallet.GetCurrentBlockTime(ctx); err != nil {
				log.WithError(err).Error("failed to get chain tip")
				return nil, nil, errors.INTERNAL_ERROR.New(
					"something went wrong, please retry",
				)
			}
		}
		// Use a margin to make sure the exit path doesn't become available right after cosigning.
		expired, err := isExitDelayExpired(
			&conf, tip, input.delay, settings.UnrolledVtxoMinExpiryMargin, now,
		)
		if err != nil {
			log.WithError(err).Error("failed to check if exit delay is expired")
			return nil, nil, errors.INTERNAL_ERROR.New("something went wrong, please retry")
		}
		if expired {
			return nil, nil, errors.INVALID_ARK_PSBT.New(
				"input %d has an available exit closure", inIndex,
			).WithMetadata(errors.PsbtMetadata{Tx: tx})
		}
	}

	return inputsToCosign, inputIndexes, nil
}

func (s *service) waitForSpendConfirmationAndUpdateUtxos(onchainTx *domain.OnchainTx) {
	txid := onchainTx.Txid
	utxos := onchainTx.SignedInputs
	log.Debugf(
		"start waiting for tx %s spending %d cosigned utxos to be confirmed", txid, len(utxos),
	)
	confirmation, err := waitForConfirmation(s.ctx, txid, s.wallet)
	if err != nil {
		log.WithError(err).Errorf("failed to wait for tx %s to be confirmed", txid)
		return
	}

	event, err := onchainTx.Confirm(confirmation.Time, uint64(confirmation.Height))
	if err != nil {
		log.WithError(err).Errorf(
			"failed to confirm the spend of utxos cosigned in tx %s", txid,
		)
		return
	}

	if err := s.repoManager.Events().Save(
		s.ctx, domain.OnchainTxTopic, txid, []domain.Event{event},
	); err != nil {
		log.WithError(err).Errorf(
			"failed to save the spend of utxos cosigned in tx %s", txid,
		)
		return
	}

	log.Debugf(
		"tx %s spending %d cosigned utxos confirmed at %+v", txid, len(utxos), confirmation,
	)
}

// watchSpentCosignedUtxos records the confirmation of a boarding or unrolled vtxo cosigned with us
// in the given tx that is now in mempool.
func (s *service) watchSpentCosignedUtxos(txid string) {
	repo := s.repoManager.CosignedUtxos()

	utxos, err := repo.GetUnconfirmedUtxosWithSpendingTxid(s.ctx, txid)
	if err != nil {
		log.WithError(err).Errorf("failed to get cosigned utxos spent by tx %s", txid)
		return
	}
	if len(utxos) <= 0 {
		return
	}

	confirmation, err := waitForConfirmation(s.ctx, txid, s.wallet)
	if err != nil {
		log.WithError(err).Errorf("failed to wait for tx %s to be confirmed", txid)
		return
	}

	for i := range utxos {
		utxos[i].Spend.ConfirmedAtTime = confirmation.Time
		utxos[i].Spend.ConfirmedAtHeight = uint64(confirmation.Height)
	}
	if err := repo.UpdateUtxos(s.ctx, utxos); err != nil {
		log.WithError(err).Errorf("failed to confirm utxos spent by tx %s", txid)
		return
	}

	confirmedAt := time.Unix(confirmation.Time, 0).Format(time.RFC3339)
	log.Debugf(
		"tx %s spending %d cosigned utxos confirmed at %s in block %d",
		txid, len(utxos), confirmedAt, confirmation.Height,
	)
}

// verifyCosignersSigs verifies the tapscript signatures of the inputs to cosign, expecting
// every key of their spending leaf but ours to have signed. The other inputs are ignored: the
// check runs on a copy of the tx with their leaf scripts dropped, that's what makes the
// verifier skip them, while their prevouts are kept since the sighash commits to all of them.
func verifyCosignersSigs(
	ptx *psbt.Packet, inputIndexes []int, signerPubkeys []*btcec.PublicKey,
) error {
	toCosign := make(map[int]struct{}, len(inputIndexes))
	for _, i := range inputIndexes {
		toCosign[i] = struct{}{}
	}

	// Shallow copy, the caller's inputs are left untouched.
	toVerify := *ptx
	toVerify.Inputs = append([]psbt.PInput(nil), ptx.Inputs...)
	prevouts := make(map[wire.OutPoint]*wire.TxOut, len(toVerify.Inputs))
	for i, in := range toVerify.UnsignedTx.TxIn {
		prevouts[in.PreviousOutPoint] = toVerify.Inputs[i].WitnessUtxo
		if _, ok := toCosign[i]; !ok {
			toVerify.Inputs[i].TaprootLeafScript = nil
		}
	}

	_, err := script.VerifyTapscriptSigs(
		&toVerify, txscript.NewMultiPrevOutFetcher(prevouts),
		script.WithSkipPublicKeys(signerPubkeys...),
	)
	return err
}

func isUnsignedInput(input psbt.PInput) bool {
	return len(input.TaprootKeySpendSig) <= 0 && len(input.TaprootScriptSpendSig) <= 0 &&
		len(input.PartialSigs) <= 0
}

func outpointsToString(list []domain.Outpoint) []string {
	outpoints := make([]string, 0, len(list))
	for _, l := range list {
		outpoints = append(outpoints, l.String())
	}
	return outpoints
}

func utxosToString(list []domain.Utxo) []string {
	outpoints := make([]string, 0, len(list))
	for _, l := range list {
		outpoints = append(outpoints, l.String())
	}
	return outpoints
}

type inputExitDelay struct {
	txid  string
	delay arklib.RelativeLocktime
}

func getTxidsFromOutpoints(outpoints []domain.Outpoint) []string {
	txids := make([]string, 0, len(outpoints))
	seen := make(map[string]struct{})
	for _, outpoint := range outpoints {
		if _, ok := seen[outpoint.Txid]; ok {
			continue
		}
		txids = append(txids, outpoint.Txid)
		seen[outpoint.Txid] = struct{}{}
	}
	return txids
}
