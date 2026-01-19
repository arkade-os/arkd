package arksdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

func (a *service) Settle(ctx context.Context, opts ...SettleOption) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}
	if options.expiryThreshold <= 0 {
		options.expiryThreshold = defaultExpiryThreshold
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	info, err := a.client.GetInfo(ctx)
	if err != nil {
		return "", err
	}

	feeEstimator, err := arkfee.New(info.Fees.IntentFees)
	if err != nil {
		return "", err
	}

	// coinselect all available boarding utxos and vtxos
	boardingUtxos, vtxos, outputs, err := a.getFundsToSettle(
		ctx, nil, feeEstimator, getVtxosFilter{
			withRecoverableVtxos: options.withRecoverableVtxos,
			expiryThreshold:      options.expiryThreshold,
			vtxos:                options.vtxos,
			utxos:                options.boardingUtxos,
		},
	)
	if err != nil {
		return "", err
	}

	return a.joinBatchWithRetry(ctx, nil, outputs, *options, vtxos, boardingUtxos)
}

func (a *service) RedeemNotes(
	ctx context.Context, notes []string, opts ...SettleOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	amount := uint64(0)

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}

	for _, vStr := range notes {
		v, err := note.NewNoteFromString(vStr)
		if err != nil {
			return "", err
		}
		amount += uint64(v.Value)
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}
	if len(offchainAddrs) <= 0 {
		return "", fmt.Errorf("no funds detected")
	}

	receiversOutput := []types.Receiver{{
		To:     offchainAddrs[0].Address,
		Amount: amount,
	}}

	return a.joinBatchWithRetry(ctx, notes, receiversOutput, *options, nil, nil)
}

func (a *service) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, opts ...SettleOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if a.UtxoMaxAmount == 0 {
		return "", fmt.Errorf("operation not allowed by the server")
	}

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}
	if options.expiryThreshold <= 0 {
		options.expiryThreshold = defaultExpiryThreshold
	}

	netParams := utils.ToBitcoinNetwork(a.Network)
	if _, err := btcutil.DecodeAddress(addr, &netParams); err != nil {
		return "", fmt.Errorf("invalid onchain address")
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	getVtxosOpts := &getVtxosFilter{
		withRecoverableVtxos: options.withRecoverableVtxos,
	}
	spendableVtxos, err := a.getSpendableVtxos(ctx, getVtxosOpts)
	if err != nil {
		return "", err
	}
	balance := uint64(0)
	for _, vtxo := range spendableVtxos {
		balance += vtxo.Amount
	}
	if balance < amount {
		return "", fmt.Errorf("not enough funds to cover amount %d", amount)
	}
	// send all case: substract fees from exited amount
	info, err := a.client.GetInfo(ctx)
	if err != nil {
		return "", err
	}

	feeEstimator, err := arkfee.New(info.Fees.IntentFees)
	if err != nil {
		return "", err
	}

	receivers := []types.Receiver{{To: addr, Amount: amount}}
	boardingUtxos, vtxos, outputs, err := a.getFundsToSettle(
		ctx, receivers, feeEstimator, getVtxosFilter{
			withRecoverableVtxos: options.withRecoverableVtxos,
			expiryThreshold:      options.expiryThreshold,
			vtxos:                options.vtxos,
			utxos:                options.boardingUtxos,
		},
	)
	if err != nil {
		return "", err
	}

	return a.joinBatchWithRetry(ctx, nil, outputs, *options, vtxos, boardingUtxos)
}

func (a *service) RegisterIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
	outputs []types.Receiver, cosignersPublicKeys []string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return "", err
	}

	inputs, tapLeaves, arkFields, err := toIntentInputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return "", err
	}

	proofTx, message, err := a.makeRegisterIntent(
		inputs, tapLeaves, outputs, cosignersPublicKeys, arkFields,
	)
	if err != nil {
		return "", err
	}

	return a.client.RegisterIntent(ctx, proofTx, message)
}

func (a *service) DeleteIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return err
	}

	inputs, exitLeaves, arkFields, err := toIntentInputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return err
	}

	proofTx, message, err := a.makeDeleteIntent(inputs, exitLeaves, arkFields)
	if err != nil {
		return err
	}

	return a.client.DeleteIntent(ctx, proofTx, message)
}

func (a *service) getFundsToSettle(
	ctx context.Context,
	outputs []types.Receiver, feeEstimator *arkfee.Estimator, opts getVtxosFilter,
) ([]types.Utxo, []types.VtxoWithTapTree, []types.Receiver, error) {
	_, offchainAddrs, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, nil, nil, fmt.Errorf("no offchain addresses found")
	}

	vtxos := opts.vtxos
	if len(vtxos) <= 0 {
		spendableVtxos, err := a.getSpendableVtxos(ctx, &opts)
		if err != nil {
			return nil, nil, nil, err
		}

		for _, offchainAddr := range offchainAddrs {
			for _, v := range spendableVtxos {
				vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
				if err != nil {
					return nil, nil, nil, err
				}

				if vtxoAddr == offchainAddr.Address {
					vtxos = append(vtxos, types.VtxoWithTapTree{
						Vtxo:       v,
						Tapscripts: offchainAddr.Tapscripts,
					})
				}
			}
		}
	}

	boardingUtxos := opts.utxos
	if len(boardingUtxos) <= 0 {
		boardingUtxos, err = a.getClaimableBoardingUtxos(ctx, boardingAddrs, nil)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if len(outputs) <= 0 {
		outputs = []types.Receiver{{
			To:     offchainAddrs[0].Address,
			Amount: 0,
		}}
	}
	if len(outputs) == 1 && outputs[0].Amount <= 0 {
		for _, utxo := range boardingUtxos {
			outputs[0].Amount += utxo.Amount
			fees, err := feeEstimator.EvalOnchainInput(utxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, nil, err
			}
			outputs[0].Amount -= uint64(fees.ToSatoshis())
		}

		for _, vtxo := range vtxos {
			outputs[0].Amount += vtxo.Amount
			fees, err := feeEstimator.EvalOffchainInput(vtxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, nil, err
			}
			outputs[0].Amount -= uint64(fees.ToSatoshis())
		}
	}

	selectedBoardingUtxos, selectedVtxos, changeAmount, err := utils.CoinSelect(
		boardingUtxos, vtxos, outputs, a.Dust, opts.withoutExpirySorting, feeEstimator,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	if changeAmount > 0 {
		outputs = append(outputs, types.Receiver{
			To:     offchainAddrs[0].Address,
			Amount: changeAmount,
		})
	}
	return selectedBoardingUtxos, selectedVtxos, outputs, nil
}

func (a *service) getClaimableBoardingUtxos(
	_ context.Context, boardingAddrs []wallet.TapscriptsAddress, opts *getVtxosFilter,
) ([]types.Utxo, error) {
	claimable := make([]types.Utxo, 0)
	for _, addr := range boardingAddrs {
		boardingScript, err := script.ParseVtxoScript(addr.Tapscripts)
		if err != nil {
			return nil, err
		}

		boardingTimeout, err := boardingScript.SmallestExitDelay()
		if err != nil {
			return nil, err
		}

		boardingUtxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		for _, utxo := range boardingUtxos {
			if opts != nil && len(opts.outpoints) > 0 {
				utxoOutpoint := types.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}
				found := false
				for _, outpoint := range opts.outpoints {
					if outpoint == utxoOutpoint {
						found = true
						break
					}
				}

				if !found {
					continue
				}
			}

			u := utxo.ToUtxo(*boardingTimeout, addr.Tapscripts)
			if u.SpendableAt.Before(now) {
				continue
			}

			claimable = append(claimable, u)
		}
	}

	return claimable, nil
}

func (a *service) joinBatchWithRetry(
	ctx context.Context, notes []string, outputs []types.Receiver, options settleOptions,
	selectedCoins []types.VtxoWithTapTree, selectedBoardingCoins []types.Utxo,
) (string, error) {
	inputs, exitLeaves, arkFields, err := toIntentInputs(
		selectedBoardingCoins, selectedCoins, notes,
	)
	if err != nil {
		return "", err
	}

	signerSessions, signerPubKeys, err := a.handleOptions(options, inputs, notes)
	if err != nil {
		return "", err
	}

	deleteIntent := func() {
		proof, message, err := a.makeDeleteIntent(inputs, exitLeaves, arkFields)
		if err != nil {
			log.WithError(err).Warn("failed to create delete intent proof")
			return
		}

		err = a.client.DeleteIntent(ctx, proof, message)
		if err != nil {
			log.WithError(err).Warn("failed to delete intent")
			return
		}
	}

	maxRetry := 3
	retryCount := 0
	var batchErr error
	for retryCount < maxRetry {
		proofTx, message, err := a.makeRegisterIntent(
			inputs, exitLeaves, outputs, signerPubKeys, arkFields,
		)
		if err != nil {
			return "", err
		}

		intentID, err := a.client.RegisterIntent(ctx, proofTx, message)
		if err != nil {
			return "", fmt.Errorf("failed to register intent: %w", err)
		}

		log.Debugf("registered inputs and outputs with request id: %s", intentID)

		commitmentTxid, err := a.handleBatchEvents(
			ctx, intentID, selectedCoins, notes, selectedBoardingCoins, outputs, signerSessions,
			options.eventsCh, options.cancelCh,
		)
		if err != nil {
			deleteIntent()
			log.WithError(err).Warn("batch failed, retrying...")
			retryCount++
			time.Sleep(100 * time.Millisecond)
			batchErr = err
			continue
		}

		return commitmentTxid, nil
	}

	return "", fmt.Errorf("reached max attempt of retries, last batch error: %s", batchErr)
}

func (a *service) handleOptions(
	options settleOptions, inputs []intent.Input, notesInputs []string,
) ([]tree.SignerSession, []string, error) {
	sessions := make([]tree.SignerSession, 0)
	sessions = append(sessions, options.extraSignerSessions...)

	if !options.walletSignerDisabled {
		outpoints := make([]types.Outpoint, 0, len(inputs))
		for _, input := range inputs {
			outpoints = append(outpoints, types.Outpoint{
				Txid: input.OutPoint.Hash.String(),
				VOut: uint32(input.OutPoint.Index),
			})
		}

		signerSession, err := a.wallet.NewVtxoTreeSigner(
			context.Background(),
			inputsToDerivationPath(outpoints, notesInputs),
		)
		if err != nil {
			return nil, nil, err
		}
		sessions = append(sessions, signerSession)
	}

	if len(sessions) == 0 {
		return nil, nil, fmt.Errorf("no signer sessions")
	}

	signerPubKeys := make([]string, 0)
	for _, session := range sessions {
		signerPubKeys = append(signerPubKeys, session.GetPublicKey())
	}

	return sessions, signerPubKeys, nil
}

func (a *service) handleBatchEvents(
	ctx context.Context,
	intentId string, vtxos []types.VtxoWithTapTree, notes []string, boardingUtxos []types.Utxo,
	receivers []types.Receiver, signerSessions []tree.SignerSession,
	replayEventsCh chan<- any, cancelCh <-chan struct{},
) (string, error) {
	topics := make([]string, 0)
	for _, n := range notes {
		parsedNote, err := note.NewNoteFromString(n)
		if err != nil {
			return "", err
		}
		outpoint, _, err := parsedNote.IntentProofInput()
		if err != nil {
			return "", err
		}
		topics = append(topics, outpoint.String())
	}

	for _, boardingUtxo := range boardingUtxos {
		topics = append(topics, boardingUtxo.String())
	}
	for _, vtxo := range vtxos {
		topics = append(topics, vtxo.Outpoint.String())
	}
	for _, signer := range signerSessions {
		topics = append(topics, signer.GetPublicKey())
	}

	// skip only if there is no offchain output
	skipVtxoTreeSigning := true

	for _, receiver := range receivers {
		if _, err := arklib.DecodeAddressV0(receiver.To); err == nil {
			skipVtxoTreeSigning = false
			break
		}
	}

	options := []BatchSessionOption{WithCancel(cancelCh)}

	if skipVtxoTreeSigning {
		options = append(options, WithSkipVtxoTreeSigning())
	}

	if replayEventsCh != nil {
		options = append(options, WithReplay(replayEventsCh))
	}

	eventsCh, close, err := a.client.GetEventStream(ctx, topics)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("connection closed by server")
		}
		return "", err
	}
	defer close()

	batchEventsHandler := newBatchEventsHandler(
		a, intentId, vtxos, boardingUtxos, receivers, signerSessions,
	)

	commitmentTxid, err := JoinBatchSession(ctx, eventsCh, batchEventsHandler, options...)
	if err != nil {
		return "", err
	}

	return commitmentTxid, nil
}

func (a *service) makeRegisterIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof,
	outputs []types.Receiver, cosignersPublicKeys []string, arkFields [][]*psbt.Unknown,
) (string, string, error) {
	message, outputsTxOut, err := registerIntentMessage(outputs, cosignersPublicKeys)
	if err != nil {
		return "", "", err
	}

	return a.makeIntent(message, inputs, outputsTxOut, leafProofs, arkFields)
}

func (a *service) makeGetPendingTxIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
) (string, string, error) {
	message, err := intent.GetPendingTxMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeGetPendingTx,
		},
		ExpireAt: time.Now().Add(10 * time.Minute).Unix(), // valid for 10 minutes
	}.Encode()
	if err != nil {
		return "", "", err
	}

	return a.makeIntent(message, inputs, nil, leafProofs, arkFields)
}

func (a *service) makeDeleteIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
) (string, string, error) {
	message, err := intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeDelete,
		},
		ExpireAt: time.Now().Add(2 * time.Minute).Unix(),
	}.Encode()
	if err != nil {
		return "", "", err
	}

	return a.makeIntent(message, inputs, nil, leafProofs, arkFields)
}

func (a *service) makeIntent(
	message string, inputs []intent.Input, outputsTxOut []*wire.TxOut,
	leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
) (string, string, error) {
	proof, err := intent.New(message, inputs, outputsTxOut)
	if err != nil {
		return "", "", err
	}

	for i, input := range proof.Inputs {
		// intent proof tx has an additional input using the first vtxo script
		// so we need to use the previous leaf proof for the current input except for the first input
		var leafProof *arklib.TaprootMerkleProof
		if i == 0 {
			leafProof = leafProofs[0]
		} else {
			leafProof = leafProofs[i-1]
			input.Unknowns = arkFields[i-1]
		}
		input.TaprootLeafScript = []*psbt.TaprootTapLeafScript{
			{
				ControlBlock: leafProof.ControlBlock,
				Script:       leafProof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			},
		}

		proof.Inputs[i] = input
	}

	unsignedProofTx, err := proof.B64Encode()
	if err != nil {
		return "", "", err
	}

	signedTx, err := a.wallet.SignTransaction(context.Background(), a.explorer, unsignedProofTx)
	if err != nil {
		return "", "", err
	}

	return signedTx, message, nil
}
