package arksdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

func (a *service) Settle(ctx context.Context, opts ...BatchSessionOption) (*SettleRes, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt.applyBatch(options); err != nil {
			return nil, err
		}
	}
	if options.expiryThreshold <= 0 {
		options.expiryThreshold = defaultExpiryThreshold
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	info, err := a.client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	feeEstimator, err := arkfee.New(info.Fees.IntentFees)
	if err != nil {
		return nil, err
	}

	// coinselect all available boarding utxos and vtxos
	boardingUtxos, vtxos, outputs, err := a.getFundsToSettle(
		ctx, nil, feeEstimator, getVtxosFilter{
			withRecoverableVtxos: options.withRecoverableVtxos,
			expiryThreshold:      options.expiryThreshold,
			vtxos:                options.vtxos,
			utxos:                options.boardingUtxos,
		},
		options.receiver,
	)
	if err != nil {
		return nil, err
	}

	return a.joinBatchWithRetry(ctx, nil, outputs, *options, vtxos, boardingUtxos)
}

func (a *service) RedeemNotes(
	ctx context.Context, notes []string, opts ...BatchSessionOption,
) (*RedeemNotesRes, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	amount := uint64(0)

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt.applyBatch(options); err != nil {
			return nil, err
		}
	}

	for _, vStr := range notes {
		v, err := note.NewNoteFromString(vStr)
		if err != nil {
			return nil, err
		}
		amount += uint64(v.Value)
	}

	addr, err := a.getReceiver(ctx, options.receiver)
	if err != nil {
		return nil, err
	}

	receiversOutput := []types.Receiver{{
		To:     addr,
		Amount: amount,
	}}

	return a.joinBatchWithRetry(ctx, notes, receiversOutput, *options, nil, nil)
}

func (a *service) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, opts ...BatchSessionOption,
) (*CollaborativeExitRes, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	if a.UtxoMaxAmount == 0 {
		return nil, fmt.Errorf("operation not allowed by the server")
	}

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt.applyBatch(options); err != nil {
			return nil, err
		}
	}
	if options.expiryThreshold <= 0 {
		options.expiryThreshold = defaultExpiryThreshold
	}

	netParams := utils.ToBitcoinNetwork(a.Network)
	if _, err := btcutil.DecodeAddress(addr, &netParams); err != nil {
		return nil, fmt.Errorf("invalid onchain address")
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	// send all case: substract fees from exited amount
	info, err := a.client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	feeEstimator, err := arkfee.New(info.Fees.IntentFees)
	if err != nil {
		return nil, err
	}

	receivers := []types.Receiver{{To: addr, Amount: amount}}
	boardingUtxos, vtxos, outputs, err := a.getFundsToSettle(
		ctx, receivers, feeEstimator, getVtxosFilter{
			withRecoverableVtxos: options.withRecoverableVtxos,
			expiryThreshold:      options.expiryThreshold,
			vtxos:                options.vtxos,
			utxos:                options.boardingUtxos,
			excludeAssetVtxos:    true,
		},
		options.receiver,
	)
	if err != nil {
		return nil, err
	}

	return a.joinBatchWithRetry(ctx, nil, outputs, *options, vtxos, boardingUtxos)
}

func (a *service) RegisterIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
	outputs []types.Receiver, cosignersPublicKeys []string, opts ...SignOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt.applyBatch(options); err != nil {
			return "", err
		}
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return "", err
	}

	inputs, tapLeaves, arkFields, assetInputs, err := toIntentInputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return "", err
	}

	signingRequired := len(boardingUtxos)+len(vtxos) > 0
	proofTx, message, _, err := a.makeRegisterIntent(
		inputs, assetInputs, tapLeaves, outputs,
		cosignersPublicKeys, arkFields, signingRequired, options.keyIdsByScript,
	)
	if err != nil {
		return "", err
	}

	return a.client.RegisterIntent(ctx, proofTx, message)
}

func (a *service) DeleteIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
	opts ...SignOption,
) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt.applyBatch(options); err != nil {
			return err
		}
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return err
	}

	inputs, exitLeaves, arkFields, _, err := toIntentInputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return err
	}

	signingRequired := len(boardingUtxos)+len(vtxos) > 0
	proofTx, message, err := a.makeDeleteIntent(
		inputs, exitLeaves, arkFields, signingRequired, options.keyIdsByScript,
	)
	if err != nil {
		return err
	}

	return a.client.DeleteIntent(ctx, proofTx, message)
}

func (a *service) getFundsToSettle(
	ctx context.Context,
	outputs []types.Receiver, feeEstimator *arkfee.Estimator, opts getVtxosFilter,
	receiver string,
) ([]types.Utxo, []types.VtxoWithTapTree, []types.Receiver, error) {
	vtxos := opts.vtxos
	boardingUtxos := opts.utxos
	if len(opts.vtxos) <= 0 && len(opts.utxos) <= 0 {
		_, offchainAddrs, boardingAddrs, _, err := a.getAddresses(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(offchainAddrs) <= 0 {
			return nil, nil, nil, fmt.Errorf("no offchain addresses found")
		}

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

		boardingUtxos, err = a.getClaimableBoardingUtxos(ctx, boardingAddrs, nil)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	addr, err := a.getReceiver(ctx, receiver)
	if err != nil {
		return nil, nil, nil, err
	}

	if opts.expiryThreshold > 0 {
		vtxos = utils.FilterVtxosByExpiry(vtxos, opts.expiryThreshold)
	}

	if len(outputs) <= 0 {
		// gather all asset balances from inputs to carry them forward
		assetBalances := make(map[string]uint64)
		for _, vtxo := range vtxos {
			for _, a := range vtxo.Assets {
				assetBalances[a.AssetId] += a.Amount
			}
		}
		for _, utxo := range boardingUtxos {
			for _, a := range utxo.Assets {
				assetBalances[a.AssetId] += a.Amount
			}
		}

		assets := make([]types.Asset, 0, len(assetBalances))
		for assetId, amount := range assetBalances {
			assets = append(assets, types.Asset{
				AssetId: assetId,
				Amount:  amount,
			})
		}

		outputs = []types.Receiver{{
			To:     addr,
			Amount: 0,
			Assets: assets,
		}}
	}
	if len(outputs) == 1 && outputs[0].Amount <= 0 {
		totalAmount, totalFeeAmount := uint64(0), uint64(0)
		for _, utxo := range boardingUtxos {
			totalAmount += utxo.Amount
			fees, err := feeEstimator.EvalOnchainInput(utxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, nil, err
			}
			totalFeeAmount += uint64(fees.ToSatoshis())
		}

		for _, vtxo := range vtxos {
			totalAmount += vtxo.Amount
			fees, err := feeEstimator.EvalOffchainInput(vtxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, nil, err
			}
			totalFeeAmount += uint64(fees.ToSatoshis())
		}
		if totalFeeAmount >= totalAmount {
			return nil, nil, nil, fmt.Errorf(
				"fees (%d) exceed total amount (%d)", totalFeeAmount, totalAmount,
			)
		}
		outputs[0].Amount = totalAmount - totalFeeAmount
	}

	selectedBoardingUtxos, selectedVtxos, changeAmount, err := utils.CoinSelect(
		boardingUtxos, vtxos, outputs, a.Dust, opts.withoutExpirySorting, feeEstimator,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	if changeAmount > 0 {
		outputs = append(outputs, types.Receiver{
			To:     addr,
			Amount: changeAmount,
		})
	}
	return selectedBoardingUtxos, selectedVtxos, outputs, nil
}

func (a *service) getClaimableBoardingUtxos(
	_ context.Context, boardingAddrs []types.Address, opts *getVtxosFilter,
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

		boardingUtxos, err := a.explorer.GetUtxos([]string{addr.Address})
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
	ctx context.Context, notes []string, outputs []types.Receiver, options batchSessionOptions,
	selectedCoins []types.VtxoWithTapTree, selectedBoardingCoins []types.Utxo,
) (*BatchTxRes, error) {
	inputs, exitLeaves, arkFields, assetInputs, err := toIntentInputs(
		selectedBoardingCoins, selectedCoins, notes,
	)
	if err != nil {
		return nil, err
	}
	signingRequired := len(selectedCoins)+len(selectedBoardingCoins) > 0

	signerSessions, signerPubKeys, err := a.handleOptions(options, inputs, notes)
	if err != nil {
		return nil, err
	}

	deleteIntent := func() {
		proof, message, err := a.makeDeleteIntent(
			inputs, exitLeaves, arkFields, signingRequired, options.keyIdsByScript,
		)
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

	maxRetry := 1
	if options.retryNum > 0 {
		maxRetry = options.retryNum
	}
	retryCount := 0
	var batchErr error
	for retryCount < maxRetry {
		proofTx, message, ext, err := a.makeRegisterIntent(
			inputs, assetInputs, exitLeaves, outputs, signerPubKeys,
			arkFields, signingRequired, options.keyIdsByScript,
		)
		if err != nil {
			return nil, err
		}

		intentID, err := a.client.RegisterIntent(ctx, proofTx, message)
		if err != nil {
			return nil, fmt.Errorf("failed to register intent: %w", err)
		}

		log.Debugf("registered inputs and outputs with request id: %s", intentID)

		commitmentTxid, commitmentTx, batchExpiry, forfeitTxs, vtxoTree, err := a.handleBatchEvents(
			ctx, intentID, selectedCoins, notes, selectedBoardingCoins, outputs, signerSessions,
			options.eventsCh, options.cancelCh, options.keyIdsByScript,
		)
		if err != nil {
			if retryCount < maxRetry-1 {
				time.Sleep(100 * time.Millisecond)
				deleteIntent()
				log.WithError(err).Warn("batch failed, retrying...")
			}
			retryCount++
			batchErr = err
			continue
		}

		ins := make([]types.Vtxo, 0, len(selectedCoins))
		for _, c := range selectedCoins {
			ins = append(ins, c.Vtxo)
		}
		vtxoOuts := make([]types.Vtxo, 0, len(outputs))
		utxoOuts := make([]types.Receiver, 0, len(outputs))

		now := time.Now()
		var leaves []*psbt.Packet
		if vtxoTree != nil {
			leaves = vtxoTree.Leaves()
		}
		for _, output := range outputs {
			if output.IsOnchain() {
				utxoOuts = append(utxoOuts, output)
				continue
			}

			for _, leaf := range leaves {
				txOut, _, err := output.ToTxOut()
				if err != nil {
					return nil, err
				}
				for i, out := range leaf.UnsignedTx.TxOut {
					if bytes.Equal(txOut.PkScript, out.PkScript) {
						ext, _ := extension.NewExtensionFromTx(leaf.UnsignedTx)
						var assets []types.Asset
						if len(ext) > 0 {
							packet := ext.GetAssetPacket()
							if len(packet) > 0 {
								for _, asset := range packet {
									for _, assetOut := range asset.Outputs {
										if assetOut.Vout == uint16(i) {
											assets = append(assets, types.Asset{
												AssetId: asset.AssetId.String(),
												Amount:  assetOut.Amount,
											})
											break
										}
									}
								}
							}
						}
						vtxoOuts = append(vtxoOuts, types.Vtxo{
							Outpoint: types.Outpoint{
								Txid: leaf.UnsignedTx.TxID(),
								VOut: uint32(i),
							},
							Script:          hex.EncodeToString(out.PkScript),
							Amount:          uint64(out.Value),
							CommitmentTxids: []string{commitmentTxid},
							ExpiresAt:       now.Add(batchExpiry),
							CreatedAt:       now,
							Assets:          assets,
						})
						break
					}
				}
			}
		}

		return &BatchTxRes{
			CommitmentTxid: commitmentTxid,
			CommitmentTx:   commitmentTx,
			IntentTx:       proofTx,
			ForfeitTxs:     forfeitTxs,
			VtxoInputs:     ins,
			UtxoInputs:     selectedBoardingCoins,
			VtxoOutputs:    vtxoOuts,
			UtxoOutputs:    utxoOuts,
			Extension:      ext,
		}, nil
	}

	return nil, fmt.Errorf("reached max attempt of retries, last batch error: %s", batchErr)
}

func (a *service) handleOptions(
	options batchSessionOptions, inputs []intent.Input, notesInputs []string,
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

		signerSession, err := a.wallet.NewVtxoTreeSigner(context.Background())
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
	replayEventsCh chan<- any, cancelCh <-chan struct{}, keysByScript map[string]string,
) (string, string, time.Duration, []string, *tree.TxTree, error) {
	topics := make([]string, 0)
	for _, n := range notes {
		parsedNote, err := note.NewNoteFromString(n)
		if err != nil {
			return "", "", -1, nil, nil, err
		}
		outpoint, _, err := parsedNote.IntentProofInput()
		if err != nil {
			return "", "", -1, nil, nil, err
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

	options := []BatchEventHandlerOption{WithCancel(cancelCh)}

	if skipVtxoTreeSigning {
		options = append(options, WithSkipVtxoTreeSigning())
	}

	if replayEventsCh != nil {
		options = append(options, WithReplay(replayEventsCh))
	}

	eventsCh, close, err := a.client.GetEventStream(ctx, topics)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", "", -1, nil, nil, fmt.Errorf("connection closed by server")
		}
		return "", "", -1, nil, nil, err
	}
	defer close()

	batchEventsHandler := newBatchEventsHandler(
		a, intentId, vtxos, boardingUtxos, receivers, signerSessions, keysByScript,
	)

	return JoinBatchSession(ctx, eventsCh, batchEventsHandler, options...)
}

func (a *service) makeRegisterIntent(
	inputs []intent.Input, assetInputs map[int][]types.Asset,
	leafProofs []*arklib.TaprootMerkleProof, outputs []types.Receiver,
	cosignersPublicKeys []string, arkFields [][]*psbt.Unknown,
	signingRequired bool, keysByScripts map[string]string,
) (string, string, extension.Extension, error) {
	message, outputsTxOut, ext, err := registerIntentMessage(
		assetInputs, outputs, cosignersPublicKeys,
	)
	if err != nil {
		return "", "", nil, err
	}

	proof, message, err := a.makeIntent(
		message, inputs, outputsTxOut, leafProofs, arkFields, signingRequired, keysByScripts,
	)
	if err != nil {
		return "", "", nil, err
	}

	return proof, message, ext, nil
}

func (a *service) makeGetPendingTxIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof,
	arkFields [][]*psbt.Unknown, signingRequired bool, keysByScripts map[string]string,
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

	return a.makeIntent(
		message, inputs, nil, leafProofs, arkFields, signingRequired, keysByScripts,
	)
}

func (a *service) makeDeleteIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof,
	arkFields [][]*psbt.Unknown, signingRequired bool, keysByScripts map[string]string,
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

	return a.makeIntent(
		message, inputs, nil, leafProofs, arkFields, signingRequired, keysByScripts,
	)
}

func (a *service) makeIntent(
	message string, inputs []intent.Input, outputsTxOut []*wire.TxOut,
	leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
	signingRequired bool, keysByScript map[string]string,
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

	if !signingRequired {
		return unsignedProofTx, message, nil
	}

	signedTx, err := a.wallet.SignTransaction(context.Background(), unsignedProofTx, keysByScript)
	if err != nil {
		return "", "", err
	}

	return signedTx, message, nil
}
