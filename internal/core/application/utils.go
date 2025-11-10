package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// onchainOutputs iterates over all the nodes' outputs in the vtxo tree and checks their onchain state
// returns the sweepable outputs as ports.SweepInput mapped by their expiration time
func findSweepableOutputs(
	ctx context.Context, walletSvc ports.WalletService, txbuilder ports.TxBuilder,
	schedulerUnit ports.TimeUnit, vtxoTree *tree.TxTree,
) (map[int64][]ports.SweepableOutput, error) {
	sweepableBatchOutputs := make(map[int64][]ports.SweepableOutput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime / blockheight

	if err := vtxoTree.Apply(func(g *tree.TxTree) (bool, error) {
		isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(
			ctx, g.Root.UnsignedTx.TxID(),
		)
		if err != nil {
			return false, err
		}

		if !isConfirmed {
			parentTxid := g.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()

			if _, ok := blocktimeCache[parentTxid]; !ok {
				isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(
					ctx, parentTxid,
				)
				if !isConfirmed || err != nil {
					return false, fmt.Errorf("tx %s not confirmed", parentTxid)
				}

				if schedulerUnit == ports.BlockHeight {
					blocktimeCache[parentTxid] = height
				} else {
					blocktimeCache[parentTxid] = blocktime
				}
			}

			vtxoTreeExpiry, sweepInput, err := txbuilder.GetSweepableBatchOutputs(g)
			if err != nil {
				return false, err
			}

			expirationTime := blocktimeCache[parentTxid] + int64(vtxoTreeExpiry.Value)
			if _, ok := sweepableBatchOutputs[expirationTime]; !ok {
				sweepableBatchOutputs[expirationTime] = make([]ports.SweepableOutput, 0)
			}
			sweepableBatchOutputs[expirationTime] = append(
				sweepableBatchOutputs[expirationTime], sweepInput,
			)
			// we don't need to check the children, we already found a sweepable output
			return false, nil
		}

		// cache the blocktime for future use
		if schedulerUnit == ports.BlockHeight {
			blocktimeCache[g.Root.UnsignedTx.TxID()] = height
		} else {
			blocktimeCache[g.Root.UnsignedTx.TxID()] = blocktime
		}

		// if the tx is onchain, it means that the input is spent, we need to check the children
		return true, nil
	}); err != nil {
		return nil, err
	}

	return sweepableBatchOutputs, nil
}

func getSpentVtxos(intents map[string]domain.Intent) []domain.Outpoint {
	vtxos := make([]domain.Outpoint, 0)
	for _, intent := range intents {
		for _, vtxo := range intent.Inputs {
			vtxos = append(vtxos, vtxo.Outpoint)
		}
	}
	return vtxos
}

func decodeTx(offchainTx domain.OffchainTx) (string, []domain.Outpoint, []domain.Vtxo, error) {
	ins := make([]domain.Outpoint, 0, len(offchainTx.CheckpointTxs))
	for _, checkpointTx := range offchainTx.CheckpointTxs {
		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTx), true)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to parse checkpoint tx: %s", err)
		}
		ins = append(ins, domain.Outpoint{
			Txid: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		})
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(offchainTx.ArkTx), true)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse partial tx: %s", err)
	}
	txid := ptx.UnsignedTx.TxID()

	outs := make([]domain.Vtxo, 0, len(ptx.UnsignedTx.TxOut))
	for outIndex, out := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
			continue
		}
		outs = append(outs, domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: txid,
				VOut: uint32(outIndex),
			},
			PubKey:             hex.EncodeToString(out.PkScript[2:]),
			Amount:             uint64(out.Value),
			ExpiresAt:          offchainTx.ExpiryTimestamp,
			CommitmentTxids:    offchainTx.CommitmentTxidsList(),
			RootCommitmentTxid: offchainTx.RootCommitmentTxId,
			Preconfirmed:       true,
			Swept:              script.IsSubDustScript(out.PkScript),
			CreatedAt:          offchainTx.StartingTimestamp,
		})
	}

	return txid, ins, outs, nil
}

func newBoardingInput(
	tx wire.MsgTx, input ports.Input, signerPubkey *btcec.PublicKey,
	boardingExitDelay arklib.RelativeLocktime, blockTypeCSVAllowed bool,
) (*ports.BoardingInput, errors.Error) {
	if len(tx.TxOut) <= int(input.VOut) {
		return nil, errors.INVALID_PSBT_INPUT.New("output index out of range [0, %d]", len(tx.TxOut)-1).
			WithMetadata(errors.InputMetadata{Txid: tx.TxID(), InputIndex: int(input.VOut)})
	}

	output := tx.TxOut[input.VOut]

	boardingScript, err := script.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, errors.INVALID_PSBT_INPUT.New("failed to parse boarding utxo taproot tree: %w", err).
			WithMetadata(errors.InputMetadata{Txid: tx.TxID(), InputIndex: int(input.VOut)})
	}

	tapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, errors.INVALID_PSBT_INPUT.New("failed to compute taproot tree: %w", err).
			WithMetadata(errors.InputMetadata{Txid: tx.TxID(), InputIndex: int(input.VOut)})
	}

	expectedScriptPubkey, err := script.P2TRScript(tapKey)
	if err != nil {
		return nil, errors.INVALID_PSBT_INPUT.New("failed to compute P2TR script from tapkey: %w", err).
			WithMetadata(errors.InputMetadata{Txid: tx.TxID(), InputIndex: int(input.VOut)})
	}

	if !bytes.Equal(output.PkScript, expectedScriptPubkey) {
		return nil, errors.INVALID_PSBT_INPUT.New("invalid boarding utxo taproot key: got %x expected %x", output.PkScript, expectedScriptPubkey).
			WithMetadata(errors.InputMetadata{Txid: tx.TxID(), InputIndex: int(input.VOut)})
	}

	if err := boardingScript.Validate(
		signerPubkey, boardingExitDelay, blockTypeCSVAllowed,
	); err != nil {
		return nil, errors.INVALID_PSBT_INPUT.New("invalid boarding utxo taproot tree: %w", err).
			WithMetadata(errors.InputMetadata{Txid: tx.TxID(), InputIndex: int(input.VOut)})
	}

	return &ports.BoardingInput{
		Amount: uint64(output.Value),
		Input:  input,
	}, nil
}

func calcNextScheduledSession(
	now, scheduledSessionStartTime, scheduledSessionEndTime time.Time, period time.Duration,
) (time.Time, time.Time) {
	// Calculate the number of periods since the initial scheduledSessionStartTime
	elapsed := now.Sub(scheduledSessionEndTime)
	var n int64
	if elapsed >= 0 {
		n = int64(elapsed/period) + 1
	}

	// Calculate the next scheduled session start and end timestamps
	nextStartTime := scheduledSessionStartTime.Add(time.Duration(n) * period)
	nextEndTime := scheduledSessionEndTime.Add(time.Duration(n) * period)

	return nextStartTime, nextEndTime
}

func getNewVtxosFromRound(round *domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	now := time.Now()
	createdAt := now.Unix()
	expireAt := round.ExpiryTimestamp()

	vtxos := make([]domain.Vtxo, 0)
	for _, node := range tree.FlatTxTree(round.VtxoTree).Leaves() {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
				continue
			}

			vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				log.WithError(err).Warn("failed to parse vtxo tap key")
				continue
			}

			vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))
			vtxos = append(vtxos, domain.Vtxo{
				Outpoint:           domain.Outpoint{Txid: tx.UnsignedTx.TxID(), VOut: uint32(i)},
				PubKey:             vtxoPubkey,
				Amount:             uint64(out.Value),
				CommitmentTxids:    []string{round.CommitmentTxid},
				RootCommitmentTxid: round.CommitmentTxid,
				CreatedAt:          createdAt,
				ExpiresAt:          expireAt,
			})
		}
	}
	return vtxos
}

func fancyTime(timestamp int64, unit ports.TimeUnit) (fancyTime string) {
	if unit == ports.UnixTime {
		fancyTime = time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
	} else {
		fancyTime = fmt.Sprintf("block %d", timestamp)
	}
	return
}

func treeTxNoncesEvents(
	txTree *tree.TxTree,
	roundId string,
	publicNoncesMap map[string]tree.TreeNonces,
) []domain.Event {
	events := make([]domain.Event, 0)
	if err := txTree.Apply(func(g *tree.TxTree) (bool, error) {
		txid := g.Root.UnsignedTx.TxID()

		noncesByPubkey := make(map[string]*tree.Musig2Nonce)

		cosignerKeys, err := txutils.ParseCosignerKeysFromArkPsbt(g.Root, 0)
		if err != nil {
			return false, err
		}

		for _, cosignerKey := range cosignerKeys {
			keyStr := hex.EncodeToString(schnorr.SerializePubKey(cosignerKey))
			noncesForCosigner, ok := publicNoncesMap[keyStr]
			if !ok {
				return false, fmt.Errorf("missing nonces for cosigner key %s", keyStr)
			}

			txNonce, ok := noncesForCosigner[txid]
			if !ok {
				return false, fmt.Errorf("missing nonce for cosigner key %s and txid %s", keyStr, txid)
			}

			noncesByPubkey[keyStr] = txNonce
		}

		topics, err := getVtxoTreeTopic(g)
		if err != nil {
			return false, err
		}

		events = append(events, TreeTxNoncesEvent{
			RoundEvent: domain.RoundEvent{
				Id:   roundId,
				Type: domain.EventTypeUndefined,
			},
			Topic:  topics,
			Txid:   txid,
			Nonces: noncesByPubkey,
		})

		return true, nil
	}); err != nil {
		log.WithError(err).Error("failed to send tree tx nonces events")
	}

	return events
}

func treeTxEvents(
	txTree *tree.TxTree, batchIndex int32, roundId string,
	getTopic func(g *tree.TxTree) ([]string, error),
) []domain.Event {
	events := make([]domain.Event, 0)

	if err := txTree.Apply(func(g *tree.TxTree) (bool, error) {
		node, err := g.SerializeNode()
		if err != nil {
			return false, err
		}

		topic, err := getTopic(g)
		if err != nil {
			return false, err
		}

		events = append(events, TreeTxMessage{
			RoundEvent: domain.RoundEvent{
				Id:   roundId,
				Type: domain.EventTypeUndefined,
			},
			BatchIndex: batchIndex,
			Topic:      topic,
			Node:       *node,
		})
		return true, nil
	}); err != nil {
		log.WithError(err).Error("failed to send batchTree events")
	}

	return events
}

func treeSignatureEvents(txTree *tree.TxTree, batchIndex int32, roundId string) []domain.Event {
	events := make([]domain.Event, 0)

	_ = txTree.Apply(func(g *tree.TxTree) (bool, error) {
		sig := g.Root.Inputs[0].TaprootKeySpendSig

		topic, err := getVtxoTreeTopic(g)
		if err != nil {
			return false, err
		}

		events = append(events, TreeSignatureMessage{
			RoundEvent: domain.RoundEvent{
				Id:   roundId,
				Type: domain.EventTypeUndefined,
			},
			Topic:      topic,
			BatchIndex: batchIndex,
			Signature:  hex.EncodeToString(sig),
			Txid:       g.Root.UnsignedTx.TxID(),
		})

		return true, nil
	})

	return events
}

// getVtxoTreeTopic returns the list of topics (cosigner keys) for the given vtxo subtree
func getVtxoTreeTopic(g *tree.TxTree) ([]string, error) {
	cosignerKeysFields, err := txutils.GetArkPsbtFields(g.Root, 0, txutils.CosignerPublicKeyField)
	if err != nil {
		return nil, err
	}

	topics := make([]string, 0, len(cosignerKeysFields))
	for _, field := range cosignerKeysFields {
		topics = append(topics, hex.EncodeToString(field.PublicKey.SerializeCompressed()))
	}

	return topics, nil
}

// getConnectorTreeTopic returns the list of topics (vtxo outpoints) for the given connector subtree
func getConnectorTreeTopic(
	connectorsIndex map[string]domain.Outpoint,
) func(g *tree.TxTree) ([]string, error) {
	return func(g *tree.TxTree) ([]string, error) {
		leaves := g.Leaves()
		topics := make([]string, 0, len(leaves))

		for _, leaf := range leaves {
			leafTxid := leaf.UnsignedTx.TxID()
			for outIndex, output := range leaf.UnsignedTx.TxOut {
				if bytes.Equal(output.PkScript, txutils.ANCHOR_PKSCRIPT) {
					continue
				}

				outpoint := domain.Outpoint{
					Txid: leafTxid,
					VOut: uint32(outIndex),
				}

				topics = append(topics, connectorsIndex[outpoint.String()].String())
			}
		}

		return topics, nil
	}
}

var (
	regtestTickerInterval = time.Second
	mainnetTickerInterval = time.Minute
)

// waitForConfirmation waits for the given tx to be confirmed onchain.
// It uses a ticker with an interval depending on the network
// (1 second for regtest or 1 minute otherwise).
// The function is blocking and returns once the tx is confirmed.
func waitForConfirmation(
	ctx context.Context,
	txid string,
	wallet ports.WalletService,
	network arklib.Network,
) (blockheight int64, blocktime int64) {
	tickerInterval := mainnetTickerInterval
	if network.Name == arklib.BitcoinRegTest.Name {
		tickerInterval = regtestTickerInterval
	}
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for range ticker.C {
		if confirmed, blockHeight, blockTime, _ := wallet.IsTransactionConfirmed(ctx, txid); confirmed {
			log.Debugf(
				"tx %s confirmed at block height %d, block time %d",
				txid,
				blockHeight,
				blockTime,
			)
			return blockHeight, blockTime
		}
	}
	return 0, 0
}

func computeIntentFees(proof intent.Proof) (int64, error) {
	sumOfInputs := int64(0)
	for i, input := range proof.Inputs {
		if input.WitnessUtxo == nil {
			return 0, fmt.Errorf("missing witness utxo for input %d", i)
		}
		sumOfInputs += int64(input.WitnessUtxo.Value)
	}

	sumOfOutputs := int64(0)
	for _, output := range proof.UnsignedTx.TxOut {
		sumOfOutputs += int64(output.Value)
	}

	fees := sumOfInputs - sumOfOutputs
	if fees < 0 {
		return 0, fmt.Errorf("sum of inputs is smaller than sum of outputs (diff: %d)", fees)
	}
	return fees, nil
}
