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
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
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
) (map[int64][]ports.SweepableBatchOutput, error) {
	sweepableBatchOutputs := make(map[int64][]ports.SweepableBatchOutput)
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
					return false, fmt.Errorf("tx %s not found", parentTxid)
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
				sweepableBatchOutputs[expirationTime] = make([]ports.SweepableBatchOutput, 0)
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
			CreatedAt:          offchainTx.EndingTimestamp,
		})
	}

	return txid, ins, outs, nil
}

func newBoardingInput(
	tx wire.MsgTx, input ports.Input, signerPubkey *btcec.PublicKey,
	boardingExitDelay arklib.RelativeLocktime, blockTypeCSVAllowed bool,
) (*ports.BoardingInput, error) {
	if len(tx.TxOut) <= int(input.VOut) {
		return nil, fmt.Errorf("output index out of range [0, %d]", len(tx.TxOut)-1)
	}

	output := tx.TxOut[input.VOut]

	boardingScript, err := script.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding utxo taproot tree: %s", err)
	}

	tapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	expectedScriptPubkey, err := script.P2TRScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get script pubkey: %s", err)
	}

	if !bytes.Equal(output.PkScript, expectedScriptPubkey) {
		return nil, fmt.Errorf(
			"invalid boarding utxo taproot key: got %x expected %x",
			output.PkScript, expectedScriptPubkey,
		)
	}

	if err := boardingScript.Validate(
		signerPubkey, boardingExitDelay, blockTypeCSVAllowed,
	); err != nil {
		return nil, err
	}

	return &ports.BoardingInput{
		Amount: uint64(output.Value),
		Input:  input,
	}, nil
}

func calcNextMarketHour(
	marketHourStartTime, marketHourEndTime time.Time,
	period, marketHourDelta time.Duration, now time.Time,
) (time.Time, time.Time, error) {
	// Validate input parameters
	if period <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("period must be greater than 0")
	}
	if !marketHourEndTime.After(marketHourStartTime) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"market hour end time must be after start time",
		)
	}

	// Calculate the duration of the market hour
	duration := marketHourEndTime.Sub(marketHourStartTime)

	// Calculate the number of periods since the initial marketHourStartTime
	elapsed := now.Sub(marketHourStartTime)
	var n int64
	if elapsed >= 0 {
		n = int64(elapsed / period)
	} else {
		n = int64((elapsed - period + 1) / period)
	}

	// Calculate the current market hour start and end times
	currentStartTime := marketHourStartTime.Add(time.Duration(n) * period)
	currentEndTime := currentStartTime.Add(duration)

	// Adjust if now is before the currentStartTime
	if now.Before(currentStartTime) {
		n -= 1
		currentStartTime = marketHourStartTime.Add(time.Duration(n) * period)
		currentEndTime = currentStartTime.Add(duration)
	}

	timeUntilEnd := currentEndTime.Sub(now)

	if !now.Before(currentStartTime) && now.Before(currentEndTime) &&
		timeUntilEnd >= marketHourDelta {
		// Return the current market hour
		return currentStartTime, currentEndTime, nil
	} else {
		// Move to the next market hour
		n += 1
		nextStartTime := marketHourStartTime.Add(time.Duration(n) * period)
		nextEndTime := nextStartTime.Add(duration)
		return nextStartTime, nextEndTime, nil
	}
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
	cosignerKeys, err := txutils.GetCosignerKeys(g.Root.Inputs[0])
	if err != nil {
		return nil, err
	}

	topics := make([]string, 0, len(cosignerKeys))
	for _, key := range cosignerKeys {
		topics = append(topics, hex.EncodeToString(key.SerializeCompressed()))
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
