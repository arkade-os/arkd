package batchsession

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batcheventhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// JoinBatch joins a batch session whose intent has already been registered
// with the server. It subscribes to the batch event stream, drives the
// per-participant signing flow (tree signing, forfeit signing, commitment-tx
// signing), and returns the finalized batch result on success.
//
// Callers normally use Settle, CollaborativeExit, or RedeemNotes — those
// orchestrators take care of registering the intent and retrying on
// transient failures before delegating to JoinBatch.
func JoinBatch(ctx context.Context, args JoinBatchArgs, opts ...Option) (*BatchTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	handlerArgs := batcheventhandler.Args{
		Client:         args.Client,
		ServerInfo:     args.ServerInfo,
		SignTx:         args.SignTx,
		IntentId:       args.IntentId,
		Vtxos:          args.Vtxos,
		BoardingUtxos:  args.BoardingUtxos,
		Receivers:      args.Outputs,
		SignerSessions: args.TreeSigners,
	}

	commitmentTxid, commitmentTx, batchExpiry, forfeitTxs, vtxoTree, err := handleBatchEvents(
		ctx, o.handler, handlerArgs, args.Notes, o.eventsCh, o.cancelCh,
	)
	if err != nil {
		return nil, err
	}

	// Key offchain outputs by (script, amount) and track counts so that
	// receivers sharing the same script (with same or different amounts)
	// are each matched to a distinct tree-leaf TxOut. The match loop below
	// decrements on each hit and does NOT break, so a leaf carrying multiple
	// matching outputs (Ark packs all of a participant's receivers into one
	// leaf) contributes one vtxo per matching TxOut.
	type outKey struct {
		script string
		amount int64
	}
	utxoOuts := make([]clientlib.Receiver, 0, len(args.Outputs))
	indexedOutputs := make(map[outKey]int)
	for _, output := range args.Outputs {
		if output.IsOnchain() {
			utxoOuts = append(utxoOuts, output)
			continue
		}

		txOut, _, err := output.ToTxOut()
		if err != nil {
			return nil, err
		}
		indexedOutputs[outKey{
			script: hex.EncodeToString(txOut.PkScript),
			amount: txOut.Value,
		}]++
	}

	var leaves []*psbt.Packet
	if vtxoTree != nil {
		leaves = vtxoTree.Leaves()
	}

	now := time.Now()
	vtxoOuts := make([]clientlib.Vtxo, 0, len(args.Outputs))
	for _, leaf := range leaves {
		for i, out := range leaf.UnsignedTx.TxOut {
			k := outKey{
				script: hex.EncodeToString(out.PkScript),
				amount: out.Value,
			}
			if indexedOutputs[k] <= 0 {
				continue
			}
			indexedOutputs[k]--

			ext, _ := extension.NewExtensionFromTx(leaf.UnsignedTx)
			var assets []clientlib.Asset
			if len(ext) > 0 {
				packet := ext.GetAssetPacket()
				if len(packet) > 0 {
					for _, asset := range packet {
						for _, assetOut := range asset.Outputs {
							if assetOut.Vout == uint16(i) {
								assets = append(assets, clientlib.Asset{
									AssetId: asset.AssetId.String(),
									Amount:  assetOut.Amount,
								})
								break
							}
						}
					}
				}
			}
			vtxoOuts = append(vtxoOuts, clientlib.Vtxo{
				Outpoint: clientlib.Outpoint{
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
		}
	}

	return &BatchTxRes{
		CommitmentTxid: commitmentTxid,
		CommitmentTx:   commitmentTx,
		ForfeitTxs:     forfeitTxs,
		VtxoInputs:     args.Vtxos,
		UtxoInputs:     args.BoardingUtxos,
		VtxoOutputs:    vtxoOuts,
		UtxoOutputs:    utxoOuts,
	}, nil
}

func joinBatchWithRetry(
	ctx context.Context, args JoinBatchArgs, opts ...Option,
) (*BatchTxRes, error) {
	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	signerSessions, signerPubkeys, err := o.treeSigners()
	if err != nil {
		return nil, err
	}

	intentArgs := IntentArgs{
		BaseArgs:  args.BaseArgs,
		Cosigners: signerPubkeys,
	}

	deleteIntent := func() {
		proof, message, err := BuildAndSignDeleteIntent(ctx, intentArgs)
		if err != nil {
			log.WithError(err).Warn("failed to create delete intent proof")
			return
		}

		err = args.Client.DeleteIntent(ctx, proof, message)
		if err != nil {
			log.WithError(err).Warn("failed to delete intent")
			return
		}
	}

	maxRetry := 1
	if o.retryNum > 0 {
		maxRetry = o.retryNum
	}
	retryCount := 0
	var batchErr error
	for retryCount < maxRetry {
		proofTx, message, ext, err := BuildAndSignRegisterIntent(ctx, intentArgs)
		if err != nil {
			return nil, err
		}

		intentId, err := args.Client.RegisterIntent(ctx, proofTx, message)
		if err != nil {
			return nil, fmt.Errorf("failed to register intent: %w", err)
		}

		log.Debugf("registered inputs and outputs with request id: %s", intentId)

		res, err := JoinBatch(ctx, JoinBatchArgs{
			BaseArgs:    args.BaseArgs,
			TreeSigners: signerSessions,
			IntentId:    intentId,
			Client:      args.Client,
			ServerInfo:  args.ServerInfo,
		}, opts...)
		if err != nil {
			if retryCount < maxRetry-1 {
				select {
				case <-time.After(100 * time.Millisecond):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				deleteIntent()
				log.WithError(err).Warn("batch failed, retrying...")
			}
			retryCount++
			batchErr = err
			continue
		}
		res.IntentTx = proofTx
		res.Extension = ext
		return res, nil
	}

	return nil, fmt.Errorf("reached max attempt of retries, last batch error: %s", batchErr)
}
