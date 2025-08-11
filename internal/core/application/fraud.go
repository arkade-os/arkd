package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

var (
	regtestTickerInterval = time.Second
	mainnetTickerInterval = time.Minute
)

// reactToFraud handles the case where a user spent or renewed a vtxo in the past and now tries to
// redeem it onchain. This function is called by the app service when it detects such fraud.
//
// If the vtxo wasn't settled, we broadcast the checkpoint tx signed by both parties when the vtxo
// was spent offchain. Otherwise, the forfeit tx created and signed during the batch execution is
// broadcasted.
//
// The function takes a mutex to ensure that only one goroutine can react to a fraud at the same
// time.
func (s *service) reactToFraud(ctx context.Context, vtxo domain.Vtxo, mutx *sync.Mutex) error {
	mutx.Lock()
	defer mutx.Unlock()

	// If the vtxo wasn't settled we must broadcast a checkpoint tx.
	if !vtxo.IsSettled() {
		if err := s.broadcastCheckpointTx(ctx, vtxo); err != nil {
			return fmt.Errorf("failed to broadcast checkpoint tx: %s", err)
		}

		return nil
	}

	// Otherwise, we must broadcast a forfeit tx.
	if err := s.broadcastForfeitTx(ctx, vtxo); err != nil {
		return fmt.Errorf("failed to broadcast forfeit tx: %s", err)
	}

	return nil
}

// broadcastCheckpointTx broadcasts a checkpoint transaction for a given vtxo spent offchain.
//
// This can happen if a user spent a vtxo offchain, and then started the unrolling process to
// redeem it onchain.
// To react to this attack, the relative offchain tx is fetched from db, then the fully signed
// checkpoint tx is finalized and broadcasted as soon as the vtxo hit the blockchain.
func (s *service) broadcastCheckpointTx(ctx context.Context, vtxo domain.Vtxo) error {
	txs, err := s.repoManager.Rounds().GetTxsWithTxids(ctx, []string{vtxo.SpentBy})
	if err != nil {
		return fmt.Errorf("failed to retrieve checkpoint tx: %s", err)
	}
	if len(txs) <= 0 {
		return fmt.Errorf("checkpoint tx %s not found", vtxo.SpentBy)
	}

	checkpointPsbt := txs[0]
	ptx, err := s.builder.FinalizeAndExtract(checkpointPsbt)
	if err != nil {
		return fmt.Errorf("failed to finalize checkpoint tx: %s", err)
	}

	var checkpointTx wire.MsgTx
	if err := checkpointTx.Deserialize(hex.NewDecoder(strings.NewReader(ptx))); err != nil {
		return fmt.Errorf("failed to deserialize checkpoint tx: %s", err)
	}

	child, err := s.bumpAnchorTx(ctx, &checkpointTx)
	if err != nil {
		return fmt.Errorf("failed to bump checkpoint tx: %s", err)
	}

	if _, err := s.wallet.BroadcastTransaction(ctx, ptx, child); err != nil {
		return fmt.Errorf("failed to broadcast checkpoint package: %s", err)
	}

	log.Debugf("broadcasted checkpoint tx %s", checkpointTx.TxHash().String())
	return nil
}

// broadcastForfeitTx broadcasts a forfeit transaction for a given vtxo.
//
// Given a vtxo, it finds the commitment tx it was settled in, and then finds the corresponding
// forfeit transaction. It then broadcasts the connector branch leading up to the forfeit tx, then
// it is signed, finalized and broadcasted.
func (s *service) broadcastForfeitTx(ctx context.Context, vtxo domain.Vtxo) error {
	round, err := s.repoManager.Rounds().GetRoundWithCommitmentTxid(ctx, vtxo.SettledBy)
	if err != nil {
		return fmt.Errorf("failed to retrieve round: %s", err)
	}

	if len(round.Connectors) <= 0 {
		return fmt.Errorf(
			"no connectors found for round %s, cannot broadcast forfeit tx",
			round.CommitmentTxid,
		)
	}

	forfeitTx, connectorOutpoint, err := findForfeitTx(round.ForfeitTxs, vtxo.Outpoint)
	if err != nil {
		return fmt.Errorf("failed to find forfeit tx: %s", err)
	}

	if len(forfeitTx.UnsignedTx.TxIn) <= 0 {
		return fmt.Errorf("invalid forfeit tx: %s", forfeitTx.UnsignedTx.TxID())
	}

	connectors, err := tree.NewTxTree(round.Connectors)
	if err != nil {
		return fmt.Errorf("failed to create connector tree: %s", err)
	}

	if err := s.broadcastConnectorBranch(ctx, connectors, connectorOutpoint); err != nil {
		return fmt.Errorf("failed to broadcast connector branch: %s", err)
	}

	if err := s.wallet.LockConnectorUtxos(ctx, []domain.Outpoint{connectorOutpoint}); err != nil {
		return fmt.Errorf("failed to lock connector utxos: %s", err)
	}

	forfeitTxB64, err := forfeitTx.B64Encode()
	if err != nil {
		return fmt.Errorf("failed to encode forfeit tx: %s", err)
	}

	signedForfeitTx, err := s.wallet.SignTransactionTapscript(ctx, forfeitTxB64, nil)
	if err != nil {
		return fmt.Errorf("failed to sign forfeit tx: %s", err)
	}

	forfeitTxHex, err := s.builder.FinalizeAndExtract(signedForfeitTx)
	if err != nil {
		return fmt.Errorf("failed to finalize forfeit tx: %s", err)
	}

	var forfeit wire.MsgTx
	if err := forfeit.Deserialize(hex.NewDecoder(strings.NewReader(forfeitTxHex))); err != nil {
		return fmt.Errorf("failed to deserialize forfeit tx: %s", err)
	}

	childForfeit, err := s.bumpAnchorTx(ctx, &forfeit)
	if err != nil {
		return fmt.Errorf("failed to bump forfeit tx: %s", err)
	}

	if _, err = s.wallet.BroadcastTransaction(ctx, forfeitTxHex, childForfeit); err != nil {
		return fmt.Errorf("failed to broadcast forfeit tx: %s", err)
	}

	log.Debugf("broadcasted forfeit tx %s", forfeit.TxHash().String())
	return nil
}

// broadcastConnectorBranch broadcasts the connector branch of txs until the target connector
// outpoint hits the blockchain.
// It takes a connector tree and a connector outpoint and returns an error if the branch can't be
// broadcasted.
// If the connector outpoint is not part of the connector tree, it will return an error.
// If any of the txs in the branch are offchain, it will sign and broadcast them.
// If any of the txs in the branch are not confirmed, it will wait for them to be confirmed before returning.
func (s *service) broadcastConnectorBranch(
	ctx context.Context, connectorTree *tree.TxTree, connectorOutpoint domain.Outpoint,
) error {
	// compute, sign and broadcast the branch txs until the connector outpoint is created
	branch, err := connectorTree.SubTree([]string{connectorOutpoint.Txid})
	if err != nil {
		return fmt.Errorf("failed to get branch of connector: %s", err)
	}

	// If branch is nil, it means there's no path from root to the connector outpoint
	// This could happen if the connector outpoint is not part of the connector tree
	if branch == nil {
		return fmt.Errorf(
			"no path found to connector outpoint %s in connector tree", connectorOutpoint.Txid,
		)
	}

	return branch.Apply(func(g *tree.TxTree) (bool, error) {
		txid := g.Root.UnsignedTx.TxID()
		_, err := s.wallet.GetTransaction(ctx, txid)
		// if err, it means the tx is offchain, must be broadcasted
		if err != nil {
			b64, err := g.Root.B64Encode()
			if err != nil {
				return false, fmt.Errorf("failed to encode tx: %s", err)
			}

			parent, err := s.wallet.SignTransaction(ctx, b64, true)
			if err != nil {
				return false, fmt.Errorf("failed to sign tx: %s", err)
			}

			var parentTx wire.MsgTx
			if err := parentTx.Deserialize(hex.NewDecoder(strings.NewReader(parent))); err != nil {
				return false, fmt.Errorf("failed to deserialize tx: %s", err)
			}

			child, err := s.bumpAnchorTx(ctx, &parentTx)
			if err != nil {
				return false, fmt.Errorf("failed to bump anchor tx: %s", err)
			}

			_, err = s.wallet.BroadcastTransaction(ctx, parent, child)
			if err != nil {
				return false, fmt.Errorf("failed to broadcast transaction: %s", err)
			}
			log.Debugf("broadcasted connector branch tx %s", txid)

			if err := s.wallet.WaitForSync(ctx, txid); err != nil {
				return false, fmt.Errorf("failed to wait for sync: %s", err)
			}

			s.waitForConfirmation(ctx, txid)
			return true, nil
		}

		return true, nil
	})
}

// bumpAnchorTx builds and signs a transaction bumping the fees for a given tx with P2A output.
// Makes use of the onchain P2TR account to select UTXOs to pay fees for parent.
func (s *service) bumpAnchorTx(
	ctx context.Context, parent *wire.MsgTx,
) (string, error) {
	anchor, err := txutils.FindAnchorOutpoint(parent)
	if err != nil {
		return "", err
	}

	// Estimate for the size of the bump transaction.
	weightEstimator := input.TxWeightEstimator{}

	// TODO: weightEstimator doesn't support P2A size, using P2WSH will lead to a small
	// over-estimation. Use the exact P2A size once supported.
	weightEstimator.AddNestedP2WSHInput(lntypes.VByte(3).ToWU())

	// We assume only one UTXO will be selected to have a correct estimation
	weightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault)
	weightEstimator.AddP2TROutput()

	childVSize := weightEstimator.Weight().ToVB()

	packageSize := childVSize + computeVSize(parent)
	feeRate, err := s.wallet.FeeRate(ctx)
	if err != nil {
		return "", err
	}

	fees := chainfee.SatPerKVByte(feeRate).FeeForVSize(packageSize)

	selectedCoins, changeAmount, err := s.wallet.SelectUtxos(
		ctx, "", uint64(fees.ToUnit(btcutil.AmountSatoshi)), true,
	)
	if err != nil {
		return "", err
	}

	addresses, err := s.wallet.DeriveAddresses(ctx, 1)
	if err != nil {
		return "", err
	}

	addr, err := btcutil.DecodeAddress(addresses[0], nil)
	if err != nil {
		return "", err
	}

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
	}

	inputs := []*wire.OutPoint{anchor}
	sequences := []uint32{
		wire.MaxTxInSequenceNum,
	}

	for _, utxo := range selectedCoins {
		txid, err := chainhash.NewHashFromStr(utxo.GetTxid())
		if err != nil {
			return "", err
		}
		inputs = append(inputs, &wire.OutPoint{
			Hash:  *txid,
			Index: utxo.GetIndex(),
		})
		sequences = append(sequences, wire.MaxTxInSequenceNum)
	}

	outputs := []*wire.TxOut{
		{
			Value:    int64(changeAmount),
			PkScript: pkScript,
		},
	}
	ptx, err := psbt.New(inputs, outputs, 3, 0, sequences)
	if err != nil {
		return "", err
	}

	ptx.Inputs[0].WitnessUtxo = txutils.AnchorOutput()

	b64, err := ptx.B64Encode()
	if err != nil {
		return "", err
	}

	tx, err := s.wallet.SignTransaction(ctx, b64, false)
	if err != nil {
		return "", err
	}

	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	for inIndex := range signedPtx.Inputs[1:] {
		if _, err := psbt.MaybeFinalize(signedPtx, inIndex+1); err != nil {
			return "", err
		}
	}

	childTx, err := txutils.ExtractWithAnchors(signedPtx)
	if err != nil {
		return "", err
	}

	var serializedTx bytes.Buffer
	if err := childTx.Serialize(&serializedTx); err != nil {
		return "", err
	}

	return hex.EncodeToString(serializedTx.Bytes()), nil
}

// waitForConfirmation waits for the given tx to be confirmed onchain.
// It uses a ticker with an interval depending on the network
// (1 second for regtest or 1 minute otherwise).
// The function is blocking and returns once the tx is confirmed.
func (s *service) waitForConfirmation(ctx context.Context, txid string) {
	tickerInterval := mainnetTickerInterval
	if s.network.Name == arklib.BitcoinRegTest.Name {
		tickerInterval = regtestTickerInterval
	}
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for range ticker.C {
		if confirmed, _, _, _ := s.wallet.IsTransactionConfirmed(ctx, txid); confirmed {
			return
		}
	}
}

// findForfeitTx finds the correct forfeit tx and connector outpoint for the given vtxo from the
// list of forfeit txs.
//
// It works by iterating over all the inputs of all the forfeit txs and checking if the input
// matches the given vtxo outpoint. If successfull, it returns the forfeit tx and the connector
// outpoint. If it can't find the forfeit tx, it returns an error.
//
// If the input spending the vtxo is at index 0, the connector outpoint is at index 1
// and vice versa.
func findForfeitTx(
	forfeits []domain.ForfeitTx, vtxo domain.Outpoint,
) (*psbt.Packet, domain.Outpoint, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit.Tx), true)
		if err != nil {
			return nil, domain.Outpoint{}, err
		}

		for i, input := range forfeitTx.UnsignedTx.TxIn {
			if input.PreviousOutPoint.Hash.String() == vtxo.Txid &&
				input.PreviousOutPoint.Index == vtxo.VOut {
				connectorInputIndex := uint32(0)
				if i == 0 {
					connectorInputIndex = 1
				}

				connectorOutpoint := forfeitTx.UnsignedTx.TxIn[connectorInputIndex].PreviousOutPoint

				return forfeitTx, domain.Outpoint{
					Txid: connectorOutpoint.Hash.String(),
					VOut: connectorOutpoint.Index,
				}, nil
			}
		}
	}

	return nil, domain.Outpoint{}, fmt.Errorf("forfeit tx not found")
}

// computeVSize calculates the virtual size (vsize) of a Bitcoin transaction
// in virtual bytes (vbytes). It takes into account both the stripped size
// (base size without witness data) and the total size (including witness data),
// and computes the vsize using the weight unit method.
func computeVSize(tx *wire.MsgTx) lntypes.VByte {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize()
	weight := totalSize + baseSize*3
	return lntypes.WeightUnit(uint64(weight)).ToVB()
}
