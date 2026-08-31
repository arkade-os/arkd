package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
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
) (map[int64][]ports.TxInput, error) {
	sweepableBatchOutputs := make(map[int64][]ports.TxInput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime / blockheight

	if err := vtxoTree.Apply(func(g *tree.TxTree) (bool, error) {
		isConfirmed, blockTimestamp, err := walletSvc.IsTransactionConfirmed(
			ctx, g.Root.UnsignedTx.TxID(),
		)
		if err != nil {
			return false, err
		}

		if !isConfirmed {
			parentTxid := g.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()

			if _, ok := blocktimeCache[parentTxid]; !ok {
				isConfirmed, blockTimestamp, err := walletSvc.IsTransactionConfirmed(
					ctx, parentTxid,
				)
				if !isConfirmed || err != nil {
					return false, fmt.Errorf("tx %s not confirmed", parentTxid)
				}

				if schedulerUnit == ports.BlockHeight {
					blocktimeCache[parentTxid] = int64(blockTimestamp.Height)
				} else {
					blocktimeCache[parentTxid] = blockTimestamp.Time
				}
			}

			sweepParams, sweepInput, err := txbuilder.GetSweepableBatchOutputs(g)
			if err != nil {
				return false, err
			}

			// The scheme comes from the node itself, not from settings: batches
			// built before the epoch cutover keep maturing on their original terms.
			expirationTime := blocktimeCache[parentTxid] + int64(sweepParams.Expiry.Value)
			if sweepParams.IsEpoch() {
				// blocktimeCache holds block heights under a block-height scheduler,
				// and an epoch expiry is a unix timestamp. Comparing the two would
				// schedule the sweep about 1.8 billion blocks out, i.e. never.
				// Settings validation refuses this pairing, so this is an invariant
				// violation rather than a condition to handle: say so at error level
				// and skip this tree. Returning an error here would abort the whole
				// scan, so one misconfigured batch would stop every other batch from
				// being swept too.
				if schedulerUnit == ports.BlockHeight {
					log.Errorf(
						"epoch batch %s cannot be swept by a block-height scheduler: "+
							"epoch expiry requires seconds-based locktimes; skipping it, "+
							"its outputs will not be swept while this deployment uses "+
							"block-based locktimes",
						g.Root.UnsignedTx.TxID(),
					)
					return false, nil
				}
				expirationTime = epochMaturity(
					int64(*sweepParams.BatchExpiry),
					blocktimeCache[parentTxid],
					int64(sweepParams.Expiry.Value),
				)
			}
			if _, ok := sweepableBatchOutputs[expirationTime]; !ok {
				sweepableBatchOutputs[expirationTime] = make([]ports.TxInput, 0)
			}
			sweepableBatchOutputs[expirationTime] = append(
				sweepableBatchOutputs[expirationTime], *sweepInput,
			)
			// we don't need to check the children, we already found a sweepable output
			return false, nil
		}

		// cache the blocktime for future use
		if schedulerUnit == ports.BlockHeight {
			blocktimeCache[g.Root.UnsignedTx.TxID()] = int64(blockTimestamp.Height)
		} else {
			blocktimeCache[g.Root.UnsignedTx.TxID()] = blockTimestamp.Time
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
		if len(checkpointPtx.UnsignedTx.TxIn) == 0 {
			return "", nil, nil, fmt.Errorf("invalid checkpoint tx: missing inputs")
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

	assets, err := getAssetsFromTx(ptx)
	if err != nil {
		return "", nil, nil, err
	}

	outs := make([]domain.Vtxo, 0, len(ptx.UnsignedTx.TxOut))
	for outIndex, out := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) ||
			extension.IsExtension(out.PkScript) {
			continue
		}
		if len(out.PkScript) < 2 {
			return "", nil, nil, fmt.Errorf(
				"invalid output script at index %d: script too short (%d bytes)",
				outIndex,
				len(out.PkScript),
			)
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
			Assets:             assets[uint32(outIndex)],
		})
	}

	return txid, ins, outs, nil
}

// acceptedSignerPubkeys returns the current signer pubkey plus the deprecated ones
// whose cutoff date has not passed yet at the given time.
func acceptedSignerPubkeys(
	current *btcec.PublicKey, deprecated []ports.DeprecatedSignerPubkey, now time.Time,
) []*btcec.PublicKey {
	pubkeys := make([]*btcec.PublicKey, 0, len(deprecated)+1)
	pubkeys = append(pubkeys, current)
	for _, key := range deprecated {
		if isPastCutoff(key, now) {
			continue
		}
		pubkeys = append(pubkeys, key.PubKey)
	}
	return pubkeys
}

func isPastCutoff(key ports.DeprecatedSignerPubkey, now time.Time) bool {
	return !key.CutoffDate.IsZero() && now.After(key.CutoffDate)
}

// validateVtxoScriptForSigners accepts the script if it validates against the current
// signer pubkey or any deprecated one whose cutoff date has not passed yet.
func validateVtxoScriptForSigners(
	v script.VtxoScript, current *btcec.PublicKey, deprecated []ports.DeprecatedSignerPubkey,
	now time.Time, minLocktime arklib.RelativeLocktime, blockTypeAllowed bool,
) error {
	var err error
	for _, signer := range acceptedSignerPubkeys(current, deprecated, now) {
		if err = v.Validate(signer, minLocktime, blockTypeAllowed); err == nil {
			return nil
		}
	}
	for _, key := range deprecated {
		if !isPastCutoff(key, now) {
			continue
		}
		if v.Validate(key.PubKey, minLocktime, blockTypeAllowed) == nil {
			return fmt.Errorf(
				"%x is a deprecated key since %s",
				key.PubKey.SerializeCompressed(), key.CutoffDate.Format(time.RFC3339),
			)
		}
	}
	return err
}

func newBoardingInput(
	tx wire.MsgTx, input ports.Input, signerPubkey *btcec.PublicKey,
	deprecatedSigners []ports.DeprecatedSignerPubkey, now time.Time,
	boardingExitDelay arklib.RelativeLocktime, blockTypeCSVAllowed bool,
) (*ports.BoardingInput, error) {
	if len(tx.TxOut) <= int(input.VOut) {
		return nil, fmt.Errorf("output index out of range [0, %d]", len(tx.TxOut)-1)
	}

	output := tx.TxOut[input.VOut]

	boardingScript, err := script.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding utxo taproot tree: %w", err)
	}

	tapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to compute taproot tree: %w", err)
	}

	expectedScriptPubkey, err := script.P2TRScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute P2TR script from tapkey: %w", err)
	}

	if !bytes.Equal(output.PkScript, expectedScriptPubkey) {
		return nil, fmt.Errorf(
			"invalid boarding utxo taproot key: got %x expected %x",
			output.PkScript, expectedScriptPubkey,
		)
	}

	if err := validateVtxoScriptForSigners(
		boardingScript, signerPubkey, deprecatedSigners, now,
		boardingExitDelay, blockTypeCSVAllowed,
	); err != nil {
		return nil, fmt.Errorf("invalid boarding utxo taproot tree: %w", err)
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

func getNewVtxosFromRound(round domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	now := time.Now()
	createdAt := now.Unix()
	expireAt := round.ExpiryTimestamp()

	totalVtxos := make([]domain.Vtxo, 0)
	for _, node := range tree.FlatTxTree(round.VtxoTree).Leaves() {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}

		assets, err := getAssetsFromTx(tx)
		if err != nil {
			log.WithError(err).Warn("failed to get assets from tx")
			continue
		}

		vtxos := make([]domain.Vtxo, 0)
		for i, out := range tx.UnsignedTx.TxOut {
			if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) ||
				extension.IsExtension(out.PkScript) {
				continue
			}

			vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				log.WithError(err).Warn("failed to parse vtxo tap key")
				continue
			}

			vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))
			outpoint := domain.Outpoint{Txid: tx.UnsignedTx.TxID(), VOut: uint32(i)}
			vtxos = append(vtxos, domain.Vtxo{
				Outpoint:           outpoint,
				PubKey:             vtxoPubkey,
				Amount:             uint64(out.Value),
				CommitmentTxids:    []string{round.CommitmentTxid},
				RootCommitmentTxid: round.CommitmentTxid,
				CreatedAt:          createdAt,
				ExpiresAt:          expireAt,
				Depth:              0,
				MarkerIDs:          []string{outpoint.String()},
				Assets:             assets[uint32(i)],
			})
		}

		totalVtxos = append(totalVtxos, vtxos...)
	}

	return totalVtxos
}

func getAssetsFromTx(ptx *psbt.Packet) (map[uint32][]domain.AssetDenomination, error) {
	ext, err := extension.NewExtensionFromTx(ptx.UnsignedTx)
	if err != nil {
		if errors.Is(err, extension.ErrExtensionNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return getAssetsDenominations(ext.GetAssetPacket(), ptx.UnsignedTx.TxID())
}

func getAssetsDenominations(
	packet asset.Packet,
	txid string,
) (map[uint32][]domain.AssetDenomination, error) {
	assetDenominations := make(map[uint32][]domain.AssetDenomination)
	for grpIndex, ast := range packet {
		for _, out := range ast.Outputs {
			var assetId string
			// In case of issuance, the asset id is empty and we derive it from the txid and vout
			if ast.AssetId == nil {
				id, err := asset.NewAssetId(txid, uint16(grpIndex))
				if err != nil {
					return nil, fmt.Errorf("failed to compute asset id: %s", err)
				}
				assetId = id.String()
			} else {
				assetId = ast.AssetId.String()
			}
			assetDenominations[uint32(out.Vout)] = append(
				assetDenominations[uint32(out.Vout)], domain.AssetDenomination{
					AssetId: assetId,
					Amount:  out.Amount,
				},
			)
		}
	}
	return assetDenominations, nil
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
				return false, fmt.Errorf(
					"missing nonce for cosigner key %s and txid %s", keyStr, txid,
				)
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
) (*ports.BlockTimestamp, error) {
	network, err := wallet.GetNetwork(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get network, cannot wait for confirmation")
		return nil, err
	}

	tickerInterval := mainnetTickerInterval
	if network.Name == arklib.BitcoinRegTest.Name {
		tickerInterval = regtestTickerInterval
	}
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			confirmed, blockTimestamp, err := wallet.IsTransactionConfirmed(ctx, txid)
			if confirmed && err == nil {
				log.Debugf(
					"tx %s confirmed at block height %d, block time %d",
					txid,
					blockTimestamp.Height,
					blockTimestamp.Time,
				)
				return blockTimestamp, nil
			}
			if err != nil {
				return nil, err
			}
		}
	}
}

// resolveMinAmounts defaults negative min amounts to the dust limit.
// vtxoMinAmount uses negative values as a sentinel for "unset" (sub-dust
// offchain VTXOs are intentionally supported via OP_RETURN scripts).
// utxoMinAmount is always clamped to at least dust.
func resolveMinAmounts(
	vtxoMinAmount, utxoMinAmount, dustAmount int64,
) (int64, int64) {
	if vtxoMinAmount < 0 {
		vtxoMinAmount = dustAmount
	}
	if utxoMinAmount < dustAmount {
		utxoMinAmount = dustAmount
	}
	return vtxoMinAmount, utxoMinAmount
}

// validateTimeRange validates time range values. A zero value means unbounded and is allowed.
func validateTimeRange(after, before int64) error {
	if after < 0 || before < 0 {
		return fmt.Errorf("after and before must be greater than or equal to 0")
	}
	if before > 0 && after > 0 && before <= after {
		return fmt.Errorf("before must be greater than after")
	}
	return nil
}

func computeWeight(tx *wire.MsgTx) uint64 {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize()
	return uint64((baseSize * 3) + totalSize)
}

// calculateCollectedFees computes the total fees (sats) collected by the coordinator for a given round.
func calculateCollectedFees(round *domain.Round, boardingInputAmount uint64) uint64 {
	totalIn := boardingInputAmount
	totalOut := uint64(0)
	for _, intent := range round.Intents {
		totalIn += intent.TotalInputAmount()
		totalOut += intent.TotalOutputAmount()
	}
	if totalOut >= totalIn {
		return 0
	}
	return totalIn - totalOut
}

// calculateBoardingInputAmount computes the total amount (sats) of boarding inputs in a PSBT.
func calculateBoardingInputAmount(ptx *psbt.Packet) uint64 {
	boardingInputAmount := uint64(0)
	for _, input := range ptx.Inputs {
		if isBoardingInput(input) {
			boardingInputAmount += uint64(input.WitnessUtxo.Value)
		}
	}
	return boardingInputAmount
}

// isBoardingInput reports whether a PSBT input is a boarding input, i.e. an
// onchain UTXO spent through a taproot script-path leaf.
//
// TODO: fragile — this assumes only boarding inputs carry a TaprootLeafScript.
// It may misclassify inputs if arkd-wallet starts populating TaprootLeafScript
// for other input types in the future.
func isBoardingInput(in psbt.PInput) bool {
	return in.WitnessUtxo != nil && len(in.TaprootLeafScript) > 0
}

// checkSettlementExpiryGap rejects a vtxo that does not have at least gap of
// remaining life. A vtxo settled with almost no life left leaves the operator no
// forfeit-enforcement window, which is the risk class the setting exists to
// exclude. Mirrors the direction of checkUnrolledVtxoExpiry.
// A gap of 0 disables the check.
func checkSettlementExpiryGap(expiresAt, now time.Time, gap time.Duration) error {
	if gap <= 0 {
		return nil
	}
	if expiresAt.Before(now.Add(gap)) {
		return fmt.Errorf("vtxo expires too soon (within %s)", gap)
	}
	return nil
}

// epochMaturity returns when an epoch batch output becomes sweepable.
//
// The hybrid sweep leaf requires both an absolute date and a relative delay since
// the output appeared, so an untouched node — whose parent confirmed long before
// the boundary — matures at the epoch date, and every batch in the epoch can be
// swept by one transaction. A node created by a mid-flight unilateral unroll
// matures a grace period after it appeared, which hands the exiting user that
// grace at each tree level without any per-level script variation, and bounds
// griefing at depth*grace past the date rather than depth*expiry.
func epochMaturity(epochDate, parentConfirmedAt, grace int64) int64 {
	if withGrace := parentConfirmedAt + grace; withGrace > epochDate {
		return withGrace
	}
	return epochDate
}

// logEpochSchedule reports where the operator sits on the boundary grid at
// startup.
//
// The anchor is only a phase offset, so the factory default is a fixed date in
// the past and stays correct forever - but an operator reading it back has no
// way to tell a deliberate anchor from a stale one, and no way to see which
// dates their batches will actually land on. Print the derived values instead of
// making them work it out.
func logEpochSchedule(settings domain.Settings) {
	if !settings.EpochExpiryEnabled {
		return
	}

	sched := settings.EpochSchedule()
	now := time.Now()

	next := sched.BoundaryAfter(now)
	if next.IsZero() {
		log.Errorf(
			"epoch expiry is enabled but the schedule anchored at %s yields no "+
				"representable boundary", sched.Anchor.UTC(),
		)
		return
	}

	log.Infof(
		"epoch expiry enabled: epochs of %s anchored at %s; batches created now "+
			"expire at %s (in %s); renewals admitted from %s, settles until %s",
		sched.Length, sched.Anchor.UTC(), next.UTC(), next.Sub(now).Truncate(time.Second),
		next.Add(-sched.RolloverWindow).UTC(), next.Add(-sched.SettlementCutoff).UTC(),
	)
}

// epochUnrollGrace reads the unroll grace a batch actually committed to from its
// own tree.
//
// The grace is baked into every sweep leaf at build time, so reading it back from
// the tree is the only value that can match the onchain CSV constraint. Taking it
// from live settings instead would reschedule an existing batch's sweep whenever
// an operator changed the setting — the same reason the epoch date is pinned on
// the round rather than recomputed. The sweep execution path already sources it
// this way, via GetSweepableBatchOutputs.
func epochUnrollGrace(vtxoTree tree.FlatTxTree) (arklib.RelativeLocktime, error) {
	var grace arklib.RelativeLocktime

	rootTxid := vtxoTree.RootTxid()
	for _, node := range vtxoTree {
		if node.Txid != rootTxid {
			continue
		}

		ptx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			return grace, fmt.Errorf("failed to parse tree root %s: %w", rootTxid, err)
		}

		expiries, err := txutils.GetArkPsbtFields(ptx, 0, txutils.VtxoTreeExpiryField)
		if err != nil {
			return grace, err
		}
		if len(expiries) <= 0 {
			return grace, fmt.Errorf("tree root %s carries no expiry field", rootTxid)
		}
		return expiries[0], nil
	}

	return grace, fmt.Errorf("root %s not found in tree", rootTxid)
}

// checkEpochAdmission applies the settlement admission window to a vtxo input.
//
// Swept vtxos are exempt: the operator already holds those funds onchain, no
// forfeit is needed, and settling one is exactly how recovery works.
//
// Vtxos from pre-cutover batches are exempt too. They expire on their own
// relative schedule, so the rollover bound would reject renewing one for as long
// as it has more life left than the window - which on the day the flag is
// flipped is every legacy vtxo in existence, and renewal is how they migrate onto
// the epoch schedule in the first place.
func checkEpochAdmission(
	sched domain.EpochSchedule, vtxo domain.Vtxo, now time.Time, isRenewal bool,
) error {
	if vtxo.Swept {
		return nil
	}
	expiry := arklib.AbsoluteLocktime(vtxo.ExpiresAt)
	if !sched.Governs(expiry) {
		return nil
	}
	return sched.AdmitsSettle(expiry, now, isRenewal)
}

// intentHasOffchainOutput reports whether an intent produces at least one vtxo,
// which is what makes it a renewal rather than a pure exit.
//
// Extension outputs carry protocol data rather than value, so they do not count.
// Every other output is offchain unless the intent listed its index as onchain.
func intentHasOffchainOutput(outputs []*wire.TxOut, onchainOutputIndexes []int) bool {
	for i, out := range outputs {
		if extension.IsExtension(out.PkScript) {
			continue
		}
		if slices.Contains(onchainOutputIndexes, i) {
			continue
		}
		return true
	}
	return false
}
