package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/bip322"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	log "github.com/sirupsen/logrus"
)

type service struct {
	// services
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scanner     ports.BlockchainScanner
	cache       ports.LiveStore
	sweeper     *sweeper

	// config
	network                   arklib.Network
	signerPubkey              *btcec.PublicKey
	vtxoTreeExpiry            arklib.RelativeLocktime
	roundInterval             time.Duration
	unilateralExitDelay       arklib.RelativeLocktime
	boardingExitDelay         arklib.RelativeLocktime
	roundMinParticipantsCount int64
	roundMaxParticipantsCount int64
	utxoMaxAmount             int64
	utxoMinAmount             int64
	vtxoMaxAmount             int64
	vtxoMinSettlementAmount   int64
	vtxoMinOffchainTxAmount   int64
	allowCSVBlockType         bool

	// TODO: derive the key pair used for the musig2 signing session from wallet.
	operatorPrvkey *btcec.PrivateKey
	operatorPubkey *btcec.PublicKey

	// channels
	eventsCh                 chan []domain.Event
	transactionEventsCh      chan TransactionEvent
	forfeitsBoardingSigsChan chan struct{}
	indexerTxEventsCh        chan TransactionEvent

	// stop and round-execution go routine handlers
	stop func()
	ctx  context.Context
	wg   *sync.WaitGroup
}

func NewService(
	wallet ports.WalletService, repoManager ports.RepoManager, builder ports.TxBuilder,
	scanner ports.BlockchainScanner, scheduler ports.SchedulerService, cache ports.LiveStore,
	vtxoTreeExpiry, unilateralExitDelay, boardingExitDelay arklib.RelativeLocktime,
	roundInterval, roundMinParticipantsCount, roundMaxParticipantsCount,
	utxoMaxAmount, utxoMinAmount, vtxoMaxAmount, vtxoMinAmount int64,
	network arklib.Network, allowCSVBlockType bool, noteUriPrefix string,
	marketHourStartTime, marketHourEndTime time.Time,
	marketHourPeriod, marketHourRoundInterval time.Duration,
) (Service, error) {
	ctx := context.Background()

	signerPubkey, err := wallet.GetPubkey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	// Try to load market hours from DB first
	marketHour, err := repoManager.MarketHourRepo().Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get market hours from db: %w", err)
	}

	if marketHour == nil && !marketHourStartTime.IsZero() && !marketHourEndTime.IsZero() &&
		int(marketHourPeriod) > 0 && marketHourRoundInterval > 0 {
		marketHour = domain.NewMarketHour(
			marketHourStartTime, marketHourEndTime, marketHourPeriod, marketHourRoundInterval,
		)
		if err := repoManager.MarketHourRepo().Upsert(ctx, *marketHour); err != nil {
			return nil, fmt.Errorf("failed to upsert initial market hours to db: %w", err)
		}
	}

	operatorSigningKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %s", err)
	}

	dustAmount, err := wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dust amount: %s", err)
	}
	var vtxoMinSettlementAmount, vtxoMinOffchainTxAmount = vtxoMinAmount, vtxoMinAmount
	if vtxoMinSettlementAmount < int64(dustAmount) {
		vtxoMinSettlementAmount = int64(dustAmount)
	}
	if vtxoMinOffchainTxAmount == -1 {
		vtxoMinOffchainTxAmount = int64(dustAmount)
	}
	if utxoMinAmount < int64(dustAmount) {
		utxoMinAmount = int64(dustAmount)
	}

	ctx, cancel := context.WithCancel(ctx)

	svc := &service{
		network:             network,
		signerPubkey:        signerPubkey,
		vtxoTreeExpiry:      vtxoTreeExpiry,
		roundInterval:       time.Duration(roundInterval) * time.Second,
		unilateralExitDelay: unilateralExitDelay,
		allowCSVBlockType:   allowCSVBlockType,
		wallet:              wallet,
		repoManager:         repoManager,
		builder:             builder,
		cache:               cache,
		scanner:             scanner,
		sweeper: newSweeper(
			wallet, repoManager, builder, scheduler, noteUriPrefix,
		),
		eventsCh:                  make(chan []domain.Event),
		transactionEventsCh:       make(chan TransactionEvent),
		boardingExitDelay:         boardingExitDelay,
		operatorPrvkey:            operatorSigningKey,
		operatorPubkey:            operatorSigningKey.PubKey(),
		forfeitsBoardingSigsChan:  make(chan struct{}, 1),
		roundMinParticipantsCount: roundMinParticipantsCount,
		roundMaxParticipantsCount: roundMaxParticipantsCount,
		utxoMaxAmount:             utxoMaxAmount,
		utxoMinAmount:             utxoMinAmount,
		vtxoMaxAmount:             vtxoMaxAmount,
		vtxoMinSettlementAmount:   vtxoMinSettlementAmount,
		vtxoMinOffchainTxAmount:   vtxoMinOffchainTxAmount,
		indexerTxEventsCh:         make(chan TransactionEvent),
		stop:                      cancel,
		ctx:                       ctx,
		wg:                        &sync.WaitGroup{},
	}

	repoManager.Events().RegisterEventsHandler(
		domain.RoundTopic, func(events []domain.Event) {
			round := domain.NewRoundFromEvents(events)

			go svc.propagateEvents(round)

			if !round.IsEnded() {
				return
			}

			spentVtxos := svc.getSpentVtxos(round.Intents)
			newVtxos := getNewVtxosFromRound(round)

			go func() {
				svc.transactionEventsCh <- TransactionEvent{
					TxData:         TxData{Tx: round.CommitmentTx, Txid: round.CommitmentTxid},
					Type:           CommitmentTxType,
					SpentVtxos:     spentVtxos,
					SpendableVtxos: newVtxos,
				}
			}()
			go func() {
				svc.indexerTxEventsCh <- TransactionEvent{
					TxData:         TxData{Tx: round.CommitmentTx, Txid: round.CommitmentTxid},
					Type:           CommitmentTxType,
					SpentVtxos:     spentVtxos,
					SpendableVtxos: newVtxos,
				}
			}()

			go func() {
				if err := svc.startWatchingVtxos(newVtxos); err != nil {
					log.WithError(err).Warn("failed to start watching vtxos")
				}
			}()

			go svc.scheduleSweepBatchOutput(round)
		},
	)

	repoManager.Events().RegisterEventsHandler(
		domain.OffchainTxTopic, func(events []domain.Event) {
			offchainTx := domain.NewOffchainTxFromEvents(events)

			if !offchainTx.IsFinalized() {
				return
			}

			txid, spentVtxoKeys, newVtxos, err := decodeTx(*offchainTx)
			if err != nil {
				log.WithError(err).Warn("failed to decode offchain tx")
				return
			}

			spentVtxos, err := svc.repoManager.Vtxos().GetVtxos(context.Background(), spentVtxoKeys)
			if err != nil {
				log.WithError(err).Warn("failed to get spent vtxos")
				return
			}

			checkpointTxsByOutpoint := make(map[string]TxData)
			for txid, tx := range offchainTx.CheckpointTxs {
				// nolint
				ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
				checkpointTxsByOutpoint[ptx.UnsignedTx.TxIn[0].PreviousOutPoint.String()] = TxData{
					Tx: tx, Txid: txid,
				}
			}

			go func() {
				svc.transactionEventsCh <- TransactionEvent{
					TxData:         TxData{Txid: txid, Tx: offchainTx.ArkTx},
					Type:           ArkTxType,
					SpentVtxos:     spentVtxos,
					SpendableVtxos: newVtxos,
					CheckpointTxs:  checkpointTxsByOutpoint,
				}
			}()
			go func() {
				svc.indexerTxEventsCh <- TransactionEvent{
					TxData:         TxData{Txid: txid, Tx: offchainTx.ArkTx},
					Type:           ArkTxType,
					SpentVtxos:     spentVtxos,
					SpendableVtxos: newVtxos,
					CheckpointTxs:  checkpointTxsByOutpoint,
				}
			}()

			go func() {
				if err := svc.startWatchingVtxos(newVtxos); err != nil {
					log.WithError(err).Warn("failed to start watching vtxos")
				}
			}()
		},
	)

	if err := svc.restoreWatchingVtxos(); err != nil {
		return nil, fmt.Errorf("failed to restore watching vtxos: %s", err)
	}
	go svc.listenToScannerNotifications()
	return svc, nil
}

func (s *service) Start() error {
	log.Debug("starting sweeper service...")
	if err := s.sweeper.start(); err != nil {
		return err
	}

	log.Debug("starting app service...")
	s.wg.Add(1)
	go s.start()
	return nil
}

func (s *service) Stop() {
	ctx := context.Background()

	s.stop()
	s.wg.Wait()
	s.sweeper.stop()
	// nolint
	vtxos, _ := s.repoManager.Vtxos().GetAllSweepableVtxos(ctx)
	if len(vtxos) > 0 {
		s.stopWatchingVtxos(vtxos)
	}

	// nolint
	s.wallet.Lock(ctx)
	log.Debug("locked wallet")
	s.wallet.Close()
	log.Debug("closed connection to wallet")
	s.repoManager.Close()
	log.Debug("closed connection to db")
	close(s.eventsCh)
}

func (s *service) SubmitOffchainTx(
	ctx context.Context, unsignedCheckpointTxs []string, signedArkTx string,
) (signedCheckpointTxs []string, finalArkTx string, arkTxid string, err error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(signedArkTx), true)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse ark tx: %s", err)
	}
	txid := ptx.UnsignedTx.TxID()

	offchainTx := domain.NewOffchainTx()
	var changes []domain.Event

	defer func() {
		if err != nil {
			change := offchainTx.Fail(err)
			changes = append(changes, change)
		}

		if err := s.repoManager.Events().Save(
			ctx, domain.OffchainTxTopic, txid, changes,
		); err != nil {
			log.WithError(err).Fatal("failed to save offchain tx events")
		}
	}()

	vtxoRepo := s.repoManager.Vtxos()

	ins := make([]offchain.VtxoInput, 0)
	checkpointTxs := make(map[string]string)
	checkpointPsbts := make(map[string]*psbt.Packet) // txid -> psbt
	spentVtxoKeys := make([]domain.Outpoint, 0)
	checkpointTxsByVtxoKey := make(map[domain.Outpoint]string)
	for _, tx := range unsignedCheckpointTxs {
		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse checkpoint tx: %s", err)
		}

		if len(checkpointPtx.UnsignedTx.TxIn) < 1 {
			return nil, "", "", fmt.Errorf(
				"invalid checkpoint tx %s", checkpointPtx.UnsignedTx.TxID(),
			)
		}

		vtxoKey := domain.Outpoint{
			Txid: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		}
		checkpointTxs[checkpointPtx.UnsignedTx.TxID()] = tx
		checkpointPsbts[checkpointPtx.UnsignedTx.TxID()] = checkpointPtx
		checkpointTxsByVtxoKey[vtxoKey] = checkpointPtx.UnsignedTx.TxID()
		spentVtxoKeys = append(spentVtxoKeys, vtxoKey)
	}

	event, err := offchainTx.Request(txid, signedArkTx, checkpointTxs)
	if err != nil {
		return nil, "", "", err
	}
	changes = []domain.Event{event}

	// get all the vtxos inputs
	spentVtxos, err := vtxoRepo.GetVtxos(ctx, spentVtxoKeys)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get vtxos: %s", err)
	}

	if len(spentVtxos) != len(spentVtxoKeys) {
		return nil, "", "", fmt.Errorf("some vtxos not found")
	}

	if exists, vtxo := s.cache.Intents().IncludesAny(spentVtxoKeys); exists {
		return nil, "", "", fmt.Errorf("vtxo %s is already registered for next round", vtxo)
	}

	indexedSpentVtxos := make(map[domain.Outpoint]domain.Vtxo)
	commitmentTxsByCheckpointTxid := make(map[string]string)
	expiration := int64(math.MaxInt64)
	rootCommitmentTxid := ""
	for _, vtxo := range spentVtxos {
		indexedSpentVtxos[vtxo.Outpoint] = vtxo
		commitmentTxsByCheckpointTxid[checkpointTxsByVtxoKey[vtxo.Outpoint]] = vtxo.RootCommitmentTxid
		if vtxo.ExpiresAt < expiration {
			rootCommitmentTxid = vtxo.RootCommitmentTxid
			expiration = vtxo.ExpiresAt
		}
	}

	for _, checkpointPsbt := range checkpointPsbts {
		input := checkpointPsbt.Inputs[0]

		if input.WitnessUtxo == nil {
			return nil, "", "", fmt.Errorf("missing witness utxo")
		}

		if len(input.TaprootLeafScript) == 0 {
			return nil, "", "", fmt.Errorf("missing tapscript leaf")
		}
		if len(input.TaprootLeafScript) != 1 {
			return nil, "", "", fmt.Errorf("expected exactly one taproot leaf script")
		}

		tapscripts, err := txutils.GetTaprootTree(input)
		if err != nil {
			return nil, "", "", fmt.Errorf("missing tapscripts: %s", err)
		}

		spendingTapscript := input.TaprootLeafScript[0]

		if spendingTapscript == nil {
			return nil, "", "", fmt.Errorf("no matching tapscript found")
		}

		outpoint := domain.Outpoint{
			Txid: checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		}

		vtxo, exists := indexedSpentVtxos[outpoint]
		if !exists {
			return nil, "", "", fmt.Errorf("vtxo not found")
		}

		// make sure we don't use the same vtxo twice
		delete(indexedSpentVtxos, outpoint)

		if vtxo.Spent {
			return nil, "", "", fmt.Errorf("vtxo already spent")
		}

		if vtxo.Unrolled {
			return nil, "", "", fmt.Errorf("vtxo already unrolled")
		}

		if vtxo.Swept {
			return nil, "", "", fmt.Errorf("vtxo already swept")
		}

		if vtxo.IsNote() {
			return nil, "", "", fmt.Errorf(
				"vtxo '%s' is a note, can't be spent in ark transaction", vtxo.Outpoint.String(),
			)
		}

		vtxoScript, err := script.ParseVtxoScript(tapscripts)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse vtxo script: %s", err)
		}

		// validate the vtxo script
		if err := vtxoScript.Validate(
			s.signerPubkey, s.unilateralExitDelay, s.allowCSVBlockType,
		); err != nil {
			return nil, "", "", fmt.Errorf("invalid vtxo script: %s", err)
		}

		witnessUtxoScript := input.WitnessUtxo.PkScript

		tapKeyFromTapscripts, _, err := vtxoScript.TapTree()
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to get taproot key from vtxo script: %s", err)
		}

		if vtxo.PubKey != hex.EncodeToString(schnorr.SerializePubKey(tapKeyFromTapscripts)) {
			return nil, "", "", fmt.Errorf("vtxo pubkey mismatch")
		}

		pkScriptFromTapscripts, err := script.P2TRScript(tapKeyFromTapscripts)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to get pkscript from taproot key: %s", err)
		}

		if !bytes.Equal(witnessUtxoScript, pkScriptFromTapscripts) {
			return nil, "", "", fmt.Errorf("witness utxo script mismatch")
		}

		vtxoPubkeyBuf, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode vtxo pubkey: %s", err)
		}

		vtxoPubkey, err := schnorr.ParsePubKey(vtxoPubkeyBuf)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse vtxo pubkey: %s", err)
		}

		// verify witness utxo
		pkscript, err := script.P2TRScript(vtxoPubkey)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to get pkscript: %s", err)
		}

		if !bytes.Equal(input.WitnessUtxo.PkScript, pkscript) {
			return nil, "", "", fmt.Errorf("witness utxo script mismatch")
		}

		if input.WitnessUtxo.Value != int64(vtxo.Amount) {
			return nil, "", "", fmt.Errorf("witness utxo value mismatch")
		}

		// verify forfeit closure script
		closure, err := script.DecodeClosure(spendingTapscript.Script)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode forfeit closure: %s", err)
		}

		var locktime *arklib.AbsoluteLocktime
		switch c := closure.(type) {
		case *script.CLTVMultisigClosure:
			locktime = &c.Locktime
		case *script.MultisigClosure, *script.ConditionMultisigClosure:
		default:
			return nil, "", "", fmt.Errorf(
				"invalid input forfeit closure script %x", spendingTapscript.Script,
			)
		}

		if locktime != nil {
			blocktimestamp, err := s.wallet.GetCurrentBlockTime(ctx)
			if err != nil {
				return nil, "", "", fmt.Errorf("failed to get current block time: %s", err)
			}
			if !locktime.IsSeconds() {
				if *locktime > arklib.AbsoluteLocktime(blocktimestamp.Height) {
					return nil, "", "", fmt.Errorf(
						"forfeit closure script is locked, %d > %d (block time)",
						*locktime, blocktimestamp.Time,
					)
				}
			} else {
				if *locktime > arklib.AbsoluteLocktime(blocktimestamp.Time) {
					return nil, "", "", fmt.Errorf(
						"forfeit closure script is locked, %d > %d (seconds)",
						*locktime, blocktimestamp.Time,
					)
				}
			}
		}

		ctrlBlock, err := txscript.ParseControlBlock(spendingTapscript.ControlBlock)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse control block: %s", err)
		}

		var checkpointTapscript *waddrmgr.Tapscript

		checkpointTxid := checkpointPsbt.UnsignedTx.TxID()
		checkpointVout := uint32(0) // always 1 output in the checkpoint tx

		// search for the checkpoint input in the ark tx
		for inputIndex, input := range ptx.UnsignedTx.TxIn {
			if input.PreviousOutPoint.Hash.String() == checkpointTxid &&
				input.PreviousOutPoint.Index == checkpointVout {
				if len(ptx.Inputs[inputIndex].TaprootLeafScript) == 0 {
					return nil, "", "", fmt.Errorf(
						"missing tapscript leaf in ark tx input #%d", inputIndex,
					)
				}

				tapleafScript := ptx.Inputs[inputIndex].TaprootLeafScript[0]
				ctrlBlock, err := txscript.ParseControlBlock(tapleafScript.ControlBlock)
				if err != nil {
					return nil, "", "", fmt.Errorf("failed to parse control block: %s", err)
				}

				checkpointTapscript = &waddrmgr.Tapscript{
					ControlBlock:   ctrlBlock,
					RevealedScript: tapleafScript.Script,
				}
				break
			}
		}

		if checkpointTapscript == nil {
			return nil, "", "", fmt.Errorf("checkpoint tapscript not found")
		}

		ins = append(ins, offchain.VtxoInput{
			Outpoint: &checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint,
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: spendingTapscript.Script,
			},
			CheckpointTapscript: checkpointTapscript,
			RevealedTapscripts:  tapscripts,
			Amount:              int64(vtxo.Amount),
		})
	}

	// iterate over the ark tx inputs and verify that the user signed a collaborative path
	signerXOnlyPubkey := schnorr.SerializePubKey(s.signerPubkey)
	for _, input := range ptx.Inputs {
		if len(input.TaprootScriptSpendSig) == 0 {
			return nil, "", "", fmt.Errorf("missing tapscript spend sig")
		}

		hasSig := false

		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, signerXOnlyPubkey) {
				if _, err := schnorr.ParsePubKey(sig.XOnlyPubKey); err != nil {
					return nil, "", "", fmt.Errorf("failed to parse signer pubkey: %s", err)
				}
				hasSig = true
				break
			}
		}

		if !hasSig {
			return nil, "", "", fmt.Errorf("ark tx is not signed")
		}
	}

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get dust amount: %s", err)
	}

	outputs := make([]*wire.TxOut, 0) // outputs excluding the anchor
	foundAnchor := false
	foundOpReturn := false

	for outIndex, out := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
			if foundAnchor {
				return nil, "", "", fmt.Errorf("invalid ark tx: multiple anchor outputs")
			}
			foundAnchor = true
			continue
		}

		// verify we don't have multiple OP_RETURN outputs
		if bytes.HasPrefix(out.PkScript, []byte{txscript.OP_RETURN}) {
			if foundOpReturn {
				return nil, "", "", fmt.Errorf("invalid tx, multiple op return outputs")
			}
			foundOpReturn = true
		}

		if s.vtxoMaxAmount >= 0 {
			if out.Value > s.vtxoMaxAmount {
				return nil, "", "", fmt.Errorf(
					"output #%d amount is higher than max vtxo amount: %d",
					outIndex, s.vtxoMaxAmount,
				)
			}
		}
		if out.Value < s.vtxoMinOffchainTxAmount {
			return nil, "", "", fmt.Errorf(
				"output #%d amount is lower than min vtxo amount: %d",
				outIndex, s.vtxoMinOffchainTxAmount,
			)
		}

		if out.Value < int64(dust) {
			// if the output is below dust limit, it must be using OP_RETURN-style vtxo pkscript
			if !script.IsSubDustScript(out.PkScript) {
				return nil, "", "", fmt.Errorf(
					"output #%d amount is below dust but is not using OP_RETURN output script",
					outIndex,
				)
			}
		}

		outputs = append(outputs, out)
	}

	if !foundAnchor {
		return nil, "", "", fmt.Errorf("invalid ark tx: missing anchor output")
	}

	// recompute all txs (checkpoint txs + ark tx)
	rebuiltArkTx, rebuiltCheckpointTxs, err := offchain.BuildTxs(
		ins, outputs,
		&script.CSVMultisigClosure{
			Locktime: s.unilateralExitDelay,
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{s.signerPubkey},
			},
		},
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to rebuild ark and/or checkpoint tx: %s", err)
	}

	// verify the checkpoints txs integrity
	if len(rebuiltCheckpointTxs) != len(checkpointPsbts) {
		return nil, "", "", fmt.Errorf(
			"invalid number of checkpoint txs, expected %d got %d",
			len(rebuiltCheckpointTxs), len(checkpointPsbts),
		)
	}

	for _, rebuiltCheckpointTx := range rebuiltCheckpointTxs {
		rebuiltTxid := rebuiltCheckpointTx.UnsignedTx.TxID()
		if _, ok := checkpointPsbts[rebuiltTxid]; !ok {
			return nil, "", "", fmt.Errorf("invalid checkpoint txs: %s not found", rebuiltTxid)
		}
	}

	// verify the ark tx integrity
	rebuiltTxid := rebuiltArkTx.UnsignedTx.TxID()
	if rebuiltTxid != txid {
		return nil, "", "", fmt.Errorf(
			"invalid ark tx: epxected txid %s got %s", rebuiltTxid, txid,
		)
	}

	// verify the tapscript signatures
	if valid, _, err := s.builder.VerifyTapscriptPartialSigs(signedArkTx); err != nil || !valid {
		return nil, "", "", fmt.Errorf("invalid ark tx signature(s): %s", err)
	}

	// sign the ark tx
	fullySignedArkTx, err := s.wallet.SignTransactionTapscript(ctx, signedArkTx, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to sign ark tx: %s", err)
	}

	signedCheckpointTxsMap := make(map[string]string)
	// sign the checkpoint txs
	for _, rebuiltCheckpointTx := range rebuiltCheckpointTxs {
		unsignedCheckpointTx, err := rebuiltCheckpointTx.B64Encode()
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to encode checkpoint tx: %s", err)
		}
		signedCheckpointTx, err := s.wallet.SignTransactionTapscript(ctx, unsignedCheckpointTx, nil)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to sign checkpoint tx: %s", err)
		}
		signedCheckpointTxsMap[rebuiltCheckpointTx.UnsignedTx.TxID()] = signedCheckpointTx
	}

	change, err := offchainTx.Accept(
		fullySignedArkTx, signedCheckpointTxsMap,
		commitmentTxsByCheckpointTxid, rootCommitmentTxid, expiration,
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to accept offchain tx: %s", err)
	}
	changes = append(changes, change)
	s.cache.OffchainTxs().Add(*offchainTx)

	finalArkTx = fullySignedArkTx
	signedCheckpointTxs = make([]string, 0, len(signedCheckpointTxsMap))
	for _, tx := range signedCheckpointTxsMap {
		signedCheckpointTxs = append(signedCheckpointTxs, tx)
	}
	arkTxid = txid

	return
}

func (s *service) FinalizeOffchainTx(
	ctx context.Context, txid string, finalCheckpointTxs []string,
) error {
	var (
		changes []domain.Event
		err     error
	)

	offchainTx, exists := s.cache.OffchainTxs().Get(txid)
	if !exists {
		err = fmt.Errorf("offchain tx: %v not found", txid)
		return err
	}

	defer func() {
		if err != nil {
			change := offchainTx.Fail(err)
			changes = append(changes, change)
		}

		if err = s.repoManager.Events().Save(
			ctx, domain.OffchainTxTopic, txid, changes,
		); err != nil {
			log.WithError(err).Fatal("failed to save offchain tx events")
		}
	}()

	finalCheckpointTxsMap := make(map[string]string)
	for _, checkpoint := range finalCheckpointTxs {
		// verify the tapscript signatures
		valid, checkpointTxid, err := s.builder.VerifyTapscriptPartialSigs(checkpoint)
		if err != nil || !valid {
			return fmt.Errorf("invalid tx signature: %s", err)
		}

		finalCheckpointTxsMap[checkpointTxid] = checkpoint
	}

	event, err := offchainTx.Finalize(finalCheckpointTxsMap)
	if err != nil {
		return err
	}
	changes = []domain.Event{event}
	s.cache.OffchainTxs().Remove(txid)

	return nil
}

func (s *service) RegisterIntent(
	ctx context.Context, proof bip322.Signature, message bip322.IntentMessage,
) (string, error) {
	// the vtxo to swap for new ones, require forfeit transactions
	vtxoInputs := make([]domain.Vtxo, 0)
	// the boarding utxos to add in the commitment tx
	boardingInputs := make([]ports.BoardingInput, 0)
	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex

	outpoints := proof.GetOutpoints()
	if len(outpoints) != len(message.InputTapTrees) {
		return "", fmt.Errorf("number of outpoints and taptrees must match")
	}

	if message.ValidAt > 0 {
		validAt := time.Unix(message.ValidAt, 0)
		if time.Now().Before(validAt) {
			return "", fmt.Errorf("proof of ownership is not valid yet")
		}
	}

	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if time.Now().After(expireAt) {
			return "", fmt.Errorf("proof of ownership expired")
		}
	}

	// we need the prevout to verify the BIP0322 signature
	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for i, outpoint := range outpoints {
		tapTree := message.InputTapTrees[i]
		tapTreeBytes, err := hex.DecodeString(tapTree)
		if err != nil {
			return "", fmt.Errorf("failed to decode taptree: %s", err)
		}

		tapscripts, err := txutils.DecodeTapTree(tapTreeBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decode taptree: %s", err)
		}

		vtxoOutpoint := domain.Outpoint{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		if s.cache.OffchainTxs().Includes(vtxoOutpoint) {
			return "", fmt.Errorf("vtxo %s is currently being spent", vtxoOutpoint.String())
		}

		now := time.Now()
		locktime, disabled := arklib.BIP68DecodeSequence(proof.TxIn[i+1].Sequence)

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxoOutpoint})
		if err != nil || len(vtxosResult) == 0 {
			// vtxo not found in db, check if it exists on-chain
			if _, ok := boardingTxs[vtxoOutpoint.Txid]; !ok {
				tx, err := s.validateBoardingInput(
					ctx, vtxoOutpoint, tapscripts, now, locktime, disabled,
				)
				if err != nil {
					return "", err
				}

				boardingTxs[vtxoOutpoint.Txid] = *tx
			}

			tx := boardingTxs[vtxoOutpoint.Txid]
			prevouts[outpoint] = tx.TxOut[vtxoOutpoint.VOut]
			input := ports.Input{
				Outpoint:   vtxoOutpoint,
				Tapscripts: tapscripts,
			}
			boardingInput, err := newBoardingInput(
				tx, input, s.signerPubkey, s.boardingExitDelay, s.allowCSVBlockType,
			)
			if err != nil {
				return "", err
			}

			boardingInputs = append(boardingInputs, *boardingInput)
			continue
		}

		vtxo := vtxosResult[0]
		if vtxo.Spent {
			return "", fmt.Errorf("input %s already spent", vtxo.Outpoint.String())
		}

		if vtxo.Unrolled {
			return "", fmt.Errorf("input %s already unrolled", vtxo.Outpoint.String())
		}

		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode script pubkey: %s", err)
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse pubkey: %s", err)
		}

		pkScript, err := script.P2TRScript(pubkey)
		if err != nil {
			return "", fmt.Errorf("failed to create p2tr script: %s", err)
		}

		prevouts[outpoint] = &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: pkScript,
		}

		// Only in case the vtxo is a note we skip the validation of its script and the csv delay.
		if !vtxo.IsNote() {
			vtxoTapKey, err := vtxo.TapKey()
			if err != nil {
				return "", fmt.Errorf("failed to get taproot key: %s", err)
			}
			if err := s.validateVtxoInput(
				tapscripts, vtxoTapKey, vtxo.CreatedAt, now, locktime, disabled,
			); err != nil {
				return "", err
			}
		}

		vtxoInputs = append(vtxoInputs, vtxo)
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)

	encodedMessage, err := message.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode message: %s", err)
	}
	encodedProof, err := proof.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode proof: %s", err)
	}

	if err := proof.Verify(encodedMessage, prevoutFetcher); err != nil {
		return "", fmt.Errorf("invalid BIP0322 proof of funds: %s", err)
	}

	intent, err := domain.NewIntent(encodedProof, encodedMessage, vtxoInputs)
	if err != nil {
		return "", err
	}

	if proof.ContainsOutputs() {
		hasOffChainReceiver := false
		receivers := make([]domain.Receiver, 0)

		for outputIndex, output := range proof.TxOut {
			amount := uint64(output.Value)
			rcv := domain.Receiver{
				Amount: amount,
			}

			isOnchain := false
			for _, index := range message.OnchainOutputIndexes {
				if index == outputIndex {
					isOnchain = true
					break
				}
			}

			if isOnchain {
				if s.utxoMaxAmount >= 0 {
					if amount > uint64(s.utxoMaxAmount) {
						return "", fmt.Errorf(
							"receiver amount is higher than max utxo amount: %d", s.utxoMaxAmount,
						)
					}
				}
				if amount < uint64(s.utxoMinAmount) {
					return "", fmt.Errorf(
						"receiver amount is lower than min utxo amount: %d", s.utxoMinAmount,
					)
				}

				_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, s.chainParams())
				if err != nil {
					return "", fmt.Errorf("failed to extract pkscript addrs: %s", err)
				}

				if len(addrs) == 0 {
					return "", fmt.Errorf("no onchain address found")
				}

				rcv.OnchainAddress = addrs[0].EncodeAddress()
			} else {
				if s.vtxoMaxAmount >= 0 {
					if amount > uint64(s.vtxoMaxAmount) {
						return "", fmt.Errorf(
							"receiver amount is higher than max vtxo amount: %d", s.vtxoMaxAmount,
						)
					}
				}
				if amount < uint64(s.vtxoMinSettlementAmount) {
					return "", fmt.Errorf(
						"receiver amount is lower than min vtxo amount: %d", s.vtxoMinSettlementAmount,
					)
				}

				hasOffChainReceiver = true
				rcv.PubKey = hex.EncodeToString(output.PkScript[2:])
			}

			receivers = append(receivers, rcv)
		}

		if hasOffChainReceiver {
			if len(message.CosignersPublicKeys) == 0 {
				return "", fmt.Errorf("musig2 data is required for offchain receivers")
			}

			// check if the operator pubkey has been set as cosigner
			operatorPubkeyHex := hex.EncodeToString(s.operatorPubkey.SerializeCompressed())
			for _, pubkey := range message.CosignersPublicKeys {
				if pubkey == operatorPubkeyHex {
					return "", fmt.Errorf("invalid cosigner pubkeys: %x is used by us", pubkey)
				}
			}
		}

		if err := intent.AddReceivers(receivers); err != nil {
			return "", err
		}
	}

	if err := s.cache.Intents().Push(
		*intent, boardingInputs, message.CosignersPublicKeys,
	); err != nil {
		return "", err
	}

	return intent.Id, nil
}

func (s *service) ConfirmRegistration(ctx context.Context, intentId string) error {
	if !s.cache.ConfirmationSessions().Initialized() {
		return fmt.Errorf("confirmation session not started")
	}

	return s.cache.ConfirmationSessions().Confirm(intentId)
}

func (s *service) SubmitForfeitTxs(ctx context.Context, forfeitTxs []string) error {
	if len(forfeitTxs) <= 0 {
		return nil
	}

	if err := s.cache.ForfeitTxs().Sign(forfeitTxs); err != nil {
		return err
	}

	go s.checkForfeitsAndBoardingSigsSent()

	return nil
}

func (s *service) SignCommitmentTx(ctx context.Context, signedCommitmentTx string) error {
	numSignedInputs, err := s.builder.CountSignedTaprootInputs(signedCommitmentTx)
	if err != nil {
		return fmt.Errorf("failed to count number of signed boarding inputs: %s", err)
	}
	if numSignedInputs == 0 {
		return nil
	}

	var combineErr error
	if err := s.cache.CurrentRound().Upsert(func(r *domain.Round) *domain.Round {
		combined, err := s.builder.VerifyAndCombinePartialTx(r.CommitmentTx, signedCommitmentTx)
		if err != nil {
			combineErr = err
			return r
		}

		ur := *r
		ur.CommitmentTx = combined
		return &ur
	}); err != nil {
		return err
	}

	if combineErr != nil {
		return fmt.Errorf("failed to verify and combine partial tx: %w", combineErr)
	}

	go s.checkForfeitsAndBoardingSigsSent()

	return nil
}

func (s *service) GetEventsChannel(ctx context.Context) <-chan []domain.Event {
	return s.eventsCh
}

func (s *service) GetTxEventsChannel(ctx context.Context) <-chan TransactionEvent {
	return s.transactionEventsCh
}

// TODO remove this in v7
func (s *service) GetIndexerTxChannel(ctx context.Context) <-chan TransactionEvent {
	return s.indexerTxEventsCh
}

func (s *service) GetInfo(ctx context.Context) (*ServiceInfo, error) {
	signerPubkey := hex.EncodeToString(s.signerPubkey.SerializeCompressed())

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dust amount: %s", err)
	}

	forfeitAddr, err := s.wallet.GetForfeitAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get forfeit address: %s", err)
	}

	marketHourConfig, err := s.repoManager.MarketHourRepo().Get(ctx)
	if err != nil {
		return nil, err
	}

	var nextMarketHour *NextMarketHour
	if marketHourConfig != nil {
		marketHourNextStart, marketHourNextEnd := calcNextMarketHour(
			time.Now(), marketHourConfig.StartTime, marketHourConfig.EndTime,
			marketHourConfig.Period,
		)
		nextMarketHour = &NextMarketHour{
			StartTime:     marketHourNextStart,
			EndTime:       marketHourNextEnd,
			Period:        marketHourConfig.Period,
			RoundInterval: marketHourConfig.RoundInterval,
		}
	}

	return &ServiceInfo{
		SignerPubKey:        signerPubkey,
		VtxoTreeExpiry:      int64(s.vtxoTreeExpiry.Value),
		UnilateralExitDelay: int64(s.unilateralExitDelay.Value),
		BoardingExitDelay:   int64(s.boardingExitDelay.Value),
		RoundInterval:       int64(s.roundInterval.Seconds()),
		Network:             s.network.Name,
		Dust:                dust,
		ForfeitAddress:      forfeitAddr,
		NextMarketHour:      nextMarketHour,
		UtxoMinAmount:       s.utxoMinAmount,
		UtxoMaxAmount:       s.utxoMaxAmount,
		VtxoMinAmount:       s.vtxoMinSettlementAmount,
		VtxoMaxAmount:       s.vtxoMaxAmount,
	}, nil
}

// DeleteIntentsByProof deletes transaction intents matching the BIP322 proof.
func (s *service) DeleteIntentsByProof(
	ctx context.Context, sig bip322.Signature, message bip322.DeleteIntentMessage,
) error {
	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if time.Now().After(expireAt) {
			return fmt.Errorf("proof of ownership expired")
		}
	}

	outpoints := sig.GetOutpoints()

	boardingTxs := make(map[string]wire.MsgTx)
	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for _, outpoint := range outpoints {
		vtxoOutpoint := domain.Outpoint{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxoOutpoint})
		if err != nil || len(vtxosResult) == 0 {
			if _, ok := boardingTxs[vtxoOutpoint.Txid]; !ok {
				txhex, err := s.wallet.GetTransaction(ctx, outpoint.Hash.String())
				if err != nil {
					return fmt.Errorf("failed to get boarding tx %s: %s", vtxoOutpoint.Txid, err)
				}

				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return fmt.Errorf(
						"failed to deserialize boarding tx %s: %s", vtxoOutpoint.Txid, err,
					)
				}

				boardingTxs[vtxoOutpoint.Txid] = tx
			}

			tx := boardingTxs[vtxoOutpoint.Txid]
			prevout := tx.TxOut[vtxoOutpoint.VOut]
			prevouts[outpoint] = prevout
			continue
		}

		vtxo := vtxosResult[0]
		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return fmt.Errorf("failed to decode script pubkey: %s", err)
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse pubkey: %s", err)
		}

		pkScript, err := script.P2TRScript(pubkey)
		if err != nil {
			return fmt.Errorf("failed to create p2tr script: %s", err)
		}

		prevouts[outpoint] = &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: pkScript,
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	encodedMessage, err := message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %s", err)
	}

	if err := sig.Verify(encodedMessage, prevoutFetcher); err != nil {
		return fmt.Errorf("failed to verify signature: %s", err)
	}

	allIntents, err := s.cache.Intents().ViewAll(nil)
	if err != nil {
		return err
	}

	idsToDeleteMap := make(map[string]struct{})
	for _, intent := range allIntents {
		for _, in := range intent.Inputs {
			for _, op := range outpoints {
				if in.Txid == op.Hash.String() && in.VOut == op.Index {
					if _, ok := idsToDeleteMap[intent.Id]; !ok {
						idsToDeleteMap[intent.Id] = struct{}{}
					}
				}
			}
		}
	}

	if len(idsToDeleteMap) == 0 {
		return fmt.Errorf("no matching intents found for BIP322 proof")
	}

	idsToDelete := make([]string, 0, len(idsToDeleteMap))
	for id := range idsToDeleteMap {
		idsToDelete = append(idsToDelete, id)
	}

	return s.cache.Intents().Delete(idsToDelete)
}

func (s *service) RegisterCosignerNonces(
	ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces,
) error {
	return s.cache.TreeSigingSessions().AddNonces(ctx, roundId, pubkey, nonces)
}

func (s *service) RegisterCosignerSignatures(
	ctx context.Context, roundId string, pubkey string, sigs tree.TreePartialSigs,
) error {
	return s.cache.TreeSigingSessions().AddSignatures(ctx, roundId, pubkey, sigs)
}

func (s *service) start() {
	s.startRound()
}

func (s *service) startRound() {
	defer s.wg.Done()

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	// reset the forfeit txs map to avoid polluting the next batch of forfeits transactions
	s.cache.ForfeitTxs().Reset()

	round := domain.NewRound()
	// nolint
	round.StartRegistration()
	if err := s.cache.CurrentRound().Upsert(func(_ *domain.Round) *domain.Round {
		return round
	}); err != nil {
		log.Errorf("failed to upsert round: %s", err)
		return
	}

	close(s.forfeitsBoardingSigsChan)
	s.forfeitsBoardingSigsChan = make(chan struct{}, 1)

	log.Debugf("started registration stage for new round: %s", round.Id)

	roundTiming := newRoundTiming(s.roundInterval)
	<-time.After(roundTiming.registrationDuration())
	s.wg.Add(1)
	go s.startConfirmation(roundTiming)
}

func (s *service) startConfirmation(roundTiming roundTiming) {
	defer s.wg.Done()

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	ctx := context.Background()
	roundId := s.cache.CurrentRound().Get().Id
	var registeredIntents []ports.TimedIntent
	roundAborted := false

	log.Debugf("started confirmation stage for round: %s", roundId)

	defer func() {
		s.wg.Add(1)

		if roundAborted {
			go s.startRound()
			return
		}

		s.cache.ConfirmationSessions().Reset()

		if err := s.saveEvents(ctx, roundId, s.cache.CurrentRound().Get().Events()); err != nil {
			log.WithError(err).Warn("failed to store new round events")
		}

		if s.cache.CurrentRound().Get().IsFailed() {
			s.cache.Intents().DeleteVtxos()
			go s.startRound()
			return
		}

		go s.startFinalization(roundTiming, registeredIntents)
	}()

	num := s.cache.Intents().Len()
	if num < s.roundMinParticipantsCount {
		roundAborted = true
		err := fmt.Errorf("not enough intents registered %d/%d", num, s.roundMinParticipantsCount)
		log.WithError(err).Debugf("round %s aborted", roundId)
		return
	}
	if num > s.roundMaxParticipantsCount {
		num = s.roundMaxParticipantsCount
	}

	availableBalance, _, err := s.wallet.MainAccountBalance(ctx)
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to get main account balance: %s", err))
		log.WithError(err).Warn("failed to get main account balance")
		return
	}

	// TODO take into account available liquidity
	intents := s.cache.Intents().Pop(num)

	totAmount := uint64(0)
	for _, intent := range intents {
		totAmount += intent.TotalOutputAmount()
	}

	if availableBalance <= totAmount {
		err := fmt.Errorf("not enough liquidity, current balance: %d", availableBalance)
		s.cache.CurrentRound().Fail(err)
		log.WithError(err).Debugf("round %s aborted, balance: %d", roundId, availableBalance)
		return
	}

	s.propagateBatchStartedEvent(intents)

	confirmedIntents := make([]ports.TimedIntent, 0)
	notConfirmedIntents := make([]ports.TimedIntent, 0)

	select {
	case <-time.After(roundTiming.confirmationDuration()):
		session := s.cache.ConfirmationSessions().Get()
		for _, intent := range intents {
			if session.IntentsHashes[intent.HashID()] {
				confirmedIntents = append(confirmedIntents, intent)
				continue
			}
			notConfirmedIntents = append(notConfirmedIntents, intent)
		}
	case <-s.cache.ConfirmationSessions().SessionCompleted():
		confirmedIntents = intents
	}

	repushToQueue := notConfirmedIntents
	if int64(len(confirmedIntents)) < s.roundMinParticipantsCount {
		repushToQueue = append(repushToQueue, confirmedIntents...)
		confirmedIntents = make([]ports.TimedIntent, 0)
	}

	// register confirmed intents if we have enough participants
	if len(confirmedIntents) > 0 {
		intents := make([]domain.Intent, 0, len(confirmedIntents))
		numOfBoardingInputs := 0
		for _, intent := range confirmedIntents {
			intents = append(intents, intent.Intent)
			numOfBoardingInputs += len(intent.BoardingInputs)
		}

		s.cache.BoardingInputs().Set(numOfBoardingInputs)

		round := s.cache.CurrentRound().Get()
		if _, err := round.RegisterIntents(intents); err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to register intents: %s", err))
			log.WithError(err).Warn("failed to register intents")
			return
		}
		if err := s.cache.CurrentRound().Upsert(func(_ *domain.Round) *domain.Round {
			return round
		}); err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to upsert round: %s", err))
			log.WithError(err).Warn("failed to upsert round")
			return
		}

		registeredIntents = confirmedIntents
	}

	if len(repushToQueue) > 0 {
		for _, intent := range repushToQueue {
			if err := s.cache.Intents().Push(
				intent.Intent, intent.BoardingInputs, intent.CosignersPublicKeys,
			); err != nil {
				log.WithError(err).Warn("failed to re-push intents to the queue")
				continue
			}
		}

		// make the round fail if we didn't receive enoush confirmations
		if len(confirmedIntents) == 0 {
			s.cache.CurrentRound().Fail(fmt.Errorf("not enough confirmation received"))
			log.Warn("not enough confirmation received")
			return
		}
	}
}

func (s *service) startFinalization(
	roundTiming roundTiming, registeredIntents []ports.TimedIntent,
) {
	defer s.wg.Done()

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	ctx := context.Background()
	roundId := s.cache.CurrentRound().Get().Id
	thirdOfRemainingDuration := roundTiming.finalizationDuration()

	log.Debugf("started finalization stage for round: %s", roundId)

	defer func() {
		s.wg.Add(1)

		s.cache.TreeSigingSessions().Delete(roundId)

		if err := s.saveEvents(ctx, roundId, s.cache.CurrentRound().Get().Events()); err != nil {
			log.WithError(err).Warn("failed to store new round events")
		}

		if s.cache.CurrentRound().Get().IsFailed() {
			s.cache.Intents().DeleteVtxos()
			go s.startRound()
			return
		}

		go s.finalizeRound(roundTiming)
	}()

	if s.cache.CurrentRound().Get().IsFailed() {
		return
	}

	connectorAddresses, err := s.repoManager.Rounds().GetSweptRoundsConnectorAddress(ctx)
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	operatorPubkeyHex := hex.EncodeToString(s.operatorPubkey.SerializeCompressed())

	intents := make([]domain.Intent, 0, len(registeredIntents))
	boardingInputs := make([]ports.BoardingInput, 0)
	cosignersPublicKeys := make([][]string, 0)
	uniqueSignerPubkeys := make(map[string]struct{})

	for _, intent := range registeredIntents {
		intents = append(intents, intent.Intent)
		boardingInputs = append(boardingInputs, intent.BoardingInputs...)
		for _, pubkey := range intent.CosignersPublicKeys {
			uniqueSignerPubkeys[pubkey] = struct{}{}
		}

		cosignersPublicKeys = append(
			cosignersPublicKeys, append(intent.CosignersPublicKeys, operatorPubkeyHex),
		)
	}

	log.Debugf("building tx for round %s", roundId)
	commitmentTx, vtxoTree, connectorAddress, connectors, err := s.builder.BuildCommitmentTx(
		s.signerPubkey, intents, boardingInputs, connectorAddresses, cosignersPublicKeys,
	)
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to create commitment tx: %s", err))
		log.WithError(err).Warn("failed to create commitment tx")
		return
	}
	log.Debugf("commitment tx created for round %s", roundId)

	flatConnectors, err := connectors.Serialize()
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to serialize connectors: %s", err))
		log.WithError(err).Warn("failed to serialize connectors")
		return
	}

	if err := s.cache.ForfeitTxs().Init(flatConnectors, intents); err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to initialize forfeit txs: %s", err))
		log.WithError(err).Warn("failed to initialize forfeit txs")
		return
	}

	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to parse commitment tx: %s", err))
		log.WithError(err).Warn("failed to parse commitment tx")
		return
	}

	if err := s.cache.CurrentRound().Upsert(func(r *domain.Round) *domain.Round {
		ur := *r
		ur.CommitmentTxid = commitmentPtx.UnsignedTx.TxID()
		ur.CommitmentTx = commitmentTx
		return &ur
	}); err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to update round: %s", err))
		log.WithError(err).Warn("failed to update round")
		return
	}

	flatVtxoTree := make(tree.FlatTxTree, 0)
	if vtxoTree != nil {
		sweepClosure := script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{s.signerPubkey}},
			Locktime:        s.vtxoTreeExpiry,
		}

		sweepScript, err := sweepClosure.Script()
		if err != nil {
			return
		}

		batchOutputAmount := commitmentPtx.UnsignedTx.TxOut[0].Value

		sweepLeaf := txscript.NewBaseTapLeaf(sweepScript)
		sweepTapTree := txscript.AssembleTaprootScriptTree(sweepLeaf)
		root := sweepTapTree.RootNode.TapHash()

		coordinator, err := tree.NewTreeCoordinatorSession(
			root.CloneBytes(), batchOutputAmount, vtxoTree,
		)
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf(
				"failed to create coordinator session: %s", err,
			))
			log.WithError(err).Warn("failed to create coordinator session")
			return
		}

		operatorSignerSession := tree.NewTreeSignerSession(s.operatorPrvkey)
		if err := operatorSignerSession.Init(
			root.CloneBytes(), batchOutputAmount, vtxoTree,
		); err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to create signer session: %s", err))
			log.WithError(err).Warn("failed to create signer session")
			return
		}

		nonces, err := operatorSignerSession.GetNonces()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to get nonces: %s", err))
			log.WithError(err).Warn("failed to get nonces")
			return
		}

		coordinator.AddNonce(s.operatorPubkey, nonces)
		s.cache.TreeSigingSessions().New(roundId, uniqueSignerPubkeys)

		log.Debugf(
			"musig2 signing session created for round %s with %d signers",
			roundId, len(uniqueSignerPubkeys),
		)

		// send back the unsigned tree & all cosigners pubkeys
		listOfCosignersPubkeys := make([]string, 0, len(uniqueSignerPubkeys))
		for pubkey := range uniqueSignerPubkeys {
			listOfCosignersPubkeys = append(listOfCosignersPubkeys, pubkey)
		}

		s.propagateRoundSigningStartedEvent(vtxoTree, listOfCosignersPubkeys)

		log.Debugf("waiting for cosigners to submit their nonces...")

		select {
		case <-time.After(thirdOfRemainingDuration):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			err := fmt.Errorf(
				"musig2 signing session timed out (nonce collection), collected %d/%d nonces",
				len(signingSession.Nonces), len(uniqueSignerPubkeys),
			)
			s.cache.CurrentRound().Fail(err)
			log.Warn(err)
			return
		case <-s.cache.TreeSigingSessions().NoncesCollected(roundId):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			for pubkey, nonce := range signingSession.Nonces {
				buf, _ := hex.DecodeString(pubkey)
				pk, _ := btcec.ParsePubKey(buf)
				coordinator.AddNonce(pk, nonce)
			}
		}

		log.Debugf("all nonces collected for round %s", roundId)

		aggregatedNonces, err := coordinator.AggregateNonces()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to aggregate nonces: %s", err))
			log.WithError(err).Warn("failed to aggregate nonces")
			return
		}

		log.Debugf("nonces aggregated for round %s", roundId)

		operatorSignerSession.SetAggregatedNonces(aggregatedNonces)

		// send the combined nonces to the clients
		s.propagateRoundSigningNoncesGeneratedEvent(aggregatedNonces)

		// sign the tree as operator
		operatorSignatures, err := operatorSignerSession.Sign()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to sign tree: %s", err))
			log.WithError(err).Warn("failed to sign tree")
			return
		}
		coordinator.AddSignatures(s.operatorPubkey, operatorSignatures)

		log.Debugf("tree signed by us for round %s", roundId)

		log.Debugf("waiting for cosigners to submit their signatures...")

		select {
		case <-time.After(thirdOfRemainingDuration):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			err := fmt.Errorf(
				"musig2 signing session timed out (signatures collection), "+
					"collected %d/%d signatures",
				len(signingSession.Signatures), len(uniqueSignerPubkeys),
			)
			s.cache.CurrentRound().Fail(err)
			log.Warn(err)
			return
		case <-s.cache.TreeSigingSessions().SignaturesCollected(roundId):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			for pubkey, sig := range signingSession.Signatures {
				buf, _ := hex.DecodeString(pubkey)
				pk, _ := btcec.ParsePubKey(buf)
				coordinator.AddSignatures(pk, sig)
			}
		}

		log.Debugf("all signatures collected for round %s", roundId)

		signedTree, err := coordinator.SignTree()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to aggregate tree signatures: %s", err))
			log.WithError(err).Warn("failed to aggregate tree signatures")
			return
		}

		log.Debugf("vtxo tree signed for round %s", roundId)

		vtxoTree = signedTree
		flatVtxoTree, err = vtxoTree.Serialize()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to serialize vtxo tree: %s", err))
			log.WithError(err).Warn("failed to serialize vtxo tree")
			return
		}
	}

	round := s.cache.CurrentRound().Get()
	_, err = round.StartFinalization(
		connectorAddress, flatConnectors, flatVtxoTree,
		round.CommitmentTxid, round.CommitmentTx, s.vtxoTreeExpiry.Seconds(),
	)
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}
	if err := s.cache.CurrentRound().Upsert(func(_ *domain.Round) *domain.Round {
		return round
	}); err != nil {
		log.Errorf("failed to upsert round: %s", err)
		return
	}
}

func (s *service) finalizeRound(roundTiming roundTiming) {
	defer s.wg.Done()

	var stopped bool
	ctx := context.Background()
	roundId := s.cache.CurrentRound().Get().Id

	defer func() {
		if !stopped {
			s.wg.Add(1)
			go s.startRound()
		}
	}()

	defer s.cache.Intents().DeleteVtxos()

	select {
	case <-s.ctx.Done():
		stopped = true
		return
	default:
	}

	if s.cache.CurrentRound().Get().IsFailed() {
		return
	}

	var changes []domain.Event
	defer func() {
		if err := s.saveEvents(ctx, roundId, changes); err != nil {
			log.WithError(err).Warn("failed to store new round events")
			return
		}
	}()

	commitmentTx, err := psbt.NewFromRawBytes(
		strings.NewReader(s.cache.CurrentRound().Get().CommitmentTx), true,
	)
	if err != nil {
		log.Debugf("failed to parse commitment tx: %s", s.cache.CurrentRound().Get().CommitmentTx)
		changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to parse commitment tx: %s", err))
		log.WithError(err).Warn("failed to parse commitment tx")
		return
	}
	commitmentTxid := commitmentTx.UnsignedTx.TxID()

	includesBoardingInputs := false
	for _, in := range commitmentTx.Inputs {
		// TODO: this is ok as long as the signer doesn't use taproot address too!
		// We need to find a better way to understand if an in input is ours or if
		// it's a boarding one.
		scriptType := txscript.GetScriptClass(in.WitnessUtxo.PkScript)
		if scriptType == txscript.WitnessV1TaprootTy {
			includesBoardingInputs = true
			break
		}
	}

	txToSign := s.cache.CurrentRound().Get().CommitmentTx
	forfeitTxs := make([]domain.ForfeitTx, 0)

	if s.cache.ForfeitTxs().Len() > 0 || includesBoardingInputs {
		remainingTime := roundTiming.remainingDuration()
		select {
		case <-s.forfeitsBoardingSigsChan:
			log.Debug("all forfeit txs and boarding inputs signatures have been sent")
		case <-time.After(remainingTime):
			log.Debug("timeout waiting for forfeit txs and boarding inputs signatures")
			// TODO: should fail here and not continue
		}

		txToSign = s.cache.CurrentRound().Get().CommitmentTx

		forfeitTxList, err := s.cache.ForfeitTxs().Pop()
		if err != nil {
			changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to finalize round: %s", err))
			log.WithError(err).Warn("failed to finalize round")
			return
		}

		if err := s.verifyForfeitTxsSigs(forfeitTxList); err != nil {
			changes = s.cache.CurrentRound().Fail(err)
			log.WithError(err).Warn("failed to validate forfeit txs")
			return
		}

		boardingInputsIndexes := make([]int, 0)
		for i, in := range commitmentTx.Inputs {
			if len(in.TaprootLeafScript) > 0 {
				if len(in.TaprootScriptSpendSig) == 0 {
					err = fmt.Errorf("missing tapscript spend sig for input %d", i)
					changes = s.cache.CurrentRound().Fail(err)
					log.WithError(err).Warn("missing boarding sig")
					return
				}

				boardingInputsIndexes = append(boardingInputsIndexes, i)
			}
		}

		if len(boardingInputsIndexes) > 0 {
			txToSign, err = s.wallet.SignTransactionTapscript(ctx, txToSign, boardingInputsIndexes)
			if err != nil {
				changes = s.cache.CurrentRound().Fail(
					fmt.Errorf("failed to sign commitment tx: %s", err),
				)
				log.WithError(err).Warn("failed to sign commitment tx")
				return
			}
		}

		for _, tx := range forfeitTxList {
			// nolint
			ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
			forfeitTxid := ptx.UnsignedTx.TxID()
			forfeitTxs = append(forfeitTxs, domain.ForfeitTx{
				Txid: forfeitTxid,
				Tx:   tx,
			})
		}
	}

	log.Debugf("signing commitment transaction for round %s\n", roundId)

	signedCommitmentTx, err := s.wallet.SignTransaction(ctx, txToSign, true)
	if err != nil {
		changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to sign commitment tx: %s", err))
		log.WithError(err).Warn("failed to sign commitment tx")
		return
	}

	if _, err := s.wallet.BroadcastTransaction(ctx, signedCommitmentTx); err != nil {
		changes = s.cache.CurrentRound().Fail(
			fmt.Errorf("failed to broadcast commitment tx: %s", err),
		)
		log.WithError(err).Warn("failed to broadcast commitment tx")
		return
	}

	round := s.cache.CurrentRound().Get()
	changes, err = round.EndFinalization(forfeitTxs, signedCommitmentTx)
	if err != nil {
		changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}
	if err := s.cache.CurrentRound().Upsert(func(m *domain.Round) *domain.Round {
		return round
	}); err != nil {
		changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	log.Debugf("finalized round %s with commitment tx %s", roundId, commitmentTxid)
}

func (s *service) listenToScannerNotifications() {
	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)

	mutx := &sync.Mutex{}
	for vtxoKeys := range chVtxos {
		go func(vtxoKeys map[string][]ports.VtxoWithValue) {
			for _, keys := range vtxoKeys {
				for _, v := range keys {
					vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{v.Outpoint})
					if err != nil {
						log.WithError(err).Warn("failed to retrieve vtxos, skipping...")
						return
					}
					vtxo := vtxos[0]

					if !vtxo.Unrolled {
						go func() {
							if err := s.repoManager.Vtxos().UnrollVtxos(
								ctx, []domain.Outpoint{vtxo.Outpoint},
							); err != nil {
								log.WithError(err).Warnf(
									"failed to mark vtxo %s as unrolled", vtxo.Outpoint.String(),
								)
							}

							log.Debugf("vtxo %s unrolled", vtxo.Outpoint.String())
						}()
					}

					if vtxo.Spent {
						log.Infof("fraud detected on vtxo %s", vtxo.Outpoint.String())
						go func() {
							if err := s.reactToFraud(ctx, vtxo, mutx); err != nil {
								log.WithError(err).Warnf(
									"failed to react to fraud for vtxo %s", vtxo.Outpoint.String(),
								)
							}
						}()
					}
				}
			}
		}(vtxoKeys)
	}
}

func (s *service) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	events := make([]domain.Event, 0)
	switch ev := lastEvent.(type) {
	// RoundFinalizationStarted event must be handled differently
	// because it contains the vtxoTree and connectorsTree
	// and we need to propagate them in specific BatchTree events
	case domain.RoundFinalizationStarted:
		if len(ev.VtxoTree) > 0 {
			vtxoTree, err := tree.NewTxTree(ev.VtxoTree)
			if err != nil {
				log.WithError(err).Warn("failed to create vtxo tree")
				return
			}

			events = append(events, treeSignatureEvents(vtxoTree, 0, round.Id)...)
		}

		if len(ev.Connectors) > 0 {
			connectorTree, err := tree.NewTxTree(ev.Connectors)
			if err != nil {
				log.WithError(err).Warn("failed to create connector tree")
				return
			}

			connectorsIndex := s.cache.ForfeitTxs().GetConnectorsIndexes()

			events = append(events, treeTxEvents(
				connectorTree, 1, round.Id, getConnectorTreeTopic(connectorsIndex),
			)...)
		}
	case domain.RoundFinalized:
		lastEvent = RoundFinalized{lastEvent.(domain.RoundFinalized), round.CommitmentTxid}
	}

	events = append(events, lastEvent)
	s.eventsCh <- events
}

func (s *service) propagateBatchStartedEvent(intents []ports.TimedIntent) {
	hashedIntentIds := make([][32]byte, 0, len(intents))
	for _, intent := range intents {
		hashedIntentIds = append(hashedIntentIds, intent.HashID())
		log.Info(fmt.Sprintf("intent id: %x", intent.HashID()))
	}

	s.cache.ConfirmationSessions().Init(hashedIntentIds)

	ev := BatchStarted{
		RoundEvent: domain.RoundEvent{
			Id:   s.cache.CurrentRound().Get().Id,
			Type: domain.EventTypeUndefined,
		},
		IntentIdsHashes: hashedIntentIds,
		BatchExpiry:     s.vtxoTreeExpiry.Value,
	}
	s.eventsCh <- []domain.Event{ev}
}

func (s *service) propagateRoundSigningStartedEvent(
	vtxoTree *tree.TxTree, cosignersPubkeys []string,
) {
	round := s.cache.CurrentRound().Get()

	events := append(
		treeTxEvents(vtxoTree, 0, round.Id, getVtxoTreeTopic),
		RoundSigningStarted{
			RoundEvent: domain.RoundEvent{
				Id:   round.Id,
				Type: domain.EventTypeUndefined,
			},
			UnsignedCommitmentTx: round.CommitmentTx,
			CosignersPubkeys:     cosignersPubkeys,
		},
	)

	s.eventsCh <- events
}

func (s *service) propagateRoundSigningNoncesGeneratedEvent(
	combinedNonces tree.TreeNonces,
) {
	ev := TreeNoncesAggregated{
		RoundEvent: domain.RoundEvent{
			Id:   s.cache.CurrentRound().Get().Id,
			Type: domain.EventTypeUndefined,
		},
		Nonces: combinedNonces,
	}

	s.eventsCh <- []domain.Event{ev}
}

func (s *service) scheduleSweepBatchOutput(round *domain.Round) {
	// Schedule the sweeping procedure only for completed round.
	if !round.IsEnded() {
		return
	}

	// if the round doesn't have a batch vtxo output, we do not need to sweep it
	if len(round.VtxoTree) <= 0 {
		return
	}

	expirationTimestamp := s.sweeper.scheduler.AddNow(int64(s.vtxoTreeExpiry.Value))

	log.Debugf(
		"batch %s:0 sweeping scheduled at %s", round.CommitmentTxid,
		fancyTime(expirationTimestamp, s.sweeper.scheduler.Unit()),
	)

	vtxoTree, err := tree.NewTxTree(round.VtxoTree)
	if err != nil {
		log.WithError(err).Warn("failed to create vtxo tree")
		return
	}

	if err := s.sweeper.schedule(expirationTimestamp, round.CommitmentTxid, vtxoTree); err != nil {
		log.WithError(err).Warn("failed to schedule sweep tx")
	}
}

func (s *service) checkForfeitsAndBoardingSigsSent() {
	tx := s.cache.CurrentRound().Get().CommitmentTx
	commitmentTx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	numOfInputsSigned := 0
	for _, v := range commitmentTx.Inputs {
		if len(v.TaprootScriptSpendSig) > 0 {
			if len(v.TaprootScriptSpendSig[0].Signature) > 0 {
				numOfInputsSigned++
			}
		}
	}

	// Condition: all forfeit txs are signed and
	// the number of signed boarding inputs matches
	// numOfBoardingInputs we expect
	numOfBoardingInputs := s.cache.BoardingInputs().Get()
	if s.cache.ForfeitTxs().AllSigned() && numOfBoardingInputs == numOfInputsSigned {
		select {
		case s.forfeitsBoardingSigsChan <- struct{}{}:
		default:
		}
	}
}

func (s *service) getSpentVtxos(intents map[string]domain.Intent) []domain.Vtxo {
	outpoints := getSpentVtxos(intents)
	vtxos, _ := s.repoManager.Vtxos().GetVtxos(context.Background(), outpoints)
	return vtxos
}

func (s *service) startWatchingVtxos(vtxos []domain.Vtxo) error {
	scripts, err := s.extractVtxosScripts(vtxos)
	if err != nil {
		return err
	}

	return s.scanner.WatchScripts(context.Background(), scripts)
}

func (s *service) stopWatchingVtxos(vtxos []domain.Vtxo) {
	scripts, err := s.extractVtxosScripts(vtxos)
	if err != nil {
		log.WithError(err).Warn("failed to extract scripts from vtxos")
		return
	}

	for {
		if err := s.scanner.UnwatchScripts(context.Background(), scripts); err != nil {
			log.WithError(err).Warn("failed to stop watching vtxos, retrying in a moment...")
			time.Sleep(100 * time.Millisecond)
			continue
		}
		log.Debugf("stopped watching %d vtxos", len(vtxos))
		break
	}
}

func (s *service) restoreWatchingVtxos() error {
	ctx := context.Background()

	sweepableBatches, err := s.repoManager.Rounds().GetSweepableRounds(ctx)
	if err != nil {
		return err
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, txid := range sweepableBatches {
		fromRound, err := s.repoManager.Vtxos().GetVtxosForRound(ctx, txid)
		if err != nil {
			log.WithError(err).Warnf("failed to retrieve vtxos for round %s", txid)
			continue
		}
		for _, v := range fromRound {
			if !v.Swept && !v.Unrolled {
				vtxos = append(vtxos, v)
			}
		}
	}

	if len(vtxos) <= 0 {
		return nil
	}

	if err := s.startWatchingVtxos(vtxos); err != nil {
		return err
	}

	log.Debugf("restored watching %d vtxos", len(vtxos))
	return nil
}

func (s *service) extractVtxosScripts(vtxos []domain.Vtxo) ([]string, error) {
	dustLimit, err := s.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	indexedScripts := make(map[string]struct{})

	for _, vtxo := range vtxos {
		vtxoTapKeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, err := schnorr.ParsePubKey(vtxoTapKeyBytes)
		if err != nil {
			return nil, err
		}

		var outScript []byte

		if vtxo.Amount < dustLimit {
			outScript, err = script.SubDustScript(vtxoTapKey)
		} else {
			outScript, err = script.P2TRScript(vtxoTapKey)
		}

		if err != nil {
			return nil, err
		}

		indexedScripts[hex.EncodeToString(outScript)] = struct{}{}
	}
	scripts := make([]string, 0, len(indexedScripts))
	for script := range indexedScripts {
		scripts = append(scripts, script)
	}
	return scripts, nil
}

func (s *service) saveEvents(
	ctx context.Context, id string, events []domain.Event,
) error {
	if len(events) <= 0 {
		return nil
	}
	return s.repoManager.Events().Save(ctx, domain.RoundTopic, id, events)
}

func (s *service) chainParams() *chaincfg.Params {
	switch s.network.Name {
	case arklib.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case arklib.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return nil
	}
}

func (s *service) validateBoardingInput(
	ctx context.Context, vtxoKey domain.Outpoint, tapscripts txutils.TapTree,
	now time.Time, locktime *arklib.RelativeLocktime, disabled bool,
) (*wire.MsgTx, error) {
	// check if the tx exists and is confirmed
	txhex, err := s.wallet.GetTransaction(ctx, vtxoKey.Txid)
	if err != nil {
		return nil, fmt.Errorf("failed to get tx %s: %s", vtxoKey.Txid, err)
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
		return nil, fmt.Errorf("failed to deserialize tx %s: %s", vtxoKey.Txid, err)
	}

	confirmed, _, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, vtxoKey.Txid)
	if err != nil {
		return nil, fmt.Errorf("failed to check tx %s: %s", vtxoKey.Txid, err)
	}

	if !confirmed {
		return nil, fmt.Errorf("tx %s not confirmed", vtxoKey.Txid)
	}

	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vtxo taproot tree: %s", err)
	}

	// validate the vtxo script
	if err := vtxoScript.Validate(s.signerPubkey, arklib.RelativeLocktime{
		Type:  s.boardingExitDelay.Type,
		Value: s.boardingExitDelay.Value,
	}, s.allowCSVBlockType); err != nil {
		return nil, fmt.Errorf("invalid vtxo script: %s", err)
	}

	exitDelay, err := vtxoScript.SmallestExitDelay()
	if err != nil {
		return nil, fmt.Errorf("failed to get exit delay: %s", err)
	}

	// if the exit path is available, forbid registering the boarding utxo
	if time.Unix(blocktime, 0).Add(time.Duration(exitDelay.Seconds()) * time.Second).Before(now) {
		return nil, fmt.Errorf("tx %s expired", vtxoKey.Txid)
	}

	// If the intent is registered using a exit path that contains CSV delay, we want to verify it
	// by shifitng the current "now" in the future of the duration of the smallest exit delay.
	// This way, any exit order guaranteed by the exit path is maintained at intent registration
	if !disabled {
		delta := now.Add(time.Duration(exitDelay.Seconds())*time.Second).Unix() - blocktime
		if diff := locktime.Seconds() - delta; diff > 0 {
			return nil, fmt.Errorf(
				"vtxo script can be used for intent registration in %d seconds", diff,
			)
		}
	}

	if s.utxoMaxAmount >= 0 {
		if tx.TxOut[vtxoKey.VOut].Value > s.utxoMaxAmount {
			return nil, fmt.Errorf(
				"boarding input amount is higher than max utxo amount:%d", s.utxoMaxAmount,
			)
		}
	}
	if tx.TxOut[vtxoKey.VOut].Value < s.utxoMinAmount {
		return nil, fmt.Errorf(
			"boarding input amount is lower than min utxo amount:%d", s.utxoMinAmount,
		)
	}

	return &tx, nil
}

func (s *service) validateVtxoInput(
	tapscripts txutils.TapTree, expectedTapKey *btcec.PublicKey,
	vtxoCreatedAt int64, now time.Time, locktime *arklib.RelativeLocktime, disabled bool,
) error {
	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return fmt.Errorf("failed to parse vtxo taproot tree: %s", err)
	}

	// validate the vtxo script
	if err := vtxoScript.Validate(
		s.signerPubkey, s.unilateralExitDelay, s.allowCSVBlockType,
	); err != nil {
		return fmt.Errorf("invalid vtxo script: %s", err)
	}

	exitDelay, err := vtxoScript.SmallestExitDelay()
	if err != nil {
		return fmt.Errorf("failed to get exit delay: %s", err)
	}

	// If the intent is registered using a exit path that contains CSV delay, we want to verify it
	// by shifitng the current "now" in the future of the duration of the smallest exit delay.
	// This way, any exit order guaranteed by the exit path is maintained at intent registration
	if !disabled {
		delta := now.Add(time.Duration(exitDelay.Seconds())*time.Second).Unix() - vtxoCreatedAt
		if diff := locktime.Seconds() - delta; diff > 0 {
			return fmt.Errorf(
				"vtxo script can be used for intent registration in %d seconds", diff,
			)
		}
	}

	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return fmt.Errorf("failed to get taproot key: %s", err)
	}

	if !bytes.Equal(schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey)) {
		return fmt.Errorf(
			"invalid vtxo taproot key: got %x expected %x",
			schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey),
		)
	}
	return nil
}

func (s *service) verifyForfeitTxsSigs(txs []string) error {
	nbWorkers := runtime.NumCPU()
	jobs := make(chan string, len(txs))
	errChan := make(chan error, 1)
	wg := sync.WaitGroup{}
	wg.Add(nbWorkers)

	for i := 0; i < nbWorkers; i++ {
		go func() {
			defer wg.Done()

			for tx := range jobs {
				valid, txid, err := s.builder.VerifyTapscriptPartialSigs(tx)
				if err != nil {
					errChan <- fmt.Errorf("failed to validate forfeit tx %s: %s", txid, err)
					return
				}

				if !valid {
					errChan <- fmt.Errorf("invalid signature for forfeit tx %s", txid)
					return
				}
			}
		}()
	}

	for _, tx := range txs {
		select {
		case err := <-errChan:
			return err
		default:
			jobs <- tx
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errChan:
		return err
	default:
		close(errChan)
		return nil
	}
}
