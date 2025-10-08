package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	log "github.com/sirupsen/logrus"
)

type service struct {
	// services
	wallet         ports.WalletService
	signer         ports.SignerService
	repoManager    ports.RepoManager
	builder        ports.TxBuilder
	scanner        ports.BlockchainScanner
	cache          ports.LiveStore
	sweeper        *sweeper
	roundReportSvc RoundReportService

	// config
	network                   arklib.Network
	signerPubkey              *btcec.PublicKey
	forfeitPubkey             *btcec.PublicKey
	forfeitAddress            string
	checkpointTapscript       []byte
	batchExpiry               arklib.RelativeLocktime
	sessionDuration           time.Duration
	banDuration               time.Duration
	banThreshold              int64
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
	wallet ports.WalletService,
	signer ports.SignerService,
	repoManager ports.RepoManager,
	builder ports.TxBuilder,
	scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
	cache ports.LiveStore,
	reportSvc RoundReportService,
	vtxoTreeExpiry, unilateralExitDelay, boardingExitDelay, checkpointExitDelay arklib.RelativeLocktime,
	sessionDuration, roundMinParticipantsCount, roundMaxParticipantsCount,
	utxoMaxAmount, utxoMinAmount, vtxoMaxAmount, vtxoMinAmount, banDuration, banThreshold int64,
	network arklib.Network,
	allowCSVBlockType bool,
	noteUriPrefix string,
	scheduledSessionStartTime, scheduledSessionEndTime time.Time,
	scheduledSessionPeriod, scheduledSessionDuration time.Duration,
	scheduledSessionRoundMinParticipantsCount, scheduledSessionRoundMaxParticipantsCount int64,
) (Service, error) {
	ctx := context.Background()

	signerPubkey, err := signer.GetPubkey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signer pubkey: %s", err)
	}

	// Try to load scheduled session from DB first
	scheduledSession, err := repoManager.ScheduledSession().Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled session from db: %w", err)
	}

	if scheduledSession == nil &&
		!scheduledSessionStartTime.IsZero() && !scheduledSessionEndTime.IsZero() &&
		scheduledSessionPeriod > 0 && scheduledSessionDuration > 0 {
		rMinParticipantsCount := roundMinParticipantsCount
		if scheduledSessionRoundMinParticipantsCount > 0 {
			rMinParticipantsCount = scheduledSessionRoundMinParticipantsCount
		}
		rMaxParticipantsCount := roundMaxParticipantsCount
		if scheduledSessionRoundMaxParticipantsCount > 0 {
			rMaxParticipantsCount = scheduledSessionRoundMaxParticipantsCount
		}
		scheduledSession = domain.NewScheduledSession(
			scheduledSessionStartTime, scheduledSessionEndTime,
			scheduledSessionPeriod, scheduledSessionDuration,
			rMinParticipantsCount, rMaxParticipantsCount,
		)
		if err := repoManager.ScheduledSession().Upsert(ctx, *scheduledSession); err != nil {
			return nil, fmt.Errorf("failed to upsert initial scheduled session to db: %w", err)
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

	forfeitPubkey, err := wallet.GetForfeitPubkey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch forfeit pubkey: %s", err)
	}

	checkpointClosure := &script.CSVMultisigClosure{
		Locktime: checkpointExitDelay,
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{forfeitPubkey},
		},
	}

	checkpointTapscript, err := checkpointClosure.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to encode checkpoint tapscript: %s", err)
	}

	roundReportSvc := reportSvc
	if roundReportSvc == nil {
		roundReportSvc = roundReportUnimplemented{}
	}

	ctx, cancel := context.WithCancel(ctx)

	svc := &service{
		network:             network,
		signerPubkey:        signerPubkey,
		forfeitPubkey:       forfeitPubkey,
		batchExpiry:         vtxoTreeExpiry,
		sessionDuration:     time.Duration(sessionDuration) * time.Second,
		banDuration:         time.Duration(banDuration) * time.Second,
		banThreshold:        banThreshold,
		unilateralExitDelay: unilateralExitDelay,
		allowCSVBlockType:   allowCSVBlockType,
		wallet:              wallet,
		signer:              signer,
		repoManager:         repoManager,
		builder:             builder,
		cache:               cache,
		scanner:             scanner,
		sweeper: newSweeper(
			wallet, repoManager, builder, scheduler, noteUriPrefix,
		),
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
		eventsCh:                  make(chan []domain.Event, 64),
		transactionEventsCh:       make(chan TransactionEvent, 64),
		indexerTxEventsCh:         make(chan TransactionEvent, 64),
		stop:                      cancel,
		ctx:                       ctx,
		wg:                        &sync.WaitGroup{},
		checkpointTapscript:       checkpointTapscript,
		roundReportSvc:            roundReportSvc,
	}
	pubkeyHash := btcutil.Hash160(forfeitPubkey.SerializeCompressed())
	forfeitAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubkeyHash, svc.chainParams())
	if err != nil {
		return nil, err
	}

	svc.forfeitAddress = forfeitAddr.String()

	repoManager.Events().RegisterEventsHandler(
		domain.RoundTopic, func(events []domain.Event) {
			round := domain.NewRoundFromEvents(events)
			go svc.propagateEvents(round)

			lastEvent := events[len(events)-1]
			if lastEvent.GetType() == domain.EventTypeBatchSwept {
				batchSweptEvent := lastEvent.(domain.BatchSwept)
				sweptVtxosOutpoints := append(
					batchSweptEvent.LeafVtxos,
					batchSweptEvent.PreconfirmedVtxos...)
				sweptVtxos, err := svc.repoManager.Vtxos().GetVtxos(ctx, sweptVtxosOutpoints)
				if err != nil {
					log.WithError(err).Warn("failed to get swept vtxos")
					return
				}
				go svc.stopWatchingVtxos(sweptVtxos)

				// sweep tx event
				txEvent := TransactionEvent{
					TxData:     TxData{Tx: batchSweptEvent.Tx, Txid: batchSweptEvent.Txid},
					Type:       SweepTxType,
					SweptVtxos: sweptVtxos,
				}
				svc.propagateTransactionEvent(txEvent)
				return
			}

			if !round.IsEnded() {
				return
			}

			spentVtxos := svc.getSpentVtxos(round.Intents)
			newVtxos := getNewVtxosFromRound(round)

			// commitment tx event
			txEvent := TransactionEvent{
				TxData:         TxData{Tx: round.CommitmentTx, Txid: round.CommitmentTxid},
				Type:           CommitmentTxType,
				SpentVtxos:     spentVtxos,
				SpendableVtxos: newVtxos,
			}

			svc.propagateTransactionEvent(txEvent)

			go func() {
				if err := svc.startWatchingVtxos(newVtxos); err != nil {
					log.WithError(err).Warn("failed to start watching vtxos")
				}
			}()

			if lastEvent := events[len(events)-1]; lastEvent.GetType() != domain.EventTypeBatchSwept {
				go svc.scheduleSweepBatchOutput(round)
			}
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

			// ark tx event
			txEvent := TransactionEvent{
				TxData:         TxData{Txid: txid, Tx: offchainTx.ArkTx},
				Type:           ArkTxType,
				SpentVtxos:     spentVtxos,
				SpendableVtxos: newVtxos,
				CheckpointTxs:  checkpointTxsByOutpoint,
			}

			svc.propagateTransactionEvent(txEvent)

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
		txid := checkpointPtx.UnsignedTx.TxID()
		checkpointTxs[txid] = tx
		checkpointPsbts[txid] = checkpointPtx
		checkpointTxsByVtxoKey[vtxoKey] = txid
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

	// check if any of the spent vtxos are banned
	for _, vtxo := range spentVtxos {
		if err := s.checkIfBanned(ctx, vtxo); err != nil {
			return nil, "", "", err
		}
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

	// Loop over the inputs of the given ark tx to ensure the order of inputs is preserved when
	// rebuilding the txs.
	for inputIndex, in := range ptx.UnsignedTx.TxIn {
		checkpointPsbt := checkpointPsbts[in.PreviousOutPoint.Hash.String()]
		checkpointTxid := checkpointPsbt.UnsignedTx.TxHash().String()
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

		spendingTapscript := input.TaprootLeafScript[0]

		if spendingTapscript == nil {
			return nil, "", "", fmt.Errorf("no matching taptree found")
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

		taptreeFields, err := txutils.GetArkPsbtFields(
			checkpointPsbt, 0, txutils.VtxoTaprootTreeField,
		)
		if err != nil {
			return nil, "", "", fmt.Errorf(
				"failed to extract taptree field from tx %s: %s", checkpointTxid, err,
			)
		}

		if len(taptreeFields) == 0 {
			return nil, "", "", fmt.Errorf("taptree field not found in tx %s", checkpointTxid)
		}

		taptree := taptreeFields[0]

		vtxoScript, err := script.ParseVtxoScript(taptree)
		if err != nil {
			return nil, "", "", fmt.Errorf(
				"failed to parse taptree field in tx %s: %s", checkpointTxid, err,
			)
		}

		// validate the vtxo script
		if err := vtxoScript.Validate(
			s.signerPubkey, s.unilateralExitDelay, s.allowCSVBlockType,
		); err != nil {
			return nil, "", "", fmt.Errorf(
				"invalid vtxo script in tx %s: %s", checkpointTxid, err,
			)
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

		tapscript := &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: spendingTapscript.Script,
		}

		if len(ptx.Inputs[inputIndex].TaprootLeafScript) == 0 {
			return nil, "", "", fmt.Errorf(
				"missing tapscript leaf in ark tx input #%d", inputIndex,
			)
		}

		tapleafScript := ptx.Inputs[inputIndex].TaprootLeafScript[0]
		checkpointTapscript := &waddrmgr.Tapscript{
			RevealedScript: tapleafScript.Script,
		}

		ins = append(ins, offchain.VtxoInput{
			Outpoint:            &checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint,
			Tapscript:           tapscript,
			CheckpointTapscript: checkpointTapscript,
			RevealedTapscripts:  taptree,
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
		ins, outputs, s.checkpointTapscript,
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
			"invalid ark tx: expected txid %s got %s", rebuiltTxid, txid,
		)
	}

	// verify the tapscript signatures
	if valid, _, err := s.builder.VerifyTapscriptPartialSigs(signedArkTx, false); err != nil ||
		!valid {
		return nil, "", "", fmt.Errorf("invalid ark tx signature(s): %s", err)
	}

	// sign the ark tx
	fullySignedArkTx, err := s.signer.SignTransactionTapscript(ctx, signedArkTx, nil)
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
		signedCheckpointTx, err := s.signer.SignTransactionTapscript(ctx, unsignedCheckpointTx, nil)
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

	decodedCheckpointTxs := make(map[string]*psbt.Packet)
	for _, checkpoint := range finalCheckpointTxs {
		// verify the tapscript signatures
		valid, ptx, err := s.builder.VerifyTapscriptPartialSigs(checkpoint, true)
		if err != nil || !valid {
			return err
		}

		decodedCheckpointTxs[ptx.UnsignedTx.TxID()] = ptx
	}

	finalCheckpointTxsMap := make(map[string]string)

	var arkTx *psbt.Packet
	arkTx, err = psbt.NewFromRawBytes(strings.NewReader(offchainTx.ArkTx), true)
	if err != nil {
		return fmt.Errorf("failed to parse ark tx: %s", err)
	}

	for inIndex := range arkTx.Inputs {
		checkpointTxid := arkTx.UnsignedTx.TxIn[inIndex].PreviousOutPoint.Hash.String()
		checkpointTx, ok := decodedCheckpointTxs[checkpointTxid]
		if !ok {
			err = fmt.Errorf("checkpoint tx %s not found", checkpointTxid)
			return err
		}

		taprootTreeField, err := txutils.GetArkPsbtFields(
			arkTx, inIndex, txutils.VtxoTaprootTreeField,
		)
		if err != nil {
			return fmt.Errorf("failed to get taproot tree: %s", err)
		}
		if len(taprootTreeField) <= 0 {
			return fmt.Errorf("missing taproot tree")
		}
		taprootTree := taprootTreeField[0]

		var encodedTapTree []byte
		encodedTapTree, err = taprootTree.Encode()
		if err != nil {
			err = fmt.Errorf("failed to encode taproot tree: %s", err)
			return err
		}

		checkpointTx.Outputs[0].TaprootTapTree = encodedTapTree

		var b64checkpointTx string
		b64checkpointTx, err = checkpointTx.B64Encode()
		if err != nil {
			err = fmt.Errorf("failed to encode checkpoint tx: %s", err)
			return err
		}

		finalCheckpointTxsMap[checkpointTxid] = b64checkpointTx
	}

	var event domain.Event
	event, err = offchainTx.Finalize(finalCheckpointTxsMap)
	if err != nil {
		err = fmt.Errorf("failed to finalize offchain tx: %s", err)
		return err
	}

	changes = []domain.Event{event}
	s.cache.OffchainTxs().Remove(txid)

	return nil
}

func (s *service) RegisterIntent(
	ctx context.Context, proof intent.Proof, message intent.RegisterMessage,
) (string, error) {
	// the vtxo to swap for new ones, require forfeit transactions
	vtxoInputs := make([]domain.Vtxo, 0)
	// the boarding utxos to add in the commitment tx
	boardingInputs := make([]ports.BoardingInput, 0)
	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex

	outpoints := proof.GetOutpoints()

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

	for i, outpoint := range outpoints {
		psbtInput := proof.Inputs[i+1]
		if psbtInput.WitnessUtxo == nil {
			return "", fmt.Errorf("missing witness utxo for input %s", outpoint.String())
		}

		vtxoOutpoint := domain.Outpoint{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		if s.cache.OffchainTxs().Includes(vtxoOutpoint) {
			return "", fmt.Errorf("vtxo %s is currently being spent", vtxoOutpoint.String())
		}

		// we ignore error cause sometimes the taproot tree is not required
		taptreeFields, _ := txutils.GetArkPsbtFields(
			&proof.Packet, i+1, txutils.VtxoTaprootTreeField,
		)
		tapscripts := make([]string, 0)
		if len(taptreeFields) > 0 {
			tapscripts = taptreeFields[0]
		}

		now := time.Now()
		locktime, disabled := arklib.BIP68DecodeSequence(proof.UnsignedTx.TxIn[i+1].Sequence)

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxoOutpoint})
		if err != nil || len(vtxosResult) == 0 {
			// vtxo not found in db, check if it exists on-chain
			if _, ok := boardingTxs[vtxoOutpoint.Txid]; !ok {
				if len(tapscripts) == 0 {
					return "", fmt.Errorf("missing taptree in boarding input %s", outpoint)
				}

				tx, err := s.validateBoardingInput(
					ctx, vtxoOutpoint, tapscripts, now, locktime, disabled,
				)
				if err != nil {
					return "", err
				}

				boardingTxs[vtxoOutpoint.Txid] = *tx
			}

			tx := boardingTxs[vtxoOutpoint.Txid]
			prevout := tx.TxOut[vtxoOutpoint.VOut]

			if !bytes.Equal(prevout.PkScript, psbtInput.WitnessUtxo.PkScript) {
				return "", fmt.Errorf(
					"invalid witness utxo script: got %x expected %x",
					prevout.PkScript,
					psbtInput.WitnessUtxo.PkScript,
				)
			}

			if prevout.Value != int64(psbtInput.WitnessUtxo.Value) {
				return "", fmt.Errorf(
					"invalid witness utxo value: got %d expected %d",
					prevout.Value,
					psbtInput.WitnessUtxo.Value,
				)
			}

			input := ports.Input{
				Outpoint:   vtxoOutpoint,
				Tapscripts: tapscripts,
			}

			if err := s.checkIfBanned(ctx, input); err != nil {
				return "", err
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
		if err := s.checkIfBanned(ctx, vtxo); err != nil {
			return "", err
		}

		if vtxo.Spent {
			return "", fmt.Errorf("input %s already spent", vtxo.Outpoint.String())
		}

		if vtxo.Unrolled {
			return "", fmt.Errorf("input %s already unrolled", vtxo.Outpoint.String())
		}

		if psbtInput.WitnessUtxo.Value != int64(vtxo.Amount) {
			return "", fmt.Errorf(
				"invalid witness utxo value: got %d expected %d",
				psbtInput.WitnessUtxo.Value,
				vtxo.Amount,
			)
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

		if !bytes.Equal(pkScript, psbtInput.WitnessUtxo.PkScript) {
			return "", fmt.Errorf(
				"invalid witness utxo script: got %x expected %x",
				psbtInput.WitnessUtxo.PkScript,
				pkScript,
			)
		}

		// Only in case the vtxo is a note we skip the validation of its script and the csv delay.
		if !vtxo.IsNote() {
			vtxoTapKey, err := vtxo.TapKey()
			if err != nil {
				return "", fmt.Errorf("failed to get taproot key: %s", err)
			}
			if len(tapscripts) == 0 {
				return "", fmt.Errorf("missing taptree for input %s", outpoint)
			}
			if err := s.validateVtxoInput(
				tapscripts, vtxoTapKey, vtxo.CreatedAt, now, locktime, disabled,
			); err != nil {
				return "", err
			}
		}

		vtxoInputs = append(vtxoInputs, vtxo)
	}

	encodedMessage, err := message.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode message: %s", err)
	}

	encodedProof, err := proof.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode proof: %s", err)
	}

	signedProof, err := s.wallet.SignTransactionTapscript(ctx, encodedProof, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign proof: %s", err)
	}

	if err := intent.Verify(signedProof, encodedMessage); err != nil {
		log.
			WithField("unsignedProof", encodedProof).
			WithField("signedProof", signedProof).
			WithField("encodedMessage", encodedMessage).
			Tracef("failed to verify intent proof: %s", err)
		return "", fmt.Errorf("invalid intent proof: %s", err)
	}

	intent, err := domain.NewIntent(signedProof, encodedMessage, vtxoInputs)
	if err != nil {
		return "", err
	}

	if proof.ContainsOutputs() {
		hasOffChainReceiver := false
		receivers := make([]domain.Receiver, 0)

		for outputIndex, output := range proof.UnsignedTx.TxOut {
			amount := uint64(output.Value)
			rcv := domain.Receiver{
				Amount: amount,
			}

			intentHasOnchainOuts := slices.Contains(message.OnchainOutputIndexes, outputIndex)
			if intentHasOnchainOuts {
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

				chainParams := s.chainParams()
				if chainParams == nil {
					return "", fmt.Errorf("unsupported network: %s", s.network.Name)
				}
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, chainParams)
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

// TODO remove this when detaching the indexer service
func (s *service) GetIndexerTxChannel(ctx context.Context) <-chan TransactionEvent {
	return s.indexerTxEventsCh
}

func (s *service) GetInfo(ctx context.Context) (*ServiceInfo, error) {
	signerPubkey := hex.EncodeToString(s.signerPubkey.SerializeCompressed())
	forfeitPubkey := hex.EncodeToString(s.forfeitPubkey.SerializeCompressed())

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dust amount: %s", err)
	}

	scheduledSessionConfig, err := s.repoManager.ScheduledSession().Get(ctx)
	if err != nil {
		return nil, err
	}

	var nextScheduledSession *NextScheduledSession
	if scheduledSessionConfig != nil {
		scheduledSessionNextStart, scheduledSessionNextEnd := calcNextScheduledSession(
			time.Now(), scheduledSessionConfig.StartTime, scheduledSessionConfig.EndTime,
			scheduledSessionConfig.Period,
		)
		nextScheduledSession = &NextScheduledSession{
			StartTime: scheduledSessionNextStart,
			EndTime:   scheduledSessionNextEnd,
			Period:    scheduledSessionConfig.Period,
			Duration:  scheduledSessionConfig.Duration,
		}
	}

	return &ServiceInfo{
		SignerPubKey:         signerPubkey,
		ForfeitPubKey:        forfeitPubkey,
		UnilateralExitDelay:  int64(s.unilateralExitDelay.Value),
		BoardingExitDelay:    int64(s.boardingExitDelay.Value),
		SessionDuration:      int64(s.sessionDuration.Seconds()),
		Network:              s.network.Name,
		Dust:                 dust,
		ForfeitAddress:       s.forfeitAddress,
		NextScheduledSession: nextScheduledSession,
		UtxoMinAmount:        s.utxoMinAmount,
		UtxoMaxAmount:        s.utxoMaxAmount,
		VtxoMinAmount:        s.vtxoMinSettlementAmount,
		VtxoMaxAmount:        s.vtxoMaxAmount,
		CheckpointTapscript:  hex.EncodeToString(s.checkpointTapscript),
	}, nil
}

// DeleteIntentsByProof deletes transaction intents matching the proof of ownership.
func (s *service) DeleteIntentsByProof(
	ctx context.Context, proof intent.Proof, message intent.DeleteMessage,
) error {
	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if time.Now().After(expireAt) {
			return fmt.Errorf("proof of ownership expired")
		}
	}

	outpoints := proof.GetOutpoints()

	boardingTxs := make(map[string]wire.MsgTx)
	for i, outpoint := range outpoints {
		psbtInput := proof.Inputs[i+1]
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

			if !bytes.Equal(prevout.PkScript, psbtInput.WitnessUtxo.PkScript) {
				return fmt.Errorf(
					"invalid witness utxo script: got %x expected %x",
					prevout.PkScript,
					psbtInput.WitnessUtxo.PkScript,
				)
			}

			if prevout.Value != int64(psbtInput.WitnessUtxo.Value) {
				return fmt.Errorf(
					"invalid witness utxo value: got %d expected %d",
					prevout.Value,
					psbtInput.WitnessUtxo.Value,
				)
			}

			continue
		}

		vtxo := vtxosResult[0]

		if psbtInput.WitnessUtxo.Value != int64(vtxo.Amount) {
			return fmt.Errorf(
				"invalid witness utxo value: got %d expected %d",
				psbtInput.WitnessUtxo.Value,
				vtxo.Amount,
			)
		}

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

		if !bytes.Equal(pkScript, psbtInput.WitnessUtxo.PkScript) {
			return fmt.Errorf(
				"invalid witness utxo script: got %x expected %x",
				psbtInput.WitnessUtxo.PkScript,
				pkScript,
			)
		}
	}

	encodedMessage, err := message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %s", err)
	}

	encodedProof, err := proof.B64Encode()
	if err != nil {
		return fmt.Errorf("failed to encode proof: %s", err)
	}

	signedProof, err := s.wallet.SignTransactionTapscript(ctx, encodedProof, nil)
	if err != nil {
		return fmt.Errorf("failed to sign proof: %s", err)
	}

	if err := intent.Verify(signedProof, encodedMessage); err != nil {
		log.
			WithField("unsignedProof", encodedProof).
			WithField("signedProof", signedProof).
			WithField("encodedMessage", encodedMessage).
			Tracef("failed to verify intent proof: %s", err)
		return fmt.Errorf("invalid intent proof: %s", err)
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
		return fmt.Errorf("no matching intents found for intent proof")
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

	s.roundReportSvc.RoundStarted(round.Id)

	log.Debugf("started registration stage for new round: %s", round.Id)

	s.roundReportSvc.StageStarted(SelectIntentsStage)

	sessionDuration := s.sessionDuration
	roundMinParticipants := s.roundMinParticipantsCount
	roundMaxParticipants := s.roundMaxParticipantsCount
	scheduledSession, _ := s.repoManager.ScheduledSession().Get(context.Background())
	if scheduledSession != nil {
		nextStartTime, nextEndTime := calcNextScheduledSession(
			time.Now(),
			scheduledSession.StartTime, scheduledSession.EndTime, scheduledSession.Period,
		)
		if now := time.Now(); !now.Before(nextStartTime) && !now.After(nextEndTime) {
			log.WithFields(log.Fields{
				"duration":             scheduledSession.Duration,
				"minRoundParticipants": scheduledSession.RoundMinParticipantsCount,
				"maxRoundParticipants": scheduledSession.RoundMaxParticipantsCount,
			}).Debug("scheduled session is active")
			sessionDuration = scheduledSession.Duration
			roundMinParticipants = scheduledSession.RoundMinParticipantsCount
			roundMaxParticipants = scheduledSession.RoundMaxParticipantsCount
		}
	}

	roundTiming := newRoundTiming(sessionDuration)
	<-time.After(roundTiming.registrationDuration())
	s.wg.Add(1)
	go s.startConfirmation(roundTiming, roundMinParticipants, roundMaxParticipants)
}

func (s *service) startConfirmation(
	roundTiming roundTiming, roundMinParticipantsCount, roundMaxParticipantsCount int64,
) {
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
	if num < roundMinParticipantsCount {
		roundAborted = true
		err := fmt.Errorf("not enough intents registered %d/%d", num, roundMinParticipantsCount)
		log.WithError(err).Debugf("round %s aborted", roundId)
		return
	}
	if num > roundMaxParticipantsCount {
		num = roundMaxParticipantsCount
	}

	availableBalance, _, err := s.wallet.MainAccountBalance(ctx)
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to get main account balance: %s", err))
		log.WithError(err).Warn("failed to get main account balance")
		return
	}

	// TODO take into account available liquidity
	intentsPopped := s.cache.Intents().Pop(num)
	intents := make([]ports.TimedIntent, 0, len(intentsPopped))

	// for each intent, check if all boarding inputs are unspent
	// exclude any intent with at least one spent boarding input
	for _, intent := range intentsPopped {
		includeIntent := true

		for _, input := range intent.BoardingInputs {
			spent, err := s.wallet.GetOutpointStatus(ctx, input.Outpoint)
			if err != nil {
				log.WithError(err).
					Warnf("failed to get outpoint status for boarding input %s", input.Outpoint)
				continue
			}

			if spent {
				log.WithField("intent_id", intent.Id).
					Debugf("boarding input %s is spent", input.Outpoint)
				includeIntent = false
				break
			}
		}

		if includeIntent {
			intents = append(intents, intent)
		}
	}

	if len(intents) < int(s.roundMinParticipantsCount) {
		// repush valid intents back to the queue
		for _, intent := range intents {
			if err := s.cache.Intents().Push(intent.Intent, intent.BoardingInputs, intent.CosignersPublicKeys); err != nil {
				log.WithError(err).Warn("failed to re-push intents to the queue")
				continue
			}
		}

		roundAborted = true
		err := fmt.Errorf(
			"not enough intents registered %d/%d",
			len(intents),
			s.roundMinParticipantsCount,
		)
		log.WithError(err).Debugf("round %s aborted", roundId)
		return
	}

	s.roundReportSvc.SetIntentsNum(len(intents))

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

	s.roundReportSvc.StageEnded(SelectIntentsStage)
	s.roundReportSvc.StageStarted(ConfirmationStage)

	s.roundReportSvc.OpStarted(SendConfirmationEventOp)

	s.propagateBatchStartedEvent(intents)

	s.roundReportSvc.OpEnded(SendConfirmationEventOp)

	confirmedIntents := make([]ports.TimedIntent, 0)
	notConfirmedIntents := make([]ports.TimedIntent, 0)

	s.roundReportSvc.OpStarted(WaitForConfirmationOp)

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

	s.roundReportSvc.OpEnded(WaitForConfirmationOp)

	repushToQueue := notConfirmedIntents
	if int64(len(confirmedIntents)) < roundMinParticipantsCount {
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

	s.roundReportSvc.StageEnded(ConfirmationStage)
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

	s.roundReportSvc.StageStarted(BuildCommitmentTxStage)

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

	s.roundReportSvc.OpStarted(BuildCommitmentTxOp)

	commitmentTx, vtxoTree, connectorAddress, connectors, err := s.builder.BuildCommitmentTx(
		s.forfeitPubkey, intents, boardingInputs, connectorAddresses, cosignersPublicKeys,
	)
	if err != nil {
		s.cache.CurrentRound().Fail(fmt.Errorf("failed to create commitment tx: %s", err))
		log.WithError(err).Warn("failed to create commitment tx")
		return
	}

	s.roundReportSvc.OpEnded(BuildCommitmentTxOp)

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

	s.roundReportSvc.StageEnded(BuildCommitmentTxStage)

	flatVtxoTree := make(tree.FlatTxTree, 0)
	if vtxoTree != nil {
		s.roundReportSvc.StageStarted(TreeSigningStage)

		sweepClosure := script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{s.forfeitPubkey}},
			Locktime:        s.batchExpiry,
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

		s.roundReportSvc.OpStarted(CreateTreeNoncesOp)

		nonces, err := operatorSignerSession.GetNonces()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to get nonces: %s", err))
			log.WithError(err).Warn("failed to get nonces")
			return
		}

		coordinator.AddNonce(s.operatorPubkey, nonces)

		s.roundReportSvc.OpEnded(CreateTreeNoncesOp)

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

		s.roundReportSvc.OpStarted(SendUnsignedTreeEventOp)

		s.propagateRoundSigningStartedEvent(vtxoTree, listOfCosignersPubkeys)

		s.roundReportSvc.OpEnded(SendUnsignedTreeEventOp)

		log.Debugf("waiting for cosigners to submit their nonces...")

		s.roundReportSvc.OpStarted(WaitForTreeNoncesOp)

		select {
		case <-time.After(thirdOfRemainingDuration):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			err := fmt.Errorf(
				"musig2 signing session timed out (nonce collection), collected %d/%d nonces",
				len(signingSession.Nonces), len(uniqueSignerPubkeys),
			)
			s.cache.CurrentRound().Fail(err)
			log.Warn(err)

			// ban all the scripts that didn't submitted their nonces
			go s.banNoncesCollectionTimeout(ctx, roundId, signingSession, registeredIntents)
			return
		case <-s.cache.TreeSigingSessions().NoncesCollected(roundId):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			for pubkey, nonce := range signingSession.Nonces {
				buf, _ := hex.DecodeString(pubkey)
				pk, _ := btcec.ParsePubKey(buf)
				coordinator.AddNonce(pk, nonce)
			}
		}

		s.roundReportSvc.OpEnded(WaitForTreeNoncesOp)

		log.Debugf("all nonces collected for round %s", roundId)

		s.roundReportSvc.OpStarted(AggregateNoncesOp)

		aggregatedNonces, err := coordinator.AggregateNonces()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to aggregate nonces: %s", err))
			log.WithError(err).Warn("failed to aggregate nonces")
			return
		}
		operatorSignerSession.SetAggregatedNonces(aggregatedNonces)

		s.roundReportSvc.OpEnded(AggregateNoncesOp)

		log.Debugf("nonces aggregated for round %s", roundId)

		s.roundReportSvc.OpStarted(SendAggregatedTreeNoncesEventOp)

		s.propagateRoundSigningNoncesGeneratedEvent(
			aggregatedNonces,
			coordinator.GetPublicNonces(),
			vtxoTree,
		)

		s.roundReportSvc.OpEnded(SendAggregatedTreeNoncesEventOp)

		s.roundReportSvc.OpStarted(SignTreeOp)

		operatorSignatures, err := operatorSignerSession.Sign()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to sign tree: %s", err))
			log.WithError(err).Warn("failed to sign tree")
			return
		}
		_, err = coordinator.AddSignatures(s.operatorPubkey, operatorSignatures)
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("invalid operator tree signature: %s", err))
			log.WithError(err).Warn("invalid operator tree signature")
			return
		}

		s.roundReportSvc.OpEnded(SignTreeOp)

		log.Debugf("tree signed by us for round %s", roundId)

		log.Debugf("waiting for cosigners to submit their signatures...")

		s.roundReportSvc.OpStarted(WaitForTreeSignaturesOp)

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

			// ban all the scripts that didn't submitted their signatures
			go s.banSignaturesCollectionTimeout(ctx, roundId, signingSession, registeredIntents)
			return
		case <-s.cache.TreeSigingSessions().SignaturesCollected(roundId):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			cosignersToBan := make(map[string]domain.Crime)

			for pubkey, sig := range signingSession.Signatures {
				buf, _ := hex.DecodeString(pubkey)
				pk, _ := btcec.ParsePubKey(buf)
				shouldBan, err := coordinator.AddSignatures(pk, sig)
				if err != nil && !shouldBan {
					// an unexpected error has occurred during the signature validation, round should fail
					s.cache.CurrentRound().
						Fail(fmt.Errorf("failed to validate signatures: %s", err))
					log.WithError(err).Warn("failed to validate signatures")
					return
				}

				if shouldBan {
					reason := fmt.Sprintf("invalid signature for cosigner pubkey %s", pubkey)
					if err != nil {
						reason = err.Error()
					}

					cosignersToBan[pubkey] = domain.Crime{
						Type:    domain.CrimeTypeMusig2InvalidSignature,
						RoundID: roundId,
						Reason:  reason,
					}
				}
			}

			// if some cosigners have to be banned, it means invalid signatures occured
			// the round fails and those cosigners are banned
			if len(cosignersToBan) > 0 {
				err = fmt.Errorf("some musig2 signatures are invalid")
				s.cache.CurrentRound().Fail(err)
				log.Warn(err)
				go s.banCosignerInputs(ctx, cosignersToBan, registeredIntents)
				return
			}
		}

		s.roundReportSvc.OpEnded(WaitForTreeSignaturesOp)

		log.Debugf("all signatures collected for round %s", roundId)

		s.roundReportSvc.OpStarted(AggregateTreeSignaturesOp)

		signedTree, err := coordinator.SignTree()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to aggregate tree signatures: %s", err))
			log.WithError(err).Warn("failed to aggregate tree signatures")
			return
		}

		s.roundReportSvc.OpEnded(AggregateTreeSignaturesOp)

		log.Debugf("vtxo tree signed for round %s", roundId)

		vtxoTree = signedTree
		flatVtxoTree, err = vtxoTree.Serialize()
		if err != nil {
			s.cache.CurrentRound().Fail(fmt.Errorf("failed to serialize vtxo tree: %s", err))
			log.WithError(err).Warn("failed to serialize vtxo tree")
			return
		}

		s.roundReportSvc.StageEnded(TreeSigningStage)
	}

	round := s.cache.CurrentRound().Get()
	_, err = round.StartFinalization(
		connectorAddress, flatConnectors, flatVtxoTree,
		round.CommitmentTxid, round.CommitmentTx, s.batchExpiry.Seconds(),
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

	s.roundReportSvc.StageStarted(ForfeitTxsCollectionStage)

	commitmentTx, err := psbt.NewFromRawBytes(
		strings.NewReader(s.cache.CurrentRound().Get().CommitmentTx), true,
	)
	if err != nil {
		changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to parse commitment tx: %s", err))
		log.WithError(err).Warn("failed to parse commitment tx")
		return
	}

	commitmentTxid := commitmentTx.UnsignedTx.TxID()
	includesBoardingInputs := s.cache.BoardingInputs().Get() > 0
	txToSign := s.cache.CurrentRound().Get().CommitmentTx
	forfeitTxs := make([]domain.ForfeitTx, 0)

	if s.cache.ForfeitTxs().Len() > 0 || includesBoardingInputs {
		s.roundReportSvc.OpStarted(WaitForForfeitTxsOp)

		remainingTime := roundTiming.remainingDuration()
		select {
		case <-s.forfeitsBoardingSigsChan:
			log.Debug("all forfeit txs and boarding inputs signatures have been sent")
		case <-time.After(remainingTime):
			log.Debug("timeout waiting for forfeit txs and boarding inputs signatures")
		}

		s.roundReportSvc.OpEnded(WaitForForfeitTxsOp)

		forfeitTxList, err := s.cache.ForfeitTxs().Pop()
		if err != nil {
			changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to finalize round: %s", err))
			log.WithError(err).Warn("failed to finalize round")
			return
		}

		// some forfeits are not signed, we must ban the associated scripts
		if !s.cache.ForfeitTxs().AllSigned() {
			go s.banForfeitCollectionTimeout(ctx, roundId)

			err = fmt.Errorf("missing forfeit transactions")
			changes = s.cache.CurrentRound().Fail(err)
			log.Warn(err)
			return
		}

		// verify is forfeit tx signatures are valid, if not we ban the associated scripts
		if convictions := s.verifyForfeitTxsSigs(roundId, forfeitTxList); len(convictions) > 0 {
			err = fmt.Errorf("invalid forfeit txs signature")
			changes = s.cache.CurrentRound().Fail(err)
			go func() {
				if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
					log.WithError(err).Warn("failed to ban vtxos")
				}
			}()
			return
		}

		s.roundReportSvc.OpStarted(VerifyForfeitsSignaturesOp)

		commitmentTx, err = psbt.NewFromRawBytes(
			strings.NewReader(s.cache.CurrentRound().Get().CommitmentTx), true,
		)
		if err != nil {
			changes = s.cache.CurrentRound().
				Fail(fmt.Errorf("failed to parse commitment tx: %s", err))
			log.WithError(err).Warn("failed to parse commitment tx")
			return
		}

		s.roundReportSvc.OpEnded(VerifyForfeitsSignaturesOp)

		boardingInputsIndexes := make([]int, 0)
		convictions := make([]domain.Conviction, 0)
		for i, in := range commitmentTx.Inputs {
			if len(in.TaprootLeafScript) > 0 {
				if len(in.TaprootScriptSpendSig) == 0 {
					outputScript, err := outputScriptFromTaprootLeafScript(*in.TaprootLeafScript[0])
					if err != nil {
						log.WithError(err).Warnf("failed to compute output script for input %d", i)
						continue
					}

					convictions = append(
						convictions,
						domain.NewScriptConviction(outputScript, domain.Crime{
							Type:    domain.CrimeTypeBoardingInputSubmission,
							RoundID: roundId,
							Reason:  fmt.Sprintf("missing tapscript spend sig for input %d", i),
						}, &s.banDuration),
					)
					continue
				}

				boardingInputsIndexes = append(boardingInputsIndexes, i)
			}
		}

		if len(convictions) > 0 {
			err = fmt.Errorf("missing boarding inputs signatures")
			changes = s.cache.CurrentRound().Fail(err)
			go func() {
				if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
					log.WithError(err).Warn("failed to ban boarding inputs")
				}
			}()
			return
		}

		if len(boardingInputsIndexes) > 0 {
			s.roundReportSvc.OpStarted(VerifyBoardingInputsSignaturesOp)

			txToSign, err = s.signer.SignTransactionTapscript(
				ctx,
				s.cache.CurrentRound().Get().CommitmentTx,
				boardingInputsIndexes,
			)
			if err != nil {
				changes = s.cache.CurrentRound().Fail(
					fmt.Errorf("failed to sign commitment tx: %s", err),
				)
				log.WithError(err).Warn("failed to sign commitment tx")
				return
			}

			s.roundReportSvc.OpEnded(VerifyBoardingInputsSignaturesOp)
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

	s.roundReportSvc.StageEnded(ForfeitTxsCollectionStage)

	log.Debugf("signing commitment transaction for round %s\n", roundId)

	s.roundReportSvc.StageStarted(SignAndPublishCommitmentTxStage)

	s.roundReportSvc.OpStarted(SignCommitmentTxOp)

	signedCommitmentTx, err := s.wallet.SignTransaction(ctx, txToSign, true)
	if err != nil {
		changes = s.cache.CurrentRound().Fail(fmt.Errorf("failed to sign commitment tx: %s", err))
		log.WithError(err).Warn("failed to sign commitment tx")
		return
	}

	s.roundReportSvc.OpEnded(SignCommitmentTxOp)
	s.roundReportSvc.OpStarted(PublishCommitmentTxOp)

	if _, err := s.wallet.BroadcastTransaction(ctx, signedCommitmentTx); err != nil {
		changes = s.cache.CurrentRound().Fail(
			fmt.Errorf("failed to broadcast commitment tx: %s", err),
		)
		log.WithError(err).Warn("failed to broadcast commitment tx")
		return
	}

	s.roundReportSvc.OpEnded(PublishCommitmentTxOp)

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

	totalInputsVtxos := s.cache.ForfeitTxs().Len()
	totalOutputVtxos := len(s.cache.CurrentRound().Get().VtxoTree.Leaves())
	numOfTreeNodes := len(s.cache.CurrentRound().Get().VtxoTree)

	s.roundReportSvc.StageEnded(SignAndPublishCommitmentTxStage)

	s.roundReportSvc.RoundEnded(commitmentTxid, totalInputsVtxos, totalOutputVtxos, numOfTreeNodes)

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
					if len(vtxos) <= 0 {
						log.Warnf("vtxo %s not found, skipping...", v.String())
						return
					}

					vtxo := vtxos[0]

					if vtxo.Preconfirmed {
						go func() {
							txs, err := s.repoManager.Rounds().GetTxsWithTxids(
								ctx, []string{vtxo.Txid},
							)
							if err != nil {
								log.WithError(err).Warn("failed to retrieve txs, skipping...")
								return
							}

							if len(txs) <= 0 {
								log.Warnf("tx %s not found", vtxo.Txid)
								return
							}

							ptx, err := psbt.NewFromRawBytes(strings.NewReader(txs[0]), true)
							if err != nil {
								log.WithError(err).Warn("failed to parse tx, skipping...")
								return
							}

							// remove sweeper task for the associated checkpoint outputs
							for _, in := range ptx.UnsignedTx.TxIn {
								taskId := in.PreviousOutPoint.Hash.String()
								s.sweeper.removeTask(taskId)
								log.Debugf("sweeper: unscheduled task for tx %s", taskId)
							}
						}()
					}

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
		s.roundReportSvc.OpStarted(SendSignedTreeEventOp)

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
		s.roundReportSvc.OpEnded(SendSignedTreeEventOp)
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
		BatchExpiry:     s.batchExpiry.Value,
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
	publicNoncesMap map[string]tree.TreeNonces,
	vtxoTree *tree.TxTree,
) {
	events := treeTxNoncesEvents(vtxoTree, s.cache.CurrentRound().Get().Id, publicNoncesMap)
	events = append(events, TreeNoncesAggregated{
		RoundEvent: domain.RoundEvent{
			Id:   s.cache.CurrentRound().Get().Id,
			Type: domain.EventTypeUndefined,
		},
		Nonces: combinedNonces,
	})

	s.eventsCh <- events
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

	expirationTimestamp := s.sweeper.scheduler.AddNow(int64(s.batchExpiry.Value))

	vtxoTree, err := tree.NewTxTree(round.VtxoTree)
	if err != nil {
		log.WithError(err).Warn("failed to create vtxo tree")
		return
	}

	if err := s.sweeper.scheduleBatchSweep(expirationTimestamp, round.CommitmentTxid, vtxoTree); err != nil {
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
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return &chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		return &chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return &arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
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

func (s *service) verifyForfeitTxsSigs(roundId string, txs []string) []domain.Conviction {
	nbWorkers := runtime.NumCPU()
	jobs := make(chan string, len(txs))

	mutx := &sync.Mutex{}
	crimes := make(map[string]domain.Crime) // vtxo script -> crime

	wg := sync.WaitGroup{}
	wg.Add(nbWorkers)

	for range nbWorkers {
		go func() {
			defer wg.Done()

			for tx := range jobs {
				valid, ptx, err := s.builder.VerifyTapscriptPartialSigs(tx, false)
				if err == nil && !valid {
					err = fmt.Errorf("invalid signature for forfeit tx %s", ptx.UnsignedTx.TxID())
				}
				if err != nil {
					verificationErr := err
					vtxoOutputScript, extractErr := extractVtxoScriptFromSignedForfeitTx(tx)
					if extractErr != nil {
						log.WithError(extractErr).
							Errorf(
								"failed to extract vtxo script from forfeit tx %s, cannot ban",
								ptx.UnsignedTx.TxID(),
							)
						continue
					}

					crime := domain.Crime{
						Type:    domain.CrimeTypeForfeitInvalidSignature,
						RoundID: roundId,
						Reason:  verificationErr.Error(),
					}

					mutx.Lock()
					if _, ok := crimes[vtxoOutputScript]; ok {
						crime.Reason += fmt.Sprintf(", %s", crimes[vtxoOutputScript].Reason)
					}
					crimes[vtxoOutputScript] = crime
					mutx.Unlock()
				}
			}
		}()
	}

	for _, tx := range txs {
		jobs <- tx
	}
	close(jobs)
	wg.Wait()

	convictions := make([]domain.Conviction, 0, len(crimes))
	for outScript, crime := range crimes {
		convictions = append(convictions, domain.NewScriptConviction(
			outScript, crime, &s.banDuration,
		))
	}

	return convictions
}

func extractVtxoScriptFromSignedForfeitTx(tx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse psbt: %s", err)
	}

	for _, input := range ptx.Inputs {
		// at this point, the connector is not signed so the vtxo input is the one with Tapscript sigs
		if len(input.TaprootScriptSpendSig) == 0 {
			continue
		}

		if len(input.TaprootLeafScript) == 0 {
			return "", fmt.Errorf("missing taproot leaf script for vtxo input, invalid forfeit tx")
		}

		return outputScriptFromTaprootLeafScript(*input.TaprootLeafScript[0])
	}

	return "", fmt.Errorf("no vtxo script found in forfeit tx")
}

func outputScriptFromTaprootLeafScript(tapLeaf psbt.TaprootTapLeafScript) (string, error) {
	controlBlock, err := txscript.ParseControlBlock(tapLeaf.ControlBlock)
	if err != nil {
		return "", err
	}

	rootHash := controlBlock.RootHash(tapLeaf.Script)
	tapKeyFromControlBlock := txscript.ComputeTaprootOutputKey(
		script.UnspendableKey(), rootHash[:],
	)

	pkscript, err := script.P2TRScript(tapKeyFromControlBlock)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(pkscript), nil
}

// propagateTransactionEvent propagates the transaction event to the indexer and the transaction events channels
func (s *service) propagateTransactionEvent(event TransactionEvent) {
	go func() {
		s.indexerTxEventsCh <- event
	}()
	go func() {
		s.transactionEventsCh <- event
	}()
}
