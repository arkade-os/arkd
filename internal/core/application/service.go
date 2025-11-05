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
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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
	sweeperCancel  context.CancelFunc
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
	publicUnilateralExitDelay arklib.RelativeLocktime
	boardingExitDelay         arklib.RelativeLocktime
	roundMinParticipantsCount int64
	roundMaxParticipantsCount int64
	utxoMaxAmount             int64
	utxoMinAmount             int64
	vtxoMaxAmount             int64
	vtxoMinSettlementAmount   int64
	vtxoMinOffchainTxAmount   int64
	allowCSVBlockType         bool

	// fees
	onchainOutputFee int64 // expected fee in satoshis per onchain output registered in intents

	// cutoff date (unix timestamp) before which CSV validation is skipped for VTXOs
	vtxoNoCsvValidationCutoffTime time.Time

	settlementMinExpiryGap time.Duration

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
	vtxoTreeExpiry, unilateralExitDelay, publicUnilateralExitDelay,
	boardingExitDelay, checkpointExitDelay arklib.RelativeLocktime,
	sessionDuration, roundMinParticipantsCount, roundMaxParticipantsCount,
	utxoMaxAmount, utxoMinAmount, vtxoMaxAmount, vtxoMinAmount, banDuration, banThreshold int64,
	network arklib.Network,
	allowCSVBlockType bool,
	noteUriPrefix string,
	scheduledSessionStartTime, scheduledSessionEndTime time.Time,
	scheduledSessionPeriod, scheduledSessionDuration time.Duration,
	scheduledSessionRoundMinParticipantsCount, scheduledSessionRoundMaxParticipantsCount int64,
	settlementMinExpiryGap int64,
	vtxoNoCsvValidationCutoffTime time.Time,
	onchainOutputFee int64,
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
		network:                   network,
		signerPubkey:              signerPubkey,
		forfeitPubkey:             forfeitPubkey,
		batchExpiry:               vtxoTreeExpiry,
		sessionDuration:           time.Duration(sessionDuration) * time.Second,
		banDuration:               time.Duration(banDuration) * time.Second,
		banThreshold:              banThreshold,
		unilateralExitDelay:       unilateralExitDelay,
		publicUnilateralExitDelay: publicUnilateralExitDelay,
		allowCSVBlockType:         allowCSVBlockType,
		wallet:                    wallet,
		signer:                    signer,
		repoManager:               repoManager,
		builder:                   builder,
		cache:                     cache,
		scanner:                   scanner,
		sweeper: newSweeper(
			wallet, repoManager, builder, scheduler, noteUriPrefix,
		),
		boardingExitDelay:             boardingExitDelay,
		operatorPrvkey:                operatorSigningKey,
		operatorPubkey:                operatorSigningKey.PubKey(),
		forfeitsBoardingSigsChan:      make(chan struct{}, 1),
		roundMinParticipantsCount:     roundMinParticipantsCount,
		roundMaxParticipantsCount:     roundMaxParticipantsCount,
		utxoMaxAmount:                 utxoMaxAmount,
		utxoMinAmount:                 utxoMinAmount,
		vtxoMaxAmount:                 vtxoMaxAmount,
		vtxoMinSettlementAmount:       vtxoMinSettlementAmount,
		vtxoMinOffchainTxAmount:       vtxoMinOffchainTxAmount,
		eventsCh:                      make(chan []domain.Event, 64),
		transactionEventsCh:           make(chan TransactionEvent, 64),
		indexerTxEventsCh:             make(chan TransactionEvent, 64),
		stop:                          cancel,
		ctx:                           ctx,
		wg:                            &sync.WaitGroup{},
		checkpointTapscript:           checkpointTapscript,
		roundReportSvc:                roundReportSvc,
		settlementMinExpiryGap:        time.Duration(settlementMinExpiryGap) * time.Second,
		vtxoNoCsvValidationCutoffTime: vtxoNoCsvValidationCutoffTime,
		onchainOutputFee:              onchainOutputFee,
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

			spentVtxos, err := svc.repoManager.Vtxos().GetVtxos(
				context.Background(), spentVtxoKeys,
			)
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

func (s *service) Start() errors.Error {
	log.Debug("starting sweeper service...")
	ctx, cancel := context.WithCancel(context.Background())
	s.sweeperCancel = cancel
	go func() {
		if err := s.sweeper.start(ctx); err != nil {
			log.WithError(err).Warn("failed to start sweeper")
		}
		log.Info("sweeper service started")
	}()

	log.Debug("starting app service...")
	s.wg.Add(1)
	go s.start()
	return nil
}

func (s *service) Stop() {
	ctx := context.Background()

	s.stop()
	s.wg.Wait()
	s.sweeperCancel()
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
) ([]string, string, string, errors.Error) {
	var err error
	var arkPtx *psbt.Packet
	arkPtx, err = psbt.NewFromRawBytes(strings.NewReader(signedArkTx), true)
	if err != nil {
		return nil, "", "", errors.INVALID_ARK_PSBT.New("failed to parse tx: %w", err).
			WithMetadata(errors.PsbtMetadata{Tx: signedArkTx})
	}
	txid := arkPtx.UnsignedTx.TxID()

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
			return nil, "", "", errors.INVALID_CHECKPOINT_PSBT.New("failed to parse tx: %w", err).
				WithMetadata(errors.PsbtMetadata{Tx: tx})
		}

		txid := checkpointPtx.UnsignedTx.TxID()
		if len(checkpointPtx.UnsignedTx.TxIn) < 1 {
			return nil, "", "", errors.INVALID_PSBT_MISSING_INPUT.New(
				"invalid checkpoint tx %s", txid,
			).WithMetadata(errors.PsbtInputMetadata{Txid: txid})
		}

		vtxoKey := domain.Outpoint{
			Txid: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		}
		checkpointTxs[txid] = tx
		checkpointPsbts[txid] = checkpointPtx
		checkpointTxsByVtxoKey[vtxoKey] = txid
		spentVtxoKeys = append(spentVtxoKeys, vtxoKey)
	}

	event, err := offchainTx.Request(txid, signedArkTx, checkpointTxs)
	if err != nil {
		return nil, "", "", errors.INTERNAL_ERROR.Wrap(err)
	}
	changes = []domain.Event{event}

	// get all the vtxos inputs
	spentVtxos, err := vtxoRepo.GetVtxos(ctx, spentVtxoKeys)
	if err != nil {
		return nil, "", "", errors.INTERNAL_ERROR.New("failed to fetch vtxos: %w", err).
			WithMetadata(
				map[string]any{"vtxos": spentVtxoKeys},
			)
	}

	if len(spentVtxos) != len(spentVtxoKeys) {
		vtxoOutpoints := make([]string, 0)
		for _, vtxo := range spentVtxoKeys {
			vtxoOutpoints = append(vtxoOutpoints, vtxo.String())
		}

		gotVtxos := make([]string, 0)
		for _, vtxo := range spentVtxos {
			gotVtxos = append(gotVtxos, vtxo.Outpoint.String())
		}

		return nil, "", "", errors.VTXO_NOT_FOUND.New("some vtxos not found").
			WithMetadata(errors.VtxoNotFoundMetadata{
				VtxoOutpoints: vtxoOutpoints,
				GotVtxos:      gotVtxos,
			})
	}

	// check if any of the spent vtxos are banned
	for _, vtxo := range spentVtxos {
		if err := s.checkIfBanned(ctx, vtxo); err != nil {
			return nil, "", "", errors.VTXO_BANNED.Wrap(err).
				WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxo.Outpoint.String()})
		}
	}

	if exists, vtxo := s.cache.Intents().IncludesAny(spentVtxoKeys); exists {
		return nil, "", "", errors.VTXO_ALREADY_REGISTERED.New("%s already registered", vtxo).
			WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxo})
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
	for inputIndex, in := range arkPtx.UnsignedTx.TxIn {
		checkpointPsbt := checkpointPsbts[in.PreviousOutPoint.Hash.String()]
		checkpointTxid := checkpointPsbt.UnsignedTx.TxID()
		input := checkpointPsbt.Inputs[0]

		if input.WitnessUtxo == nil {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"missing witness utxo on input %d", inputIndex,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		if len(input.TaprootLeafScript) == 0 {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"missing tapscript leaf on input %d", inputIndex,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}
		if len(input.TaprootLeafScript) != 1 {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"expected exactly one taproot leaf script on input %d, got %d",
				inputIndex,
				len(input.TaprootLeafScript),
			).
				WithMetadata(errors.InputMetadata{
					Txid:       checkpointTxid,
					InputIndex: inputIndex,
				})
		}
		spendingTapscript := input.TaprootLeafScript[0]
		if spendingTapscript == nil {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"missing tapscript leaf on input %d", inputIndex,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		taptreeFields, err := txutils.GetArkPsbtFields(
			checkpointPsbt,
			0,
			txutils.VtxoTaprootTreeField,
		)
		if err != nil || len(taptreeFields) == 0 {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"missing taptree on input %d", inputIndex,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		taptree := taptreeFields[0]

		vtxoScript, err := script.ParseVtxoScript(taptree)
		if err != nil {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"failed to parse taptree field in tx %s: %s", checkpointTxid, err,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		outpoint := domain.Outpoint{
			Txid: checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		}

		vtxo, exists := indexedSpentVtxos[outpoint]
		if !exists {
			return nil, "", "", errors.INTERNAL_ERROR.New(
				"can't find vtxo associated with checkpoint input %s", outpoint,
			).WithMetadata(map[string]any{
				"vtxo":          outpoint,
				"vtxos_from_db": indexedSpentVtxos,
			})
		}

		// make sure we don't use the same vtxo twice
		delete(indexedSpentVtxos, outpoint)

		vtxoOutpoint := vtxo.Outpoint.String()

		if vtxo.Spent {
			return nil, "", "", errors.VTXO_ALREADY_SPENT.New("%s already spent", vtxo.Outpoint).
				WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxoOutpoint})
		}

		if vtxo.Unrolled {
			return nil, "", "", errors.VTXO_ALREADY_UNROLLED.New(
				"%s already unrolled", vtxo.Outpoint,
			).WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxoOutpoint})
		}
		if vtxo.Swept || !s.sweeper.scheduler.AfterNow(vtxo.ExpiresAt) {
			// if we reach this point, it means vtxo.Spent = false so the vtxo is recoverable
			return nil, "", "", errors.VTXO_RECOVERABLE.New("%s is recoverable", vtxo.Outpoint).
				WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxoOutpoint})
		}

		if vtxo.IsNote() {
			return nil, "", "", errors.OFFCHAIN_TX_SPENDING_NOTE.New(
				"%s is a note", vtxo.Outpoint,
			).WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxoOutpoint})
		}

		// validate the vtxo script
		minAllowedExitDelay := s.unilateralExitDelay

		// if the vtxo was created before the vtxoNoCsvValidationCutoffTime date, we use the
		// smallest exit delay as the minimum allowed exit delay in validation: making the CSV
		// check always successful.
		if time.Unix(vtxo.CreatedAt, 0).Before(s.vtxoNoCsvValidationCutoffTime) {
			smallestExitDelay, err := vtxoScript.SmallestExitDelay()
			if err != nil {
				return nil, "", "", errors.INVALID_VTXO_SCRIPT.New(
					"failed to get smallest exit delay: %w", err,
				).WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: taptree})
			}
			minAllowedExitDelay = *smallestExitDelay
		}

		if err := vtxoScript.Validate(
			s.signerPubkey, minAllowedExitDelay, s.allowCSVBlockType,
		); err != nil {
			return nil, "", "", errors.INVALID_VTXO_SCRIPT.Wrap(err).
				WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: taptree})
		}

		witnessUtxoScript := input.WitnessUtxo.PkScript

		tapKeyFromTapscripts, _, err := vtxoScript.TapTree()
		if err != nil {
			return nil, "", "", errors.INVALID_VTXO_SCRIPT.New("failed to compute taproot tree").
				WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: taptree})
		}

		serializedTapKey := hex.EncodeToString(schnorr.SerializePubKey(tapKeyFromTapscripts))
		if vtxo.PubKey != serializedTapKey {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"expected %s, got %s", vtxo.PubKey, serializedTapKey,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		pkScriptFromTapscripts, err := script.P2TRScript(tapKeyFromTapscripts)
		if err != nil {
			return nil, "", "", errors.INVALID_VTXO_SCRIPT.New(
				"failed to compute P2TR script from tapkey",
			).WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: taptree})
		}

		if !bytes.Equal(witnessUtxoScript, pkScriptFromTapscripts) {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"witness utxo script mismatch: expected %x, got %x",
				witnessUtxoScript, pkScriptFromTapscripts,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		vtxoPubkeyBuf, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return nil, "", "", errors.INTERNAL_ERROR.New("failed to decode vtxo pubkey").
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		vtxoPubkey, err := schnorr.ParsePubKey(vtxoPubkeyBuf)
		if err != nil {
			return nil, "", "", errors.INTERNAL_ERROR.New("failed to parse vtxo pubkey").
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		// verify witness utxo
		pkscript, err := script.P2TRScript(vtxoPubkey)
		if err != nil {
			return nil, "", "", errors.INTERNAL_ERROR.New(
				"failed to compute P2TR script from vtxo pubkey",
			).WithMetadata(map[string]any{
				"vtxo_pubkey": vtxo.PubKey,
			})
		}

		if !bytes.Equal(input.WitnessUtxo.PkScript, pkscript) {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"witness utxo script mismatch: expected %x, got %x",
				input.WitnessUtxo.PkScript, pkscript,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		if input.WitnessUtxo.Value != int64(vtxo.Amount) {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"witness utxo value mismatch: expected %d, got %d",
				vtxo.Amount, input.WitnessUtxo.Value,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		// verify forfeit closure script
		closure, err := script.DecodeClosure(spendingTapscript.Script)
		if err != nil {
			return nil, "", "", errors.INVALID_PSBT_INPUT.Wrap(err).
				WithMetadata(errors.InputMetadata{
					Txid:       checkpointTxid,
					InputIndex: inputIndex,
				})
		}

		var locktime *arklib.AbsoluteLocktime
		switch c := closure.(type) {
		case *script.CLTVMultisigClosure:
			locktime = &c.Locktime
		case *script.MultisigClosure, *script.ConditionMultisigClosure:
		default:
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"invalid spending tapscript on input %d: %x", inputIndex, spendingTapscript.Script,
			).
				WithMetadata(errors.InputMetadata{
					Txid:       checkpointTxid,
					InputIndex: inputIndex,
				})
		}

		if locktime != nil {
			blocktimestamp, err := s.wallet.GetCurrentBlockTime(ctx)
			if err != nil {
				return nil, "", "", errors.INTERNAL_ERROR.New(
					"get current block time failed: %w",
					err,
				)
			}
			if !locktime.IsSeconds() {
				if *locktime > arklib.AbsoluteLocktime(blocktimestamp.Height) {
					return nil, "", "", errors.FORFEIT_CLOSURE_LOCKED.New(
						"%d > %d (blockheight)",
						*locktime, blocktimestamp.Time,
					).WithMetadata(errors.ForfeitClosureLockedMetadata{
						Locktime:        int(*locktime),
						CurrentLocktime: int(blocktimestamp.Height),
						Type:            "height",
					})
				}
			} else {
				if *locktime > arklib.AbsoluteLocktime(blocktimestamp.Time) {
					return nil, "", "", errors.FORFEIT_CLOSURE_LOCKED.New(
						"%d > %d (blocktime)",
						*locktime, blocktimestamp.Time,
					).WithMetadata(errors.ForfeitClosureLockedMetadata{
						Locktime:        int(*locktime),
						CurrentLocktime: int(blocktimestamp.Time),
						Type:            "time",
					})
				}
			}
		}

		ctrlBlock, err := txscript.ParseControlBlock(spendingTapscript.ControlBlock)
		if err != nil {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"failed to parse control block %x", spendingTapscript.ControlBlock,
			).WithMetadata(errors.InputMetadata{
				Txid:       checkpointTxid,
				InputIndex: inputIndex,
			})
		}

		tapscript := &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: spendingTapscript.Script,
		}

		if len(arkPtx.Inputs[inputIndex].TaprootLeafScript) == 0 {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"missing taproot leaf script in ark tx input %d", inputIndex,
			).WithMetadata(errors.InputMetadata{
				Txid:       txid,
				InputIndex: inputIndex,
			})
		}

		ins = append(ins, offchain.VtxoInput{
			Outpoint:           &checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint,
			Tapscript:          tapscript,
			RevealedTapscripts: taptree,
			Amount:             int64(vtxo.Amount),
		})
	}

	// iterate over the ark tx inputs and verify that the user signed a collaborative path
	signerXOnlyPubkey := schnorr.SerializePubKey(s.signerPubkey)
	for inputIndex, input := range arkPtx.Inputs {
		if len(input.TaprootScriptSpendSig) == 0 {
			return nil, "", "", errors.INVALID_PSBT_INPUT.New(
				"missing tapscript spend sig in ark tx input %d", inputIndex,
			).WithMetadata(errors.InputMetadata{
				Txid:       txid,
				InputIndex: inputIndex,
			})
		}

		hasSig := false

		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, signerXOnlyPubkey) {
				if _, err := schnorr.ParsePubKey(sig.XOnlyPubKey); err != nil {
					return nil, "", "", errors.INVALID_PSBT_INPUT.New(
						"invalid xonly pubkey in tx input signature %d", inputIndex,
					).WithMetadata(errors.InputMetadata{
						Txid:       txid,
						InputIndex: inputIndex,
					})
				}
				hasSig = true
				break
			}
		}

		if !hasSig {
			return nil, "", "", errors.ARK_TX_INPUT_NOT_SIGNED.New("tx %s is not signed", txid).
				WithMetadata(errors.InputMetadata{
					Txid:       txid,
					InputIndex: inputIndex,
				})
		}
	}

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, "", "", errors.INTERNAL_ERROR.New("get dust amount failed: %w", err)
	}

	outputs := make([]*wire.TxOut, 0) // outputs excluding the anchor
	foundAnchor := false
	foundOpReturn := false

	for outIndex, out := range arkPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
			if foundAnchor {
				return nil, "", "", errors.MALFORMED_ARK_TX.New(
					"tx %s has multiple anchor outputs", txid,
				).WithMetadata(errors.PsbtMetadata{Tx: signedArkTx})
			}
			foundAnchor = true
			continue
		}

		// verify we don't have multiple OP_RETURN outputs
		if bytes.HasPrefix(out.PkScript, []byte{txscript.OP_RETURN}) {
			if foundOpReturn {
				return nil, "", "", errors.MALFORMED_ARK_TX.New(
					"tx %s has multiple op return outputs", txid,
				).WithMetadata(errors.PsbtMetadata{Tx: signedArkTx})
			}
			foundOpReturn = true
		}

		if s.vtxoMaxAmount >= 0 {
			if out.Value > s.vtxoMaxAmount {
				return nil, "", "", errors.AMOUNT_TOO_HIGH.New(
					"output #%d amount (%d) is higher than max vtxo amount: %d",
					outIndex, out.Value, s.vtxoMaxAmount,
				).WithMetadata(errors.AmountTooHighMetadata{
					OutputIndex: outIndex,
					Amount:      int(out.Value),
					MaxAmount:   int(s.vtxoMaxAmount),
				})
			}
		}
		if out.Value < s.vtxoMinOffchainTxAmount {
			return nil, "", "", errors.AMOUNT_TOO_LOW.New(
				"output #%d amount is lower than min vtxo amount: %d",
				outIndex, s.vtxoMinOffchainTxAmount,
			).WithMetadata(errors.AmountTooLowMetadata{
				OutputIndex: outIndex,
				Amount:      int(s.vtxoMinOffchainTxAmount),
				MinAmount:   int(s.vtxoMinOffchainTxAmount),
			})
		}

		if out.Value < int64(dust) {
			// if the output is below dust limit, it must be using OP_RETURN-style vtxo pkscript
			if !script.IsSubDustScript(out.PkScript) {
				return nil, "", "", errors.AMOUNT_TOO_LOW.New(
					"output #%d amount is below dust limit (%d < %d) but is not using "+
						"OP_RETURN output script", outIndex, out.Value, dust,
				).WithMetadata(errors.AmountTooLowMetadata{
					OutputIndex: outIndex,
					Amount:      int(out.Value),
					MinAmount:   int(dust),
				})
			}
		}

		outputs = append(outputs, out)
	}

	if !foundAnchor {
		return nil, "", "", errors.MALFORMED_ARK_TX.New("missing anchor output in ark tx %s", txid).
			WithMetadata(errors.PsbtMetadata{Tx: signedArkTx})
	}

	// recompute all txs (checkpoint txs + ark tx)
	rebuiltArkTx, rebuiltCheckpointTxs, err := offchain.BuildTxs(
		ins, outputs, s.checkpointTapscript,
	)
	if err != nil {
		return nil, "", "", errors.INTERNAL_ERROR.New("failed to rebuild ark transaction: %w", err).
			WithMetadata(map[string]any{
				"ark_tx":               signedArkTx,
				"outputs":              outputs,
				"ins":                  ins,
				"checkpoint_tapscript": s.checkpointTapscript,
			})
	}

	// verify the checkpoints txs integrity
	if len(rebuiltCheckpointTxs) != len(checkpointPsbts) {
		return nil, "", "", errors.CHECKPOINT_MISMATCH.New(
			"invalid number of checkpoint txs, expected %d got %d",
			len(rebuiltCheckpointTxs), len(checkpointPsbts),
		)
	}

	for _, rebuiltCheckpointTx := range rebuiltCheckpointTxs {
		rebuiltTxid := rebuiltCheckpointTx.UnsignedTx.TxID()
		if _, ok := checkpointPsbts[rebuiltTxid]; !ok {
			return nil, "", "", errors.CHECKPOINT_MISMATCH.New(
				"invalid checkpoint txs: %s not found", rebuiltTxid,
			).WithMetadata(errors.CheckpointMismatchMetadata{ExpectedTxid: txid})
		}
	}

	// verify the ark tx integrity
	rebuiltTxid := rebuiltArkTx.UnsignedTx.TxID()
	if rebuiltTxid != txid {
		return nil, "", "", errors.ARK_TX_MISMATCH.New(
			"expected tx %s, got %s", rebuiltTxid, txid,
		).WithMetadata(errors.ArkTxMismatchMetadata{
			ExpectedTxid: txid,
			GotTxid:      rebuiltTxid,
		})
	}

	// verify the tapscript signatures
	if valid, _, err := s.builder.VerifyTapscriptPartialSigs(signedArkTx, false); err != nil ||
		!valid {
		return nil, "", "", errors.INVALID_SIGNATURE.New("invalid signature in ark tx %s", txid).
			WithMetadata(errors.InvalidSignatureMetadata{Tx: signedArkTx})
	}

	// sign the ark tx
	finalArkTx, err := s.signer.SignTransactionTapscript(ctx, signedArkTx, nil)
	if err != nil {
		return nil, "", "", errors.INTERNAL_ERROR.New("failed to sign ark tx: %w", err).
			WithMetadata(map[string]any{
				"ark_tx": signedArkTx,
			})
	}

	signedCheckpointTxsMap := make(map[string]string)
	// sign the checkpoint txs
	for _, rebuiltCheckpointTx := range rebuiltCheckpointTxs {
		unsignedCheckpointTx, err := rebuiltCheckpointTx.B64Encode()
		if err != nil {
			return nil, "", "", errors.INTERNAL_ERROR.New(
				"failed to encode checkpoint tx: %w", err,
			).WithMetadata(map[string]any{
				"checkpoint_tx": rebuiltCheckpointTx,
			})
		}
		signedCheckpointTx, err := s.signer.SignTransactionTapscript(
			ctx, unsignedCheckpointTx, nil,
		)
		if err != nil {
			return nil, "", "", errors.INTERNAL_ERROR.New("failed to sign checkpoint tx: %w", err).
				WithMetadata(map[string]any{
					"checkpoint_tx": rebuiltCheckpointTx,
				})
		}
		signedCheckpointTxsMap[rebuiltCheckpointTx.UnsignedTx.TxID()] = signedCheckpointTx
	}

	change, err := offchainTx.Accept(
		finalArkTx, signedCheckpointTxsMap,
		commitmentTxsByCheckpointTxid, rootCommitmentTxid, expiration,
	)
	if err != nil {
		return nil, "", "", errors.INTERNAL_ERROR.New("failed to accept offchain tx: %w", err).
			WithMetadata(map[string]any{
				"ark_tx":                finalArkTx,
				"signed_checkpoint_txs": signedCheckpointTxsMap,
				"commitment_txids":      commitmentTxsByCheckpointTxid,
				"root_commitment_txid":  rootCommitmentTxid,
				"expiration":            expiration,
			})
	}
	changes = append(changes, change)
	s.cache.OffchainTxs().Add(*offchainTx)

	signedCheckpointTxs := make([]string, 0, len(signedCheckpointTxsMap))
	for _, tx := range signedCheckpointTxsMap {
		signedCheckpointTxs = append(signedCheckpointTxs, tx)
	}

	return signedCheckpointTxs, finalArkTx, txid, nil
}

func (s *service) FinalizeOffchainTx(
	ctx context.Context, txid string, finalCheckpointTxs []string,
) errors.Error {
	var (
		changes []domain.Event
		err     error
	)

	offchainTx, exists := s.cache.OffchainTxs().Get(txid)
	if !exists {
		return errors.TX_NOT_FOUND.New("offchain tx %s not found", txid).
			WithMetadata(errors.TxNotFoundMetadata{Txid: txid})
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
			return errors.INVALID_SIGNATURE.New(
				"invalid signature in checkpoint tx %s", checkpoint,
			).WithMetadata(errors.InvalidSignatureMetadata{Tx: checkpoint})
		}

		decodedCheckpointTxs[ptx.UnsignedTx.TxID()] = ptx
	}

	finalCheckpointTxsMap := make(map[string]string)

	var arkTx *psbt.Packet
	arkTx, err = psbt.NewFromRawBytes(strings.NewReader(offchainTx.ArkTx), true)
	if err != nil {
		return errors.INVALID_ARK_PSBT.New("failed to parse ark tx: %w", err).
			WithMetadata(errors.PsbtMetadata{Tx: offchainTx.ArkTx})
	}

	for inIndex := range arkTx.Inputs {
		checkpointTxid := arkTx.UnsignedTx.TxIn[inIndex].PreviousOutPoint.Hash.String()
		checkpointTx, ok := decodedCheckpointTxs[checkpointTxid]
		if !ok {
			return errors.INVALID_PSBT_INPUT.New("tx %s not found", checkpointTxid).
				WithMetadata(errors.InputMetadata{Txid: checkpointTxid, InputIndex: inIndex})
		}

		taprootTreeField, err := txutils.GetArkPsbtFields(
			arkTx, inIndex, txutils.VtxoTaprootTreeField,
		)
		if err != nil {
			return errors.INVALID_PSBT_INPUT.New("missing taptree on input %d", inIndex).
				WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inIndex})
		}
		if len(taprootTreeField) <= 0 {
			return errors.INVALID_PSBT_INPUT.New("missing taproot tree").
				WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inIndex})
		}
		taprootTree := taprootTreeField[0]

		// verify taproot tree of ark tx = script pubkey of checkpoint tx
		vtxoScript, err := script.ParseVtxoScript(taprootTree)
		if err != nil {
			return errors.INVALID_PSBT_INPUT.New("invalid ark taproot tree: %w", err).
				WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inIndex})
		}

		tapKey, _, err := vtxoScript.TapTree()
		if err != nil {
			return errors.INVALID_PSBT_INPUT.New("failed to compute taproot tree: %w", err).
				WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inIndex})
		}

		expectedOutputScript, err := script.P2TRScript(tapKey)
		if err != nil {
			return errors.INVALID_PSBT_INPUT.New("failed to compute P2TR script: %w", err).
				WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inIndex})
		}

		checkpointOutputScript := checkpointTx.UnsignedTx.TxOut[0].PkScript
		if !bytes.Equal(checkpointOutputScript, expectedOutputScript) {
			return errors.INVALID_PSBT_INPUT.New(
				"invalid output script: got %x expected %x",
				checkpointOutputScript, expectedOutputScript,
			).WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inIndex})
		}

		encodedTapTree, err := taprootTree.Encode()
		if err != nil {
			return errors.INVALID_PSBT_INPUT.New("failed to encode taptree: %w", err).
				WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inIndex})
		}

		// save the encoded taproot tree in the checkpoint tx output
		// it will be used to compute the sweep leaf in the sweeper
		checkpointTx.Outputs[0].TaprootTapTree = encodedTapTree

		var b64checkpointTx string
		b64checkpointTx, err = checkpointTx.B64Encode()
		if err != nil {
			return errors.INTERNAL_ERROR.New("failed to encode checkpoint tx: %w", err).
				WithMetadata(map[string]any{
					"checkpoint_tx": checkpointTx,
				})
		}

		finalCheckpointTxsMap[checkpointTxid] = b64checkpointTx
	}

	var event domain.Event
	event, err = offchainTx.Finalize(finalCheckpointTxsMap)
	if err != nil {
		return errors.INTERNAL_ERROR.New("failed to finalize offchain tx: %w", err).
			WithMetadata(map[string]any{
				"final_checkpoint_txs": finalCheckpointTxsMap,
			})
	}

	changes = []domain.Event{event}
	s.cache.OffchainTxs().Remove(txid)

	return nil
}

func (s *service) RegisterIntent(
	ctx context.Context, proof intent.Proof, message intent.RegisterMessage,
) (string, errors.Error) {
	// the vtxo to swap for new ones, require forfeit transactions
	vtxoInputs := make([]domain.Vtxo, 0)
	// the boarding utxos to add in the commitment tx
	boardingUtxos := make([]boardingIntentInput, 0)

	now := time.Now()
	if message.ValidAt > 0 {
		validAt := time.Unix(message.ValidAt, 0)
		if now.Before(validAt) {
			return "", errors.INVALID_INTENT_TIMERANGE.New("proof of ownership not yet valid").
				WithMetadata(errors.IntentTimeRangeMetadata{
					ValidAt:  message.ValidAt,
					ExpireAt: message.ExpireAt,
					Now:      now.Unix(),
				})
		}
	}

	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if now.After(expireAt) {
			return "", errors.INVALID_INTENT_TIMERANGE.New("proof of ownership expired").
				WithMetadata(errors.IntentTimeRangeMetadata{
					ValidAt:  message.ValidAt,
					ExpireAt: message.ExpireAt,
					Now:      now.Unix(),
				})
		}
	}

	proofTxid := proof.UnsignedTx.TxID()

	encodedMessage, err := message.Encode()
	if err != nil {
		return "", errors.INVALID_INTENT_MESSAGE.New("failed to encode message: %w", err).
			WithMetadata(errors.InvalidIntentMessageMetadata{Message: message.BaseMessage})
	}

	encodedProof, err := proof.B64Encode()
	if err != nil {
		return "", errors.INVALID_INTENT_PSBT.New("failed to encode proof: %w", err).
			WithMetadata(errors.PsbtMetadata{Tx: proof.UnsignedTx.TxID()})
	}

	fees, err := computeIntentFees(proof)
	if err != nil {
		return "", errors.INVALID_INTENT_PROOF.New("failed to compute intent fees: %w", err).
			WithMetadata(errors.InvalidIntentProofMetadata{
				Proof:   encodedProof,
				Message: encodedMessage,
			})
	}

	countOnchainOutputs := len(message.OnchainOutputIndexes)
	expectedFees := int64(countOnchainOutputs) * s.onchainOutputFee

	if fees < expectedFees {
		return "", errors.INTENT_INSUFFICIENT_FEE.New("got %d expected %d", fees, expectedFees).
			WithMetadata(errors.IntentInsufficientFeeMetadata{
				ExpectedFee: int(expectedFees),
				ActualFee:   int(fees),
			})
	}

	outpoints := proof.GetOutpoints()

	for i, outpoint := range outpoints {
		psbtInput := proof.Inputs[i+1]

		if len(psbtInput.TaprootLeafScript) == 0 {
			return "", errors.INVALID_PSBT_INPUT.New(
				"missing taproot leaf script on input %d", i+1,
			).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: i + 1})
		}

		if psbtInput.WitnessUtxo == nil {
			return "", errors.INVALID_PSBT_INPUT.New(
				"missing witness utxo for input %s", outpoint.String(),
			).WithMetadata(errors.InputMetadata{
				Txid:       proofTxid,
				InputIndex: int(outpoint.Index)},
			)
		}

		vtxoOutpoint := domain.Outpoint{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		if s.cache.OffchainTxs().Includes(vtxoOutpoint) {
			return "", errors.VTXO_ALREADY_SPENT.New(
				"vtxo %s is currently being spent", vtxoOutpoint.String(),
			).WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxoOutpoint.String()})
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
		locktime, locktimeDisabled := arklib.BIP68DecodeSequence(
			proof.UnsignedTx.TxIn[i+1].Sequence,
		)

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxoOutpoint})
		if err != nil || len(vtxosResult) == 0 {
			// reject if intent specifies onchain outputs and boarding inputs
			if len(message.OnchainOutputIndexes) > 0 {
				return "", errors.INVALID_INTENT_PROOF.New(
					"cannot include onchain inputs and outputs",
				).WithMetadata(errors.InvalidIntentProofMetadata{
					Proof:   encodedProof,
					Message: encodedMessage,
				})
			}

			input := ports.Input{
				Outpoint:   vtxoOutpoint,
				Tapscripts: tapscripts,
			}

			if err := s.checkIfBanned(ctx, input); err != nil {
				return "", errors.VTXO_BANNED.Wrap(err).
					WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxoOutpoint.String()})
			}

			boardingUtxos = append(boardingUtxos, boardingIntentInput{
				Input:            input,
				locktime:         locktime,
				locktimeDisabled: locktimeDisabled,
				witnessUtxo:      psbtInput.WitnessUtxo,
			})

			continue
		}

		vtxo := vtxosResult[0]
		if err := s.checkIfBanned(ctx, vtxo); err != nil {
			return "", errors.VTXO_BANNED.Wrap(err).
				WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxo.Outpoint.String()})
		}

		if vtxo.Spent {
			return "", errors.VTXO_ALREADY_SPENT.New(
				"input %s already spent", vtxo.Outpoint.String(),
			).WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxo.Outpoint.String()})
		}

		if vtxo.Unrolled {
			return "", errors.VTXO_ALREADY_UNROLLED.New(
				"input %s already unrolled", vtxo.Outpoint.String(),
			).WithMetadata(errors.VtxoMetadata{VtxoOutpoint: vtxo.Outpoint.String()})
		}

		if s.settlementMinExpiryGap > 0 && !vtxo.Swept {
			// reject if expires after now + settlementMinExpiryGap
			expiresAt := time.Unix(vtxo.ExpiresAt, 0)
			limit := time.Now().Add(s.settlementMinExpiryGap)
			if expiresAt.After(limit) {
				return "", errors.INVALID_PSBT_INPUT.New(
					"vtxo %s expires after %s (minExpiryGap: %s)",
					vtxo.Outpoint.String(), limit, s.settlementMinExpiryGap,
				).WithMetadata(errors.InputMetadata{
					Txid:       proofTxid,
					InputIndex: int(outpoint.Index),
				})
			}
		}

		if psbtInput.WitnessUtxo.Value != int64(vtxo.Amount) {
			return "", errors.INVALID_PSBT_INPUT.New(
				"witness utxo value mismatch: got %d expected %d",
				psbtInput.WitnessUtxo.Value, vtxo.Amount,
			).WithMetadata(errors.InputMetadata{
				Txid:       proofTxid,
				InputIndex: int(outpoint.Index),
			})
		}

		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return "", errors.INTERNAL_ERROR.New("failed to decode script pubkey: %w", err).
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return "", errors.INTERNAL_ERROR.New("failed to parse pubkey: %w", err).
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		pkScript, err := script.P2TRScript(pubkey)
		if err != nil {
			return "", errors.INTERNAL_ERROR.New(
				"failed to compute P2TR script from vtxo pubkey: %w", err,
			).WithMetadata(map[string]any{"vtxo_pubkey": vtxo.PubKey})
		}

		if !bytes.Equal(pkScript, psbtInput.WitnessUtxo.PkScript) {
			return "", errors.INVALID_PSBT_INPUT.New(
				"invalid witness utxo script: got %x expected %x",
				psbtInput.WitnessUtxo.PkScript, pkScript,
			).WithMetadata(errors.InputMetadata{
				Txid:       proofTxid,
				InputIndex: int(outpoint.Index),
			})
		}

		// validation is required only in case the vtxo can be unrolled = requires a forfeit transaction
		if vtxo.RequiresForfeit() {
			vtxoTapKey, err := vtxo.TapKey()
			if err != nil {
				return "", errors.INTERNAL_ERROR.New("failed to get taproot key: %w", err).
					WithMetadata(map[string]any{
						"vtxo_pubkey": vtxo.PubKey,
					})
			}
			if len(tapscripts) == 0 {
				return "", errors.INVALID_PSBT_INPUT.New("missing taptree for input %d", outpoint).
					WithMetadata(errors.InputMetadata{
						Txid:       proofTxid,
						InputIndex: int(outpoint.Index),
					})
			}
			if err := s.validateVtxoInput(
				tapscripts, vtxoTapKey, vtxo.CreatedAt, now,
				locktime, locktimeDisabled, proofTxid, i+1,
			); err != nil {
				return "", err
			}
		}

		vtxoInputs = append(vtxoInputs, vtxo)
	}

	signedProof, err := s.signer.SignTransactionTapscript(ctx, encodedProof, nil)
	if err != nil {
		return "", errors.INTERNAL_ERROR.New("failed to sign proof: %w", err).
			WithMetadata(map[string]any{
				"proof": proof.UnsignedTx.TxID(),
			})
	}

	if err := intent.Verify(signedProof, encodedMessage); err != nil {
		log.
			WithField("unsignedProof", encodedProof).
			WithField("signedProof", signedProof).
			WithField("encodedMessage", encodedMessage).
			Tracef("failed to verify intent proof: %s", err)
		return "", errors.INVALID_INTENT_PROOF.New("invalid intent proof: %w", err).
			WithMetadata(errors.InvalidIntentProofMetadata{
				Proof:   signedProof,
				Message: encodedMessage,
			})
	}

	intent, err := domain.NewIntent(signedProof, encodedMessage, vtxoInputs)
	if err != nil {
		return "", errors.INTERNAL_ERROR.New("failed to create intent: %w", err).
			WithMetadata(map[string]any{
				"proof":       signedProof,
				"message":     encodedMessage,
				"vtxo_inputs": vtxoInputs,
			})
	}

	// reject if proof does not specify outputs
	// TODO remove if blinded credentials are supported
	if !proof.ContainsOutputs() {
		return "", errors.INVALID_INTENT_PROOF.New("proof does not contain outputs").
			WithMetadata(errors.InvalidIntentProofMetadata{
				Proof:   signedProof,
				Message: encodedMessage,
			})
	}

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
					return "", errors.AMOUNT_TOO_HIGH.New(
						"output %d amount is higher than max utxo amount: %d",
						outputIndex,
						s.utxoMaxAmount,
					).WithMetadata(errors.AmountTooHighMetadata{
						OutputIndex: outputIndex,
						Amount:      int(amount),
						MaxAmount:   int(s.utxoMaxAmount),
					})
				}
			}
			if amount < uint64(s.utxoMinAmount) {
				return "", errors.AMOUNT_TOO_LOW.New(
					"output %d amount is lower than min utxo amount: %d",
					outputIndex,
					s.utxoMinAmount,
				).WithMetadata(errors.AmountTooLowMetadata{
					OutputIndex: outputIndex,
					Amount:      int(amount),
					MinAmount:   int(s.utxoMinAmount),
				})
			}

			chainParams := s.chainParams()
			if chainParams == nil {
				return "", errors.INTERNAL_ERROR.New("unsupported network: %s", s.network.Name).
					WithMetadata(map[string]any{
						"network": s.network.Name,
					})
			}
			scriptType, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, chainParams,
			)
			if err != nil {
				return "", errors.INVALID_PKSCRIPT.New(
					"failed to get onchain address from script of output %d: %w", outputIndex, err,
				).WithMetadata(errors.InvalidPkScriptMetadata{
					Script: hex.EncodeToString(output.PkScript),
				})
			}

			if len(addrs) == 0 {
				return "", errors.INVALID_PKSCRIPT.New(
					"invalid script type for output %d: %s", outputIndex, scriptType,
				).WithMetadata(errors.InvalidPkScriptMetadata{
					Script: hex.EncodeToString(output.PkScript),
				})
			}

			rcv.OnchainAddress = addrs[0].EncodeAddress()
		} else {
			if s.vtxoMaxAmount >= 0 {
				if amount > uint64(s.vtxoMaxAmount) {
					return "", errors.AMOUNT_TOO_HIGH.New(
						"output %d amount is higher than max vtxo amount: %d",
						outputIndex, s.vtxoMaxAmount,
					).WithMetadata(errors.AmountTooHighMetadata{
						OutputIndex: outputIndex,
						Amount:      int(amount),
						MaxAmount:   int(s.vtxoMaxAmount),
					})
				}
			}
			if amount < uint64(s.vtxoMinSettlementAmount) {
				return "", errors.AMOUNT_TOO_LOW.New(
					"output %d amount is lower than min vtxo amount: %d",
					outputIndex, s.vtxoMinSettlementAmount,
				).WithMetadata(errors.AmountTooLowMetadata{
					OutputIndex: outputIndex,
					Amount:      int(amount),
					MinAmount:   int(s.vtxoMinSettlementAmount),
				})
			}

			hasOffChainReceiver = true
			rcv.PubKey = hex.EncodeToString(output.PkScript[2:])
		}

		receivers = append(receivers, rcv)
	}

	if hasOffChainReceiver {
		if len(message.CosignersPublicKeys) == 0 {
			return "", errors.INVALID_INTENT_MESSAGE.New(
				"CosignersPublicKeys is required in intent message",
			).WithMetadata(errors.InvalidIntentMessageMetadata{
				Message: message.BaseMessage,
			})
		}

		// check if the operator pubkey has been set as cosigner
		operatorPubkeyHex := hex.EncodeToString(s.operatorPubkey.SerializeCompressed())
		for _, pubkey := range message.CosignersPublicKeys {
			if pubkey == operatorPubkeyHex {
				return "", errors.INVALID_INTENT_MESSAGE.New(
					"invalid cosigner pubkeys: %x is used by us", pubkey,
				).WithMetadata(errors.InvalidIntentMessageMetadata{
					Message: message.BaseMessage,
				})
			}
		}
	}

	if err := intent.AddReceivers(receivers); err != nil {
		return "", errors.INTERNAL_ERROR.New("failed to add receivers to intent: %w", err).
			WithMetadata(map[string]any{
				"receivers": receivers,
			})
	}

	boardingInputs := make([]ports.BoardingInput, 0)

	if len(boardingUtxos) > 0 {
		var err errors.Error
		boardingInputs, err = s.processBoardingInputs(ctx, intent.Id, boardingUtxos)
		if err != nil {
			return "", err
		}
	}

	if err := s.cache.Intents().Push(
		*intent, boardingInputs, message.CosignersPublicKeys,
	); err != nil {
		return "", errors.INTERNAL_ERROR.New("failed to push intent: %w", err).
			WithMetadata(map[string]any{
				"intent":                intent,
				"boarding_inputs":       boardingInputs,
				"cosigners_public_keys": message.CosignersPublicKeys,
			})
	}

	return intent.Id, nil
}

func (s *service) ConfirmRegistration(ctx context.Context, intentId string) errors.Error {
	if !s.cache.ConfirmationSessions().Initialized() {
		return errors.CONFIRMATION_SESSION_NOT_STARTED.New("confirmation session not started")
	}

	if err := s.cache.ConfirmationSessions().Confirm(intentId); err != nil {
		return errors.INTERNAL_ERROR.New("failed to confirm intent: %w", err).
			WithMetadata(map[string]any{
				"intent_id": intentId,
			})
	}
	return nil
}

func (s *service) SubmitForfeitTxs(ctx context.Context, forfeitTxs []string) errors.Error {
	if len(forfeitTxs) <= 0 {
		return nil
	}

	// TODO move forfeit validation outside of ports.LiveStore
	if err := s.cache.ForfeitTxs().Sign(forfeitTxs); err != nil {
		return errors.INVALID_FORFEIT_TXS.New("failed to sign forfeit txs: %w", err).
			WithMetadata(errors.InvalidForfeitTxsMetadata{ForfeitTxs: forfeitTxs})
	}

	go s.checkForfeitsAndBoardingSigsSent()

	return nil
}

func (s *service) SignCommitmentTx(ctx context.Context, signedCommitmentTx string) errors.Error {
	numSignedInputs, err := s.builder.CountSignedTaprootInputs(signedCommitmentTx)
	if err != nil {
		return errors.INTERNAL_ERROR.New(
			"failed to count number of signed boarding inputs: %w", err,
		).WithMetadata(map[string]any{
			"signed_commitment_tx": signedCommitmentTx,
		})
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
		return errors.INTERNAL_ERROR.New("failed to upsert current round: %w", err).
			WithMetadata(map[string]any{
				"signed_commitment_tx": signedCommitmentTx,
			})
	}

	if combineErr != nil {
		return errors.INVALID_BOARDING_INPUT_SIG.New(
			"failed to verify and combine partial signature(s): %w", err,
		).WithMetadata(errors.InvalidBoardingInputSigMetadata{
			SignedCommitmentTx: signedCommitmentTx,
		})
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

func (s *service) GetInfo(ctx context.Context) (*ServiceInfo, errors.Error) {
	signerPubkey := hex.EncodeToString(s.signerPubkey.SerializeCompressed())
	forfeitPubkey := hex.EncodeToString(s.forfeitPubkey.SerializeCompressed())

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, errors.INTERNAL_ERROR.New("failed to get dust amount: %w", err)
	}

	scheduledSessionConfig, err := s.repoManager.ScheduledSession().Get(ctx)
	if err != nil {
		return nil, errors.INTERNAL_ERROR.New("failed to get market hour config from db: %w", err)
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
		UnilateralExitDelay:  int64(s.publicUnilateralExitDelay.Value),
		BoardingExitDelay:    int64(s.boardingExitDelay.Value),
		SessionDuration:      int64(s.sessionDuration.Seconds()),
		Network:              s.network.Name,
		Dust:                 dust,
		ForfeitAddress:       s.forfeitAddress,
		NextScheduledSession: nextScheduledSession,
		UtxoMinAmount:        s.utxoMinAmount,
		UtxoMaxAmount:        s.utxoMaxAmount,
		VtxoMinAmount:        s.vtxoMinOffchainTxAmount,
		VtxoMaxAmount:        s.vtxoMaxAmount,
		CheckpointTapscript:  hex.EncodeToString(s.checkpointTapscript),
		Fees: FeeInfo{
			IntentFees: IntentFeeInfo{
				OnchainOutput: uint64(s.onchainOutputFee),
			},
		},
	}, nil
}

// DeleteIntentsByProof deletes transaction intents matching the proof of ownership.
func (s *service) DeleteIntentsByProof(
	ctx context.Context, proof intent.Proof, message intent.DeleteMessage,
) errors.Error {
	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if time.Now().After(expireAt) {
			return errors.INVALID_INTENT_TIMERANGE.New("proof of ownership expired").
				WithMetadata(errors.IntentTimeRangeMetadata{
					ValidAt:  0,
					ExpireAt: message.ExpireAt,
					Now:      time.Now().Unix(),
				})
		}
	}

	outpoints := proof.GetOutpoints()
	proofTxid := proof.UnsignedTx.TxID()

	boardingTxs := make(map[string]wire.MsgTx)
	for i, outpoint := range outpoints {
		psbtInput := proof.Inputs[i+1]

		if len(psbtInput.TaprootLeafScript) == 0 {
			return errors.INVALID_PSBT_INPUT.New("missing taproot leaf script on input %d", i+1).
				WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: i + 1})
		}

		vtxoOutpoint := domain.Outpoint{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxoOutpoint})
		if err != nil || len(vtxosResult) == 0 {
			if _, ok := boardingTxs[vtxoOutpoint.Txid]; !ok {
				txhex, err := s.wallet.GetTransaction(ctx, outpoint.Hash.String())
				if err != nil {
					return errors.TX_NOT_FOUND.New(
						"failed to get boarding input tx %s: %s", vtxoOutpoint.Txid, err,
					).WithMetadata(errors.TxNotFoundMetadata{Txid: vtxoOutpoint.Txid})
				}

				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return errors.INVALID_PSBT_INPUT.New(
						"failed to deserialize boarding tx %s: %s", vtxoOutpoint.Txid, err,
					).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: i + 1})
				}

				boardingTxs[vtxoOutpoint.Txid] = tx
			}

			tx := boardingTxs[vtxoOutpoint.Txid]
			prevout := tx.TxOut[vtxoOutpoint.VOut]

			if !bytes.Equal(prevout.PkScript, psbtInput.WitnessUtxo.PkScript) {
				return errors.INVALID_PSBT_INPUT.New(
					"pkscript mismatch: got %x expected %x",
					prevout.PkScript,
					psbtInput.WitnessUtxo.PkScript,
				).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: i + 1})
			}

			if prevout.Value != int64(psbtInput.WitnessUtxo.Value) {
				return errors.INVALID_PSBT_INPUT.New(
					"invalid witness utxo value: got %d expected %d",
					prevout.Value,
					psbtInput.WitnessUtxo.Value,
				).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: i + 1})
			}

			continue
		}

		vtxo := vtxosResult[0]

		if psbtInput.WitnessUtxo.Value != int64(vtxo.Amount) {
			return errors.INVALID_PSBT_INPUT.New(
				"invalid witness utxo value: got %d expected %d",
				psbtInput.WitnessUtxo.Value,
				vtxo.Amount,
			).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: i + 1})
		}

		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return errors.INTERNAL_ERROR.New("failed to decode vtxo pubkey: %w", err).
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return errors.INTERNAL_ERROR.New("failed to parse vtxo pubkey: %w", err).
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		pkScript, err := script.P2TRScript(pubkey)
		if err != nil {
			return errors.INTERNAL_ERROR.New(
				"failed to compute P2TR script from vtxo pubkey: %w", err,
			).WithMetadata(map[string]any{
				"vtxo_pubkey": vtxo.PubKey,
			})
		}

		if !bytes.Equal(pkScript, psbtInput.WitnessUtxo.PkScript) {
			return errors.INVALID_PSBT_INPUT.New(
				"invalid witness utxo script: got %x expected %x",
				psbtInput.WitnessUtxo.PkScript,
				pkScript,
			).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: i + 1})
		}
	}

	encodedMessage, err := message.Encode()
	if err != nil {
		return errors.INVALID_INTENT_MESSAGE.New("failed to encode message: %w", err).
			WithMetadata(errors.InvalidIntentMessageMetadata{Message: message.BaseMessage})
	}

	encodedProof, err := proof.B64Encode()
	if err != nil {
		return errors.INVALID_INTENT_PSBT.New("failed to encode proof: %w", err).
			WithMetadata(errors.PsbtMetadata{Tx: proof.UnsignedTx.TxID()})
	}

	signedProof, err := s.signer.SignTransactionTapscript(ctx, encodedProof, nil)
	if err != nil {
		return errors.INTERNAL_ERROR.New("failed to sign proof: %w", err).
			WithMetadata(map[string]any{
				"proof": proof.UnsignedTx.TxID(),
			})
	}

	if err := intent.Verify(signedProof, encodedMessage); err != nil {
		log.
			WithField("unsignedProof", encodedProof).
			WithField("signedProof", signedProof).
			WithField("encodedMessage", encodedMessage).
			Tracef("failed to verify intent proof: %s", err)
		return errors.INVALID_INTENT_PROOF.New("invalid intent proof: %w", err).
			WithMetadata(errors.InvalidIntentProofMetadata{
				Proof:   signedProof,
				Message: encodedMessage,
			})
	}

	allIntents, err := s.cache.Intents().ViewAll(nil)
	if err != nil {
		return errors.INTERNAL_ERROR.New("failed to view all intents: %w", err)
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
		return errors.INVALID_INTENT_PROOF.New("no matching intents found for intent proof")
	}

	idsToDelete := make([]string, 0, len(idsToDeleteMap))
	for id := range idsToDeleteMap {
		idsToDelete = append(idsToDelete, id)
	}

	if err := s.cache.Intents().Delete(idsToDelete); err != nil {
		return errors.INTERNAL_ERROR.New("failed to delete intents: %w", err).
			WithMetadata(map[string]any{
				"ids_to_delete": idsToDelete,
			})
	}
	return nil
}

func (s *service) RegisterCosignerNonces(
	ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces,
) errors.Error {
	if err := s.cache.TreeSigingSessions().AddNonces(ctx, roundId, pubkey, nonces); err != nil {
		return errors.INTERNAL_ERROR.New("failed to add nonces: %w", err).
			WithMetadata(map[string]any{
				"round_id": roundId,
				"pubkey":   pubkey,
				"nonces":   nonces,
			})
	}
	return nil
}

func (s *service) RegisterCosignerSignatures(
	ctx context.Context, roundId string, pubkey string, sigs tree.TreePartialSigs,
) errors.Error {
	if err := s.cache.TreeSigingSessions().AddSignatures(ctx, roundId, pubkey, sigs); err != nil {
		return errors.INTERNAL_ERROR.New("failed to add signatures: %w", err).
			WithMetadata(map[string]any{
				"round_id": roundId,
				"pubkey":   pubkey,
				"sigs":     sigs,
			})
	}
	return nil
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
		s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to get main account balance: %s", err))
		return
	}

	// TODO take into account available liquidity
	selectedIntents := s.cache.Intents().Pop(num)
	intents := make([]ports.TimedIntent, 0, len(selectedIntents))

	// for each intent, check if all boarding inputs are unspent
	// exclude any intent with at least one spent boarding input
	for _, intent := range selectedIntents {
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
			if err := s.cache.Intents().Push(
				intent.Intent, intent.BoardingInputs, intent.CosignersPublicKeys,
			); err != nil {
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
		log.Errorf("not enough liquidity, current balance: %d", availableBalance)
		s.cache.CurrentRound().Fail(
			errors.INTERNAL_ERROR.New("service temporary unavailable"),
		)
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
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to register intents: %s", err))
			return
		}
		if err := s.cache.CurrentRound().Upsert(func(_ *domain.Round) *domain.Round {
			return round
		}); err != nil {
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to upsert round: %s", err))
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
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("not enough confirmation received"))
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
		s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to retrieve swept rounds: %s", err))
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
		s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to create commitment tx: %s", err))
		return
	}

	s.roundReportSvc.OpEnded(BuildCommitmentTxOp)

	log.Debugf("commitment tx created for round %s", roundId)

	flatConnectors, err := connectors.Serialize()
	if err != nil {
		s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to serialize connectors: %s", err))
		return
	}

	if err := s.cache.ForfeitTxs().Init(flatConnectors, intents); err != nil {
		s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to initialize forfeit txs: %s", err))
		return
	}

	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to parse commitment tx: %s", err))
		return
	}

	if err := s.cache.CurrentRound().Upsert(func(r *domain.Round) *domain.Round {
		ur := *r
		ur.CommitmentTxid = commitmentPtx.UnsignedTx.TxID()
		ur.CommitmentTx = commitmentTx
		return &ur
	}); err != nil {
		s.cache.CurrentRound().Fail(errors.INTERNAL_ERROR.New("failed to update round: %s", err))
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
			s.cache.CurrentRound().Fail(errors.INTERNAL_ERROR.New(
				"failed to create coordinator session: %s", err,
			))
			return
		}

		operatorSignerSession := tree.NewTreeSignerSession(s.operatorPrvkey)
		if err := operatorSignerSession.Init(
			root.CloneBytes(), batchOutputAmount, vtxoTree,
		); err != nil {
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to create signer session: %s", err))
			return
		}

		s.roundReportSvc.OpStarted(CreateTreeNoncesOp)

		nonces, err := operatorSignerSession.GetNonces()
		if err != nil {
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to generate musig2 nonces: %s", err))
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
			s.cache.CurrentRound().Fail(errors.SIGNING_SESSION_TIMED_OUT.New(
				"musig2 signing session timed out (nonce collection), collected %d/%d nonces",
				len(signingSession.Nonces), len(uniqueSignerPubkeys),
			))
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
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to aggregate nonces: %s", err))
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
			s.cache.CurrentRound().Fail(errors.INTERNAL_ERROR.New("failed to sign tree: %s", err))
			return
		}
		_, err = coordinator.AddSignatures(s.operatorPubkey, operatorSignatures)
		if err != nil {
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("invalid operator tree signature: %s", err))
			return
		}

		s.roundReportSvc.OpEnded(SignTreeOp)

		log.Debugf("tree signed by us for round %s", roundId)

		log.Debugf("waiting for cosigners to submit their signatures...")

		s.roundReportSvc.OpStarted(WaitForTreeSignaturesOp)

		select {
		case <-time.After(thirdOfRemainingDuration):
			signingSession, _ := s.cache.TreeSigingSessions().Get(roundId)
			s.cache.CurrentRound().Fail(errors.SIGNING_SESSION_TIMED_OUT.New(
				"musig2 signing session timed out (signatures collection), "+
					"collected %d/%d signatures",
				len(signingSession.Signatures), len(uniqueSignerPubkeys),
			))

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
					// an unexpected error occurred during the signature validation, batch fails
					s.cache.CurrentRound().
						Fail(errors.INTERNAL_ERROR.New("failed to validate signatures: %s", err))
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
				s.cache.CurrentRound().
					Fail(errors.INTERNAL_ERROR.New("some musig2 signatures are invalid"))
				go s.banCosignerInputs(ctx, cosignersToBan, registeredIntents)
				return
			}
		}

		s.roundReportSvc.OpEnded(WaitForTreeSignaturesOp)

		log.Debugf("all signatures collected for round %s", roundId)

		s.roundReportSvc.OpStarted(AggregateTreeSignaturesOp)

		signedTree, err := coordinator.SignTree()
		if err != nil {
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to aggregate tree signatures: %s", err))
			return
		}

		s.roundReportSvc.OpEnded(AggregateTreeSignaturesOp)

		log.Debugf("vtxo tree signed for round %s", roundId)

		vtxoTree = signedTree
		flatVtxoTree, err = vtxoTree.Serialize()
		if err != nil {
			s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to serialize vtxo tree: %s", err))
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
		s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to start finalization: %s", err))
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
		changes = s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to parse commitment tx: %s", err))
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

		txToSign = s.cache.CurrentRound().Get().CommitmentTx
		commitmentTx, err = psbt.NewFromRawBytes(strings.NewReader(txToSign), true)
		if err != nil {
			changes = s.cache.CurrentRound().Fail(errors.INTERNAL_ERROR.New(
				"failed to parse commitment tx: %s", err,
			))
			return
		}

		forfeitTxList, err := s.cache.ForfeitTxs().Pop()
		if err != nil {
			changes = s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("failed to finalize round: %s", err))
			return
		}

		// some forfeits are not signed, we must ban the associated scripts
		if !s.cache.ForfeitTxs().AllSigned() {
			go s.banForfeitCollectionTimeout(ctx, roundId)

			changes = s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("missing forfeit transactions"))
			return
		}

		s.roundReportSvc.OpStarted(VerifyForfeitsSignaturesOp)

		// verify is forfeit tx signatures are valid, if not we ban the associated scripts
		if convictions := s.verifyForfeitTxsSigs(roundId, forfeitTxList); len(convictions) > 0 {
			changes = s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("invalid forfeit txs signature"))
			go func() {
				if err := s.repoManager.Convictions().Add(ctx, convictions...); err != nil {
					log.WithError(err).Warn("failed to ban vtxos")
				}
			}()
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
			changes = s.cache.CurrentRound().
				Fail(errors.INTERNAL_ERROR.New("missing boarding inputs signatures"))
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
					errors.INTERNAL_ERROR.New("failed to sign commitment tx: %s", err),
				)
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
		changes = s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to sign commitment tx: %s", err))
		return
	}

	s.roundReportSvc.OpEnded(SignCommitmentTxOp)
	s.roundReportSvc.OpStarted(PublishCommitmentTxOp)

	if _, err := s.wallet.BroadcastTransaction(ctx, signedCommitmentTx); err != nil {
		changes = s.cache.CurrentRound().Fail(
			errors.INTERNAL_ERROR.New("failed to broadcast commitment tx: %s", err),
		)
		return
	}

	s.roundReportSvc.OpEnded(PublishCommitmentTxOp)

	round := s.cache.CurrentRound().Get()
	changes, err = round.EndFinalization(forfeitTxs, signedCommitmentTx)
	if err != nil {
		changes = s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to finalize round: %s", err))
		return
	}
	if err := s.cache.CurrentRound().Upsert(func(m *domain.Round) *domain.Round {
		return round
	}); err != nil {
		changes = s.cache.CurrentRound().
			Fail(errors.INTERNAL_ERROR.New("failed to finalize round: %s", err))
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
					outs := []domain.Outpoint{v.Outpoint}
					vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, outs)
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
		lastEvent = RoundFinalized{ev, round.CommitmentTxid}
	case domain.RoundFailed:
		intents := s.cache.Intents().GetSelectedIntents()
		topics := make([]string, 0, len(intents))
		for _, intent := range intents {
			for _, input := range intent.Inputs {
				topics = append(topics, input.Outpoint.String())
			}

			for _, boardingInput := range intent.BoardingInputs {
				topics = append(topics, boardingInput.String())
			}
		}

		lastEvent = RoundFailed{ev, topics}
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

	if err := s.sweeper.scheduleBatchSweep(
		expirationTimestamp, round.CommitmentTxid, vtxoTree,
	); err != nil {
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
	scripts, err := s.extractVtxosScriptsForScanner(vtxos)
	if err != nil {
		return err
	}

	return s.scanner.WatchScripts(context.Background(), scripts)
}

func (s *service) stopWatchingVtxos(vtxos []domain.Vtxo) {
	scripts, err := s.extractVtxosScriptsForScanner(vtxos)
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

// extractVtxosScriptsForScanner extracts the scripts for the vtxos to be watched by the scanner
// it excludes subdust vtxos scripts and duplicates
// it logs errors and continues in order to not block the start/stop watching vtxos operations
func (s *service) extractVtxosScriptsForScanner(vtxos []domain.Vtxo) ([]string, error) {
	dustLimit, err := s.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	indexedScripts := make(map[string]struct{})
	scripts := make([]string, 0)

	for _, vtxo := range vtxos {
		vtxoTapKeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			log.WithError(err).Warnf("failed to decode vtxo pubkey: %s", vtxo.PubKey)
			continue
		}

		vtxoTapKey, err := schnorr.ParsePubKey(vtxoTapKeyBytes)
		if err != nil {
			log.WithError(err).Warnf("failed to parse vtxo pubkey: %s", vtxo.PubKey)
			continue
		}

		if vtxo.Amount < dustLimit {
			continue
		}

		p2trScript, err := script.P2TRScript(vtxoTapKey)
		if err != nil {
			log.WithError(err).
				Warnf("failed to compute P2TR script from vtxo pubkey: %s", vtxo.PubKey)
			continue
		}

		scriptHex := hex.EncodeToString(p2trScript)

		if _, ok := indexedScripts[scriptHex]; !ok {
			indexedScripts[scriptHex] = struct{}{}
			scripts = append(scripts, scriptHex)
		}
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

func (s *service) processBoardingInputs(
	ctx context.Context,
	intentTxid string,
	boardingUtxos []boardingIntentInput,
) ([]ports.BoardingInput, errors.Error) {
	scripts := make([]string, 0)
	outpoints := make([]wire.OutPoint, 0)

	// extract the scripts and outpoints from the boarding utxos
	// in order to trigger watch and rescan operations
	for _, input := range boardingUtxos {
		script, err := input.OutputScript()
		if err != nil {
			return nil, errors.INTERNAL_ERROR.New(
				"failed to compute output script from tapscripts: %w", err,
			).WithMetadata(map[string]any{
				"txid":       input.Txid,
				"vout":       input.VOut,
				"tapscripts": input.Tapscripts,
			})
		}
		scripts = append(scripts, hex.EncodeToString(script))

		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return nil, errors.INTERNAL_ERROR.New("failed to parse txid: %w", err).
				WithMetadata(map[string]any{"txid": input.Txid})
		}

		outpoints = append(outpoints, wire.OutPoint{
			Hash:  *txHash,
			Index: input.VOut,
		})
	}

	if err := s.scanner.WatchScripts(ctx, scripts); err != nil {
		return nil, errors.INTERNAL_ERROR.New("failed to watch boarding scripts: %w", err).
			WithMetadata(map[string]any{"scripts": scripts})
	}

	defer func() {
		if err := s.scanner.UnwatchScripts(ctx, scripts); err != nil {
			log.WithError(err).Warnf(
				"failed to unwatch boarding scripts for intent %s", intentTxid,
			)
		}
	}()

	// we must rescan the utxos to ensure nbxplorer is aware of the boarding transactions
	if err := s.scanner.RescanUtxos(ctx, outpoints); err != nil {
		return nil, errors.INTERNAL_ERROR.New("failed to rescan boarding utxos: %w", err).
			WithMetadata(map[string]any{"outpoints": outpoints})
	}

	boardingInputs := make([]ports.BoardingInput, 0)
	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex
	now := time.Now()

	for _, input := range boardingUtxos {
		if _, ok := boardingTxs[input.Txid]; !ok {
			if len(input.Tapscripts) == 0 {
				return nil, errors.INVALID_PSBT_INPUT.New(
					"missing taptree for input %s", input.Outpoint,
				).WithMetadata(errors.InputMetadata{
					Txid:       intentTxid,
					InputIndex: int(input.VOut),
				})
			}

			tx, err := s.validateBoardingInput(ctx, input, now)
			if err != nil {
				return nil, errors.INVALID_PSBT_INPUT.New(
					"failed to validate boarding input: %w", err,
				).WithMetadata(errors.InputMetadata{
					Txid:       intentTxid,
					InputIndex: int(input.VOut),
				})
			}

			boardingTxs[input.Txid] = *tx
		}

		tx := boardingTxs[input.Txid]
		prevout := tx.TxOut[input.VOut]

		if !bytes.Equal(prevout.PkScript, input.witnessUtxo.PkScript) {
			return nil, errors.INVALID_PSBT_INPUT.New(
				"invalid witness utxo script: got %x expected %x",
				prevout.PkScript,
				input.witnessUtxo.PkScript,
			).
				WithMetadata(errors.InputMetadata{Txid: intentTxid, InputIndex: int(input.VOut)})
		}

		if prevout.Value != int64(input.witnessUtxo.Value) {
			return nil, errors.INVALID_PSBT_INPUT.New(
				"invalid witness utxo value: got %d expected %d",
				prevout.Value,
				input.witnessUtxo.Value,
			).
				WithMetadata(errors.InputMetadata{Txid: intentTxid, InputIndex: int(input.VOut)})
		}

		boardingInput, err := newBoardingInput(
			tx, input.Input, s.signerPubkey, s.boardingExitDelay, s.allowCSVBlockType,
		)
		if err != nil {
			return nil, err
		}

		boardingInputs = append(boardingInputs, *boardingInput)
	}

	return boardingInputs, nil
}

func (s *service) validateBoardingInput(
	ctx context.Context, input boardingIntentInput, now time.Time,
) (*wire.MsgTx, error) {
	vtxoScript, err := script.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, err
	}

	// check if the tx exists and is confirmed
	txhex, err := s.wallet.GetTransaction(ctx, input.Txid)
	if err != nil {
		return nil, fmt.Errorf("failed to get tx %s: %s", input.Txid, err)
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
		return nil, fmt.Errorf("failed to deserialize tx %s: %s", input.Txid, err)
	}

	confirmed, _, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, input.Txid)
	if err != nil {
		return nil, fmt.Errorf("failed to check tx %s: %s", input.Txid, err)
	}

	if !confirmed {
		return nil, fmt.Errorf("tx %s not confirmed", input.Txid)
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
		return nil, fmt.Errorf("tx %s expired", input.Txid)
	}

	// If the intent is registered using a exit path that contains CSV delay, we want to verify it
	// by shifitng the current "now" in the future of the duration of the smallest exit delay.
	// This way, any exit order guaranteed by the exit path is maintained at intent registration
	if !input.locktimeDisabled {
		delta := now.Add(time.Duration(exitDelay.Seconds())*time.Second).Unix() - blocktime
		if diff := input.locktime.Seconds() - delta; diff > 0 {
			return nil, fmt.Errorf(
				"vtxo script can be used for intent registration in %d seconds", diff,
			)
		}
	}

	if s.utxoMaxAmount >= 0 {
		if tx.TxOut[input.VOut].Value > s.utxoMaxAmount {
			return nil, fmt.Errorf(
				"boarding input amount is higher than max utxo amount:%d", s.utxoMaxAmount,
			)
		}
	}
	if tx.TxOut[input.VOut].Value < s.utxoMinAmount {
		return nil, fmt.Errorf(
			"boarding input amount is lower than min utxo amount:%d", s.utxoMinAmount,
		)
	}

	return &tx, nil
}

func (s *service) validateVtxoInput(
	tapscripts txutils.TapTree, expectedTapKey *btcec.PublicKey,
	vtxoCreatedAt int64, now time.Time, locktime *arklib.RelativeLocktime, disabled bool,
	txid string, inputIndex int,
) errors.Error {
	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return errors.INVALID_VTXO_SCRIPT.New("failed to parse vtxo taproot tree: %w", err).
			WithMetadata(errors.InvalidVtxoScriptMetadata{
				Tapscripts: tapscripts,
			})
	}

	smallestExitDelay, err := vtxoScript.SmallestExitDelay()
	if err != nil {
		return errors.INVALID_VTXO_SCRIPT.New("failed to get smallest exit delay: %w", err).
			WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: tapscripts})
	}

	minAllowedExitDelay := s.unilateralExitDelay

	// if the vtxo was created before the vtxoNoCsvValidationCutoffTime date, we use the smallest
	// exit delay as the minimum allowed exit delay in validation: making the CSV check always
	// successful.
	if smallestExitDelay != nil &&
		time.Unix(vtxoCreatedAt, 0).Before(s.vtxoNoCsvValidationCutoffTime) {
		minAllowedExitDelay = *smallestExitDelay
	}

	// validate the vtxo script
	if err := vtxoScript.Validate(
		s.signerPubkey, minAllowedExitDelay, s.allowCSVBlockType,
	); err != nil {
		return errors.INVALID_VTXO_SCRIPT.New("invalid vtxo script: %w", err).
			WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: tapscripts})
	}

	// If the intent is registered using a exit path that contains CSV delay, we want to verify it
	// by shifitng the current "now" in the future of the duration of the smallest exit delay.
	// This way, any exit order guaranteed by the exit path is maintained at intent registration
	if !disabled {
		delta := now.Add(time.Duration(smallestExitDelay.Seconds())*time.Second).
			Unix() -
			vtxoCreatedAt
		if diff := locktime.Seconds() - delta; diff > 0 {
			return errors.INVALID_VTXO_SCRIPT.New(
				"vtxo script can be used for intent registration in %d seconds", diff,
			).WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: tapscripts})
		}
	}

	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return errors.INVALID_VTXO_SCRIPT.New("failed to compute taproot tree: %w", err).
			WithMetadata(errors.InvalidVtxoScriptMetadata{Tapscripts: tapscripts})
	}

	if !bytes.Equal(schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey)) {
		return errors.INVALID_PSBT_INPUT.New(
			"taproot key mismatch: got %x expected %x",
			schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey),
		).WithMetadata(errors.InputMetadata{Txid: txid, InputIndex: inputIndex})
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
		// at this point, the connector is not signed so the vtxo input is the one with
		// Tapscript sigs
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

// propagateTransactionEvent propagates the transaction event to the indexer and the
// transaction events channels
func (s *service) propagateTransactionEvent(event TransactionEvent) {
	go func() {
		s.indexerTxEventsCh <- event
	}()
	go func() {
		s.transactionEventsCh <- event
	}()
}
