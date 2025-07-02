package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

const marketHourDelta = 5 * time.Minute

type covenantlessService struct {
	network             common.Network
	pubkey              *secp256k1.PublicKey
	vtxoTreeExpiry      common.RelativeLocktime
	roundInterval       int64
	unilateralExitDelay common.RelativeLocktime
	boardingExitDelay   common.RelativeLocktime

	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scanner     ports.BlockchainScanner
	sweeper     *sweeper

	txRequests     *txRequestsQueue
	forfeitTxs     *forfeitTxsMap
	redeemTxInputs *outpointMap
	roundInputs    *outpointMap

	stop func()
	ctx  context.Context
	wg   *sync.WaitGroup

	eventsCh            chan domain.RoundEvent
	transactionEventsCh chan TransactionEvent
	// TODO remove this in v7
	indexerTxEventsCh chan TransactionEvent

	// cached data for the current round
	currentRoundLock    sync.Mutex
	currentRound        *domain.Round
	treeSigningSessions map[string]*musigSigningSession

	// TODO derive this from wallet
	serverSigningKey    *secp256k1.PrivateKey
	serverSigningPubKey *secp256k1.PublicKey

	// allowZeroFees is a temporary flag letting to submit redeem txs with zero miner fees
	// this should be removed after we migrate to transactions version 3
	allowZeroFees bool

	numOfBoardingInputs    int
	numOfBoardingInputsMtx sync.RWMutex

	forfeitsBoardingSigsChan chan struct{}

	roundMaxParticipantsCount int64
	utxoMaxAmount             int64
	utxoMinAmount             int64
	vtxoMaxAmount             int64
	vtxoMinAmount             int64
}

func NewService(
	network common.Network,
	roundInterval int64,
	vtxoTreeExpiry, unilateralExitDelay, boardingExitDelay common.RelativeLocktime,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
	noteUriPrefix string,
	marketHourStartTime, marketHourEndTime time.Time,
	marketHourPeriod, marketHourRoundInterval time.Duration,
	allowZeroFees bool,
	roundMaxParticipantsCount int64,
	utxoMaxAmount int64,
	utxoMinAmount int64,
	vtxoMaxAmount int64,
	vtxoMinAmount int64,
) (Service, error) {
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	// Try to load market hours from DB first
	marketHour, err := repoManager.MarketHourRepo().Get(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get market hours from db: %w", err)
	}

	if marketHour == nil {
		marketHour = domain.NewMarketHour(marketHourStartTime, marketHourEndTime, marketHourPeriod, marketHourRoundInterval)
		if err := repoManager.MarketHourRepo().Upsert(context.Background(), *marketHour); err != nil {
			return nil, fmt.Errorf("failed to upsert initial market hours to db: %w", err)
		}
	}

	serverSigningKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %s", err)
	}

	dustAmount, err := walletSvc.GetDustAmount(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get dust amount: %s", err)
	}
	if vtxoMinAmount < int64(dustAmount) {
		vtxoMinAmount = int64(dustAmount)
	}
	if utxoMinAmount < int64(dustAmount) {
		utxoMinAmount = int64(dustAmount)
	}

	ctx, cancel := context.WithCancel(context.Background())

	svc := &covenantlessService{
		network:                   network,
		pubkey:                    pubkey,
		vtxoTreeExpiry:            vtxoTreeExpiry,
		roundInterval:             roundInterval,
		unilateralExitDelay:       unilateralExitDelay,
		wallet:                    walletSvc,
		repoManager:               repoManager,
		builder:                   builder,
		scanner:                   scanner,
		sweeper:                   newSweeper(walletSvc, repoManager, builder, scheduler, noteUriPrefix),
		txRequests:                newTxRequestsQueue(),
		forfeitTxs:                newForfeitTxsMap(builder),
		redeemTxInputs:            newOutpointMap(),
		roundInputs:               newOutpointMap(),
		eventsCh:                  make(chan domain.RoundEvent),
		transactionEventsCh:       make(chan TransactionEvent),
		currentRoundLock:          sync.Mutex{},
		treeSigningSessions:       make(map[string]*musigSigningSession),
		boardingExitDelay:         boardingExitDelay,
		serverSigningKey:          serverSigningKey,
		serverSigningPubKey:       serverSigningKey.PubKey(),
		allowZeroFees:             allowZeroFees,
		forfeitsBoardingSigsChan:  make(chan struct{}, 1),
		roundMaxParticipantsCount: roundMaxParticipantsCount,
		utxoMaxAmount:             utxoMaxAmount,
		utxoMinAmount:             utxoMinAmount,
		vtxoMaxAmount:             vtxoMaxAmount,
		vtxoMinAmount:             vtxoMinAmount,
		indexerTxEventsCh:         make(chan TransactionEvent),
		wg:                        &sync.WaitGroup{},
		stop:                      cancel,
		ctx:                       ctx,
	}

	repoManager.RegisterEventsHandler(
		func(round *domain.Round) {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in propagateEvents: %v", r)
					}
				}()

				svc.propagateEvents(round)
			}()

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in updateVtxoSet and scheduleSweepVtxosForRound: %v", r)
					}
				}()

				// utxo db must be updated before scheduling the sweep events
				svc.updateVtxoSet(round)
				svc.scheduleSweepVtxosForRound(round)
			}()
		},
	)

	if err := svc.restoreWatchingVtxos(); err != nil {
		return nil, fmt.Errorf("failed to restore watching vtxos: %s", err)
	}
	go svc.listenToScannerNotifications()
	return svc, nil
}

func (s *covenantlessService) Start() error {
	log.Debug("starting sweeper service...")
	if err := s.sweeper.start(); err != nil {
		return err
	}

	log.Debug("starting app service...")
	s.wg.Add(1)
	go s.start()
	return nil
}

func (s *covenantlessService) Stop() {
	s.stop()
	s.wg.Wait()
	s.sweeper.stop()
	// nolint
	vtxos, _ := s.repoManager.Vtxos().GetAllSweepableVtxos(context.Background())
	if len(vtxos) > 0 {
		s.stopWatchingVtxos(vtxos)
	}

	s.wallet.Close()
	log.Debug("closed connection to wallet")
	s.repoManager.Close()
	log.Debug("closed connection to db")
	close(s.eventsCh)
}

func (s *covenantlessService) SubmitRedeemTx(
	ctx context.Context, redeemTx string,
) (string, string, error) {
	vtxoRepo := s.repoManager.Vtxos()

	expiration := int64(0)
	roundTxid := ""

	ins := make([]common.VtxoInput, 0)

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse redeem tx: %s", err)
	}

	spentVtxoKeys := make([]domain.VtxoKey, 0, len(ptx.Inputs))
	for _, input := range ptx.UnsignedTx.TxIn {
		spentVtxoKeys = append(spentVtxoKeys, domain.VtxoKey{
			Txid: input.PreviousOutPoint.Hash.String(),
			VOut: input.PreviousOutPoint.Index,
		})
	}

	spentVtxos, err := vtxoRepo.GetVtxos(ctx, spentVtxoKeys)
	if err != nil {
		return "", "", fmt.Errorf("failed to get vtxos: %s", err)
	}

	if len(spentVtxos) != len(spentVtxoKeys) {
		return "", "", fmt.Errorf("some vtxos not found")
	}

	if exists, vtxo := s.roundInputs.includesAny(spentVtxoKeys); exists {
		return "", "", fmt.Errorf("vtxo %s is already registered for next round", vtxo)
	}

	s.redeemTxInputs.add(spentVtxoKeys)
	defer s.redeemTxInputs.remove(spentVtxoKeys)

	vtxoMap := make(map[wire.OutPoint]domain.Vtxo)
	for _, vtxo := range spentVtxos {
		hash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse vtxo txid: %s", err)
		}
		vtxoMap[wire.OutPoint{Hash: *hash, Index: vtxo.VOut}] = vtxo
	}

	sumOfInputs := int64(0)
	for inputIndex, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			return "", "", fmt.Errorf("missing witness utxo")
		}

		if len(input.TaprootLeafScript) == 0 {
			return "", "", fmt.Errorf("missing tapscript leaf")
		}

		tapscripts, err := tree.GetTaprootTree(input)
		if err != nil {
			return "", "", fmt.Errorf("missing tapscripts: %s", err)
		}

		if len(input.TaprootScriptSpendSig) == 0 {
			return "", "", fmt.Errorf("missing tapscript spend sig")
		}

		if len(input.TaprootLeafScript) != 1 {
			return "", "", fmt.Errorf("expected exactly one taproot leaf script")
		}

		signedTapscript := input.TaprootLeafScript[0]

		if signedTapscript == nil {
			return "", "", fmt.Errorf("no matching tapscript found")
		}

		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint

		vtxo, exists := vtxoMap[outpoint]
		if !exists {
			return "", "", fmt.Errorf("vtxo not found")
		}

		// make sure we don't use the same vtxo twice
		delete(vtxoMap, outpoint)

		if vtxo.Spent {
			return "", "", fmt.Errorf("vtxo already spent")
		}

		if vtxo.Redeemed {
			return "", "", fmt.Errorf("vtxo already redeemed")
		}

		if vtxo.Swept {
			return "", "", fmt.Errorf("vtxo already swept")
		}

		vtxoScript, err := tree.ParseVtxoScript(tapscripts)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse vtxo script: %s", err)
		}

		// validate the vtxo script
		if err := vtxoScript.Validate(s.pubkey, s.unilateralExitDelay); err != nil {
			return "", "", fmt.Errorf("invalid vtxo script: %s", err)
		}

		// verify the witnessUtxo script
		if input.WitnessUtxo == nil {
			return "", "", fmt.Errorf("missing witness utxo")
		}

		witnessUtxoScript := input.WitnessUtxo.PkScript

		tapKeyFromTapscripts, _, err := vtxoScript.TapTree()
		if err != nil {
			return "", "", fmt.Errorf("failed to get taproot key from vtxo script: %s", err)
		}

		if vtxo.PubKey != hex.EncodeToString(schnorr.SerializePubKey(tapKeyFromTapscripts)) {
			return "", "", fmt.Errorf("vtxo pubkey mismatch")
		}

		pkScriptFromTapscripts, err := common.P2TRScript(tapKeyFromTapscripts)
		if err != nil {
			return "", "", fmt.Errorf("failed to get pkscript from taproot key: %s", err)
		}

		if !bytes.Equal(witnessUtxoScript, pkScriptFromTapscripts) {
			return "", "", fmt.Errorf("witness utxo script mismatch")
		}

		sumOfInputs += input.WitnessUtxo.Value

		if inputIndex == 0 || vtxo.ExpireAt < expiration {
			roundTxid = vtxo.RoundTxid
			expiration = vtxo.ExpireAt
		}

		// verify that the user signs a forfeit closure
		var userPubkey *secp256k1.PublicKey

		serverXOnlyPubkey := schnorr.SerializePubKey(s.pubkey)

		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, serverXOnlyPubkey) {
				parsed, err := schnorr.ParsePubKey(sig.XOnlyPubKey)
				if err != nil {
					return "", "", fmt.Errorf("failed to parse pubkey: %s", err)
				}
				userPubkey = parsed
				break
			}
		}

		if userPubkey == nil {
			return "", "", fmt.Errorf("redeem transaction is not signed")
		}

		vtxoPubkeyBuf, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode vtxo pubkey: %s", err)
		}

		vtxoPubkey, err := schnorr.ParsePubKey(vtxoPubkeyBuf)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse vtxo pubkey: %s", err)
		}

		// verify witness utxo
		pkscript, err := common.P2TRScript(vtxoPubkey)
		if err != nil {
			return "", "", fmt.Errorf("failed to get pkscript: %s", err)
		}

		if !bytes.Equal(input.WitnessUtxo.PkScript, pkscript) {
			return "", "", fmt.Errorf("witness utxo script mismatch")
		}

		if input.WitnessUtxo.Value != int64(vtxo.Amount) {
			return "", "", fmt.Errorf("witness utxo value mismatch")
		}

		// verify forfeit closure script
		closure, err := tree.DecodeClosure(signedTapscript.Script)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode forfeit closure: %s", err)
		}

		var locktime *common.AbsoluteLocktime

		switch c := closure.(type) {
		case *tree.CLTVMultisigClosure:
			locktime = &c.Locktime
		case *tree.MultisigClosure, *tree.ConditionMultisigClosure:
		default:
			return "", "", fmt.Errorf("invalid forfeit closure script %x, cannot verify redeem tx", signedTapscript.Script)
		}

		if locktime != nil {
			blocktimestamp, err := s.wallet.GetCurrentBlockTime(ctx)
			if err != nil {
				return "", "", fmt.Errorf("failed to get current block time: %s", err)
			}
			if !locktime.IsSeconds() {
				if *locktime > common.AbsoluteLocktime(blocktimestamp.Height) {
					return "", "", fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block time)", *locktime, blocktimestamp.Time)
				}
			} else {
				if *locktime > common.AbsoluteLocktime(blocktimestamp.Time) {
					return "", "", fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block time)", *locktime, blocktimestamp.Time)
				}
			}
		}

		ctrlBlock, err := txscript.ParseControlBlock(signedTapscript.ControlBlock)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse control block: %s", err)
		}

		ins = append(ins, common.VtxoInput{
			Outpoint: &outpoint,
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: signedTapscript.Script,
			},
			RevealedTapscripts: tapscripts,
		})
	}

	outputs := ptx.UnsignedTx.TxOut

	sumOfOutputs := int64(0)
	for _, out := range outputs {
		sumOfOutputs += out.Value

		if s.vtxoMaxAmount >= 0 {
			if out.Value > s.vtxoMaxAmount {
				return "", "", fmt.Errorf("output amount is higher than max vtxo amount:%d", s.vtxoMaxAmount)
			}
		}
		if s.vtxoMinAmount >= 0 {
			if out.Value < s.vtxoMinAmount {
				return "", "", fmt.Errorf("output amount is lower than min utxo amount:%d", s.vtxoMinAmount)
			}
		}
	}

	fees := sumOfInputs - sumOfOutputs
	if fees < 0 {
		return "", "", fmt.Errorf("invalid fees, inputs are less than outputs")
	}

	if !s.allowZeroFees {
		minFeeRate := s.wallet.MinRelayFeeRate(ctx)

		minFees, err := common.ComputeRedeemTxFee(chainfee.SatPerKVByte(minFeeRate), ins, len(outputs))
		if err != nil {
			return "", "", fmt.Errorf("failed to compute min fees: %s", err)
		}

		if fees < minFees {
			return "", "", fmt.Errorf("min relay fee not met, %d < %d", fees, minFees)
		}
	}

	// recompute redeem tx
	rebuiltRedeemTx, err := tree.BuildRedeemTx(ins, outputs)
	if err != nil {
		return "", "", fmt.Errorf("failed to rebuild redeem tx: %s", err)
	}

	rebuiltPtx, err := psbt.NewFromRawBytes(strings.NewReader(rebuiltRedeemTx), true)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse rebuilt redeem tx: %s", err)
	}

	rebuiltTxid := rebuiltPtx.UnsignedTx.TxID()
	redeemTxid := ptx.UnsignedTx.TxID()
	if rebuiltTxid != redeemTxid {
		return "", "", fmt.Errorf("invalid redeem tx")
	}

	// verify the tapscript signatures
	if valid, _, err := s.builder.VerifyTapscriptPartialSigs(redeemTx); err != nil || !valid {
		return "", "", fmt.Errorf("invalid tx signature: %s", err)
	}

	if expiration == 0 {
		return "", "", fmt.Errorf("no valid vtxo found")
	}

	if roundTxid == "" {
		return "", "", fmt.Errorf("no valid vtxo found")
	}

	// sign the redeem tx

	signedRedeemTx, err := s.wallet.SignTransactionTapscript(ctx, redeemTx, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign redeem tx: %s", err)
	}

	go func(ptx *psbt.Packet, signedRedeemTx, redeemTxid string) {
		ctx := context.Background()
		// Create new vtxos, update spent vtxos state
		newVtxos := make([]domain.Vtxo, 0, len(ptx.UnsignedTx.TxOut))
		for outIndex, out := range outputs {
			//notlint:all
			vtxoPubkey := hex.EncodeToString(out.PkScript[2:])

			newVtxos = append(newVtxos, domain.Vtxo{
				VtxoKey: domain.VtxoKey{
					Txid: redeemTxid,
					VOut: uint32(outIndex),
				},
				PubKey:    vtxoPubkey,
				Amount:    uint64(out.Value),
				ExpireAt:  expiration,
				RoundTxid: roundTxid,
				RedeemTx:  signedRedeemTx,
				CreatedAt: time.Now().Unix(),
			})
		}

		if err := s.repoManager.Vtxos().AddVtxos(ctx, newVtxos); err != nil {
			log.WithError(err).Warn("failed to add vtxos")
			return
		}
		log.Debugf("added %d vtxos", len(newVtxos))

		if err := s.repoManager.Vtxos().SpendVtxos(ctx, spentVtxoKeys, redeemTxid); err != nil {
			log.WithError(err).Warn("failed to spend vtxos")
			return
		}
		log.Debugf("spent %d vtxos", len(spentVtxos))

		if err := s.startWatchingVtxos(newVtxos); err != nil {
			log.WithError(err).Warn("failed to start watching vtxos")
		} else {
			log.Debugf("started watching %d vtxos", len(newVtxos))
		}

		for i := range spentVtxos {
			spentVtxos[i].Spent = true
			spentVtxos[i].SpentBy = redeemTxid
		}

		event := RedeemTransactionEvent{
			RedeemTxid:     redeemTxid,
			SpentVtxos:     spentVtxos,
			SpendableVtxos: newVtxos,
			TxHex:          signedRedeemTx,
		}

		s.transactionEventsCh <- event
		s.indexerTxEventsCh <- event
	}(ptx, signedRedeemTx, redeemTxid)

	return signedRedeemTx, redeemTxid, nil
}

func (s *covenantlessService) GetBoardingAddress(
	ctx context.Context, userPubkey *secp256k1.PublicKey,
) (address string, scripts []string, err error) {
	vtxoScript := tree.NewDefaultVtxoScript(s.pubkey, userPubkey, s.boardingExitDelay)

	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey), s.chainParams(),
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get address: %s", err)
	}

	scripts, err = vtxoScript.Encode()
	if err != nil {
		return "", nil, fmt.Errorf("failed to encode vtxo script: %s", err)
	}

	address = addr.EncodeAddress()

	return
}

func (s *covenantlessService) SpendNotes(ctx context.Context, notes []note.Note) (string, error) {
	notesRepo := s.repoManager.Notes()

	for _, note := range notes {
		// verify the note signature
		hash := note.Hash()

		valid, err := s.wallet.VerifyMessageSignature(ctx, hash, note.Signature)
		if err != nil {
			return "", fmt.Errorf("failed to verify note signature: %s", err)
		}

		if !valid {
			return "", fmt.Errorf("invalid note signature %s", note)
		}

		// verify that the note is spendable
		spent, err := notesRepo.Contains(ctx, note.ID)
		if err != nil {
			return "", fmt.Errorf("failed to check if note is spent: %s", err)
		}

		if spent {
			return "", fmt.Errorf("note already spent: %s", note)
		}
	}

	request, err := domain.NewTxRequest(make([]domain.Vtxo, 0))
	if err != nil {
		return "", fmt.Errorf("failed to create tx request: %s", err)
	}

	if err := s.txRequests.pushWithNotes(*request, notes); err != nil {
		return "", fmt.Errorf("failed to push tx requests: %s", err)
	}

	return request.Id, nil
}

func (s *covenantlessService) RegisterIntent(ctx context.Context, bip322signature bip322.Signature, message tree.IntentMessage) (string, error) {
	vtxoKeys := make([]domain.VtxoKey, 0)
	// the vtxo to swap for new ones
	vtxosInputs := make([]domain.Vtxo, 0)
	// the boarding utxos to add in the commitment tx
	boardingInputs := make([]ports.BoardingInput, 0)
	// the vtxos to recover (swept but unspent)
	recoveredVtxos := make([]domain.Vtxo, 0)

	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex

	outpoints := bip322signature.GetOutpoints()

	if len(outpoints) != len(message.InputTapTrees) {
		return "", fmt.Errorf("number of outpoints and taptrees do not match")
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

		tapscripts, err := tree.DecodeTapTree(tapTreeBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decode taptree: %s", err)
		}

		vtxoKey := domain.VtxoKey{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		if s.redeemTxInputs.includes(vtxoKey) {
			return "", fmt.Errorf("vtxo %s is currently being spent", vtxoKey.String())
		}

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{vtxoKey})
		if err != nil || len(vtxosResult) == 0 {
			// vtxo not found in db, check if it exists on-chain
			if _, ok := boardingTxs[vtxoKey.Txid]; !ok {
				// check if the tx exists and is confirmed
				txhex, err := s.wallet.GetTransaction(ctx, outpoint.Hash.String())
				if err != nil {
					return "", fmt.Errorf("failed to get tx %s: %s", vtxoKey.Txid, err)
				}

				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return "", fmt.Errorf("failed to deserialize tx %s: %s", vtxoKey.Txid, err)
				}

				confirmed, _, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, vtxoKey.Txid)
				if err != nil {
					return "", fmt.Errorf("failed to check tx %s: %s", vtxoKey.Txid, err)
				}

				if !confirmed {
					return "", fmt.Errorf("tx %s not confirmed", vtxoKey.Txid)
				}

				vtxoScript, err := tree.ParseVtxoScript(tapscripts)
				if err != nil {
					return "", fmt.Errorf("failed to parse boarding descriptor: %s", err)
				}

				// validate the vtxo script
				if err := vtxoScript.Validate(s.pubkey, common.RelativeLocktime{
					Type:  s.boardingExitDelay.Type,
					Value: s.boardingExitDelay.Value,
				}); err != nil {
					return "", fmt.Errorf("invalid vtxo script: %s", err)
				}

				exitDelay, err := vtxoScript.SmallestExitDelay()
				if err != nil {
					return "", fmt.Errorf("failed to get exit delay: %s", err)
				}

				// if the exit path is available, forbid registering the boarding utxo
				if time.Unix(blocktime, 0).Add(time.Duration(exitDelay.Seconds()) * time.Second).Before(time.Now()) {
					return "", fmt.Errorf("tx %s expired", vtxoKey.Txid)
				}

				if s.utxoMaxAmount >= 0 {
					if tx.TxOut[outpoint.Index].Value > s.utxoMaxAmount {
						return "", fmt.Errorf("boarding input amount is higher than max utxo amount:%d", s.utxoMaxAmount)
					}
				}
				if s.utxoMinAmount >= 0 {
					if tx.TxOut[outpoint.Index].Value < s.utxoMinAmount {
						return "", fmt.Errorf("boarding input amount is lower than min utxo amount:%d", s.utxoMinAmount)
					}
				}

				boardingTxs[vtxoKey.Txid] = tx
			}

			tx := boardingTxs[vtxoKey.Txid]
			prevout := tx.TxOut[vtxoKey.VOut]
			prevouts[outpoint] = prevout
			boardingInput, err := s.newBoardingInput(tx, ports.Input{
				VtxoKey:    vtxoKey,
				Tapscripts: tapscripts,
			})
			if err != nil {
				return "", err
			}

			boardingInputs = append(boardingInputs, *boardingInput)
			continue
		}

		vtxo := vtxosResult[0]
		if vtxo.Spent {
			return "", fmt.Errorf("input %s:%d already spent", vtxo.Txid, vtxo.VOut)
		}

		if vtxo.Redeemed {
			return "", fmt.Errorf("input %s:%d already redeemed", vtxo.Txid, vtxo.VOut)
		}

		// set the prevout
		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode script pubkey: %s", err)
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse pubkey: %s", err)
		}

		pkScript, err := common.P2TRScript(pubkey)
		if err != nil {
			return "", fmt.Errorf("failed to create p2tr script: %s", err)
		}

		prevouts[outpoint] = &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: pkScript,
		}

		if vtxo.Swept {
			// the user is asking for recovery of the vtxo
			recoveredVtxos = append(recoveredVtxos, vtxo)
			continue
		}

		vtxoScript, err := tree.ParseVtxoScript(tapscripts)
		if err != nil {
			return "", fmt.Errorf("failed to parse boarding descriptor: %s", err)
		}

		// validate the vtxo script
		if err := vtxoScript.Validate(s.pubkey, s.unilateralExitDelay); err != nil {
			return "", fmt.Errorf("invalid vtxo script: %s", err)
		}

		tapKey, _, err := vtxoScript.TapTree()
		if err != nil {
			return "", fmt.Errorf("failed to get taproot key: %s", err)
		}

		expectedTapKey, err := vtxo.TapKey()
		if err != nil {
			return "", fmt.Errorf("failed to get taproot key: %s", err)
		}

		if !bytes.Equal(schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey)) {
			return "", fmt.Errorf("descriptor does not match vtxo pubkey")
		}

		vtxosInputs = append(vtxosInputs, vtxo)
		vtxoKeys = append(vtxoKeys, vtxo.VtxoKey)
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)

	encodedMessage, err := message.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode message: %s", err)
	}

	if err := bip322signature.Verify(encodedMessage, prevoutFetcher); err != nil {
		return "", fmt.Errorf("invalid BIP0322 proof of funds: %s", err)
	}

	request, err := domain.NewTxRequest(vtxosInputs)
	if err != nil {
		return "", err
	}

	if bip322signature.ContainsOutputs() {
		hasOffChainReceiver := false
		receivers := make([]domain.Receiver, 0)

		for outputIndex, output := range bip322signature.TxOut {
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
						return "", fmt.Errorf("receiver amount is higher than max utxo amount:%d", s.vtxoMaxAmount)
					}
				}
				if s.utxoMinAmount >= 0 {
					if amount < uint64(s.utxoMinAmount) {
						return "", fmt.Errorf("receiver amount is lower than min utxo amount:%d", s.vtxoMinAmount)
					}
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
						return "", fmt.Errorf("receiver amount is higher than max vtxo amount:%d", s.vtxoMaxAmount)
					}
				}
				if s.vtxoMinAmount >= 0 {
					if amount < uint64(s.vtxoMinAmount) {
						return "", fmt.Errorf("receiver amount is lower than min vtxo amount:%d", s.vtxoMinAmount)
					}
				}

				hasOffChainReceiver = true
				rcv.PubKey = hex.EncodeToString(output.PkScript[2:])
			}

			receivers = append(receivers, rcv)
		}

		if hasOffChainReceiver {
			if message.Musig2Data == nil {
				return "", fmt.Errorf("musig2 data is required for offchain receivers")
			}

			// check if the server pubkey has been set as cosigner
			serverPubKeyHex := hex.EncodeToString(s.serverSigningPubKey.SerializeCompressed())
			for _, pubkey := range message.Musig2Data.CosignersPublicKeys {
				if pubkey == serverPubKeyHex {
					return "", fmt.Errorf("server pubkey already in musig2 data")
				}
			}
		}

		if err := request.AddReceivers(receivers); err != nil {
			return "", err
		}
	}

	if err := s.txRequests.push(*request, boardingInputs, recoveredVtxos, message.Musig2Data); err != nil {
		return "", err
	}

	s.roundInputs.add(vtxoKeys)

	return request.Id, nil
}

func (s *covenantlessService) SpendVtxos(ctx context.Context, inputs []ports.Input) (string, error) {
	vtxosInputs := make([]domain.Vtxo, 0)
	vtxoKeys := make([]domain.VtxoKey, 0)
	boardingInputs := make([]ports.BoardingInput, 0)

	now := time.Now().Unix()

	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex

	for _, input := range inputs {
		if s.redeemTxInputs.includes(input.VtxoKey) {
			return "", fmt.Errorf("vtxo %s is currently being spent", input.String())
		}

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{input.VtxoKey})
		if err != nil || len(vtxosResult) == 0 {
			// vtxo not found in db, check if it exists on-chain
			if _, ok := boardingTxs[input.Txid]; !ok {
				// check if the tx exists and is confirmed
				txhex, err := s.wallet.GetTransaction(ctx, input.Txid)
				if err != nil {
					return "", fmt.Errorf("failed to get tx %s: %s", input.Txid, err)
				}

				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return "", fmt.Errorf("failed to deserialize tx %s: %s", input.Txid, err)
				}

				confirmed, _, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, input.Txid)
				if err != nil {
					return "", fmt.Errorf("failed to check tx %s: %s", input.Txid, err)
				}

				if !confirmed {
					return "", fmt.Errorf("tx %s not confirmed", input.Txid)
				}

				vtxoScript, err := tree.ParseVtxoScript(input.Tapscripts)
				if err != nil {
					return "", fmt.Errorf("failed to parse boarding descriptor: %s", err)
				}

				// validate the vtxo script
				// TODO: fix in PR #501
				if err := vtxoScript.Validate(s.pubkey, common.RelativeLocktime{
					Type:  s.unilateralExitDelay.Type,
					Value: s.unilateralExitDelay.Value * 2,
				}); err != nil {
					return "", fmt.Errorf("invalid vtxo script: %s", err)
				}

				exitDelay, err := vtxoScript.SmallestExitDelay()
				if err != nil {
					return "", fmt.Errorf("failed to get exit delay: %s", err)
				}

				// if the exit path is available, forbid registering the boarding utxo
				if blocktime+exitDelay.Seconds() < now {
					return "", fmt.Errorf("tx %s expired", input.Txid)
				}

				if s.utxoMaxAmount >= 0 {
					if tx.TxOut[input.VOut].Value > s.utxoMaxAmount {
						return "", fmt.Errorf("boarding input amount is higher than max utxo amount:%d", s.utxoMaxAmount)
					}
				}
				if s.utxoMinAmount >= 0 {
					if tx.TxOut[input.VOut].Value < s.utxoMinAmount {
						return "", fmt.Errorf("boarding input amount is lower than min utxo amount:%d", s.utxoMinAmount)
					}
				}

				boardingTxs[input.Txid] = tx
			}

			tx := boardingTxs[input.Txid]
			boardingInput, err := s.newBoardingInput(tx, input)
			if err != nil {
				return "", err
			}

			boardingInputs = append(boardingInputs, *boardingInput)
			continue
		}

		vtxo := vtxosResult[0]
		if vtxo.Spent {
			return "", fmt.Errorf("input %s:%d already spent", vtxo.Txid, vtxo.VOut)
		}

		if vtxo.Redeemed {
			return "", fmt.Errorf("input %s:%d already redeemed", vtxo.Txid, vtxo.VOut)
		}

		if vtxo.Swept {
			return "", fmt.Errorf("input %s:%d already swept", vtxo.Txid, vtxo.VOut)
		}

		vtxoScript, err := tree.ParseVtxoScript(input.Tapscripts)
		if err != nil {
			return "", fmt.Errorf("failed to parse boarding descriptor: %s", err)
		}

		// validate the vtxo script
		if err := vtxoScript.Validate(s.pubkey, s.unilateralExitDelay); err != nil {
			return "", fmt.Errorf("invalid vtxo script: %s", err)
		}

		tapKey, _, err := vtxoScript.TapTree()
		if err != nil {
			return "", fmt.Errorf("failed to get taproot key: %s", err)
		}

		expectedTapKey, err := vtxo.TapKey()
		if err != nil {
			return "", fmt.Errorf("failed to get taproot key: %s", err)
		}

		if !bytes.Equal(schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey)) {
			return "", fmt.Errorf("descriptor does not match vtxo pubkey")
		}

		vtxosInputs = append(vtxosInputs, vtxo)
		vtxoKeys = append(vtxoKeys, vtxo.VtxoKey)
	}

	request, err := domain.NewTxRequest(vtxosInputs)
	if err != nil {
		return "", err
	}

	if err := s.txRequests.push(*request, boardingInputs, nil, nil); err != nil {
		return "", err
	}

	s.roundInputs.add(vtxoKeys)

	return request.Id, nil
}

func (s *covenantlessService) newBoardingInput(tx wire.MsgTx, input ports.Input) (*ports.BoardingInput, error) {
	if len(tx.TxOut) <= int(input.VOut) {
		return nil, fmt.Errorf("output not found")
	}

	output := tx.TxOut[input.VOut]

	boardingScript, err := tree.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding descriptor: %s", err)
	}

	tapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	expectedScriptPubkey, err := common.P2TRScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get script pubkey: %s", err)
	}

	if !bytes.Equal(output.PkScript, expectedScriptPubkey) {
		return nil, fmt.Errorf("descriptor does not match script in transaction output")
	}

	if err := boardingScript.Validate(s.pubkey, s.unilateralExitDelay); err != nil {
		return nil, err
	}

	return &ports.BoardingInput{
		Amount: uint64(output.Value),
		Input:  input,
	}, nil
}

func (s *covenantlessService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver, musig2Data *tree.Musig2) error {
	// Check credentials
	request, ok := s.txRequests.view(creds)
	if !ok {
		return fmt.Errorf("invalid credentials")
	}

	hasOffChainReceiver := false

	for _, rcv := range receivers {
		if s.vtxoMaxAmount >= 0 {
			if rcv.Amount > uint64(s.vtxoMaxAmount) {
				return fmt.Errorf("receiver amount is higher than max vtxo amount:%d", s.vtxoMaxAmount)
			}
		}
		if s.vtxoMinAmount >= 0 {
			if rcv.Amount < uint64(s.vtxoMinAmount) {
				return fmt.Errorf("receiver amount is lower than min vtxo amount:%d", s.vtxoMinAmount)
			}
		}

		if !rcv.IsOnchain() {
			hasOffChainReceiver = true
		}
	}

	var data *tree.Musig2

	if hasOffChainReceiver {
		if musig2Data == nil {
			return fmt.Errorf("musig2 data is required for offchain receivers")
		}

		// check if the server pubkey has been set as cosigner
		serverPubKeyHex := hex.EncodeToString(s.serverSigningPubKey.SerializeCompressed())
		for _, pubkey := range musig2Data.CosignersPublicKeys {
			if pubkey == serverPubKeyHex {
				return fmt.Errorf("server pubkey already in musig2 data")
			}
		}

		data = musig2Data
	}

	if err := request.AddReceivers(receivers); err != nil {
		return err
	}

	return s.txRequests.update(*request, data)
}

func (s *covenantlessService) UpdateTxRequestStatus(_ context.Context, id string) error {
	return s.txRequests.updatePingTimestamp(id)
}

func (s *covenantlessService) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	if len(forfeitTxs) <= 0 {
		return nil
	}

	if err := s.forfeitTxs.sign(forfeitTxs); err != nil {
		return err
	}

	go func() {
		s.currentRoundLock.Lock()
		round := s.currentRound
		s.currentRoundLock.Unlock()
		s.checkForfeitsAndBoardingSigsSent(round)
	}()

	return nil
}

func (s *covenantlessService) SignRoundTx(ctx context.Context, signedRoundTx string) error {
	numSignedInputs, err := s.builder.CountSignedTaprootInputs(signedRoundTx)
	if err != nil {
		return fmt.Errorf("failed to count number of signed boarding inputs: %s", err)
	}
	if numSignedInputs == 0 {
		return nil
	}

	s.currentRoundLock.Lock()
	defer s.currentRoundLock.Unlock()
	currentRound := s.currentRound

	combined, err := s.builder.VerifyAndCombinePartialTx(currentRound.UnsignedTx, signedRoundTx)
	if err != nil {
		return fmt.Errorf("failed to verify and combine partial tx: %s", err)
	}

	s.currentRound.UnsignedTx = combined

	go func() {
		s.currentRoundLock.Lock()
		round := s.currentRound
		s.currentRoundLock.Unlock()
		s.checkForfeitsAndBoardingSigsSent(round)
	}()

	return nil
}

func (s *covenantlessService) checkForfeitsAndBoardingSigsSent(currentRound *domain.Round) {
	roundTx, _ := psbt.NewFromRawBytes(strings.NewReader(currentRound.UnsignedTx), true)
	numOfInputsSigned := 0
	for _, v := range roundTx.Inputs {
		if len(v.TaprootScriptSpendSig) > 0 {
			if len(v.TaprootScriptSpendSig[0].Signature) > 0 {
				numOfInputsSigned++
			}
		}
	}

	// Condition: all forfeit txs are signed and
	// the number of signed boarding inputs matches
	// numOfBoardingInputs we expect
	s.numOfBoardingInputsMtx.RLock()
	numOfBoardingInputs := s.numOfBoardingInputs
	s.numOfBoardingInputsMtx.RUnlock()
	if s.forfeitTxs.allSigned() && numOfBoardingInputs == numOfInputsSigned {
		select {
		case s.forfeitsBoardingSigsChan <- struct{}{}:
		default:
		}
	}
}

func (s *covenantlessService) ListVtxos(ctx context.Context, address string) ([]domain.Vtxo, []domain.Vtxo, error) {
	decodedAddress, err := common.DecodeAddress(address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode address: %s", err)
	}

	if !bytes.Equal(schnorr.SerializePubKey(decodedAddress.Server), schnorr.SerializePubKey(s.pubkey)) {
		return nil, nil, fmt.Errorf("address does not match server pubkey")
	}

	pubkey := hex.EncodeToString(schnorr.SerializePubKey(decodedAddress.VtxoTapKey))

	return s.repoManager.Vtxos().GetAllNonRedeemedVtxos(ctx, pubkey)
}

func (s *covenantlessService) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *covenantlessService) GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent {
	return s.transactionEventsCh
}

// TODO remove this in v7
func (s *covenantlessService) GetIndexerTxChannel(ctx context.Context) <-chan TransactionEvent {
	return s.indexerTxEventsCh
}

func (s *covenantlessService) GetRoundByTxid(ctx context.Context, roundTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, roundTxid)
}

func (s *covenantlessService) GetRoundById(ctx context.Context, id string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithId(ctx, id)
}

func (s *covenantlessService) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	return domain.NewRoundFromEvents(s.currentRound.Events()), nil
}

func (s *covenantlessService) GetInfo(ctx context.Context) (*ServiceInfo, error) {
	pubkey := hex.EncodeToString(s.pubkey.SerializeCompressed())

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

	marketHourNextStart, marketHourNextEnd, err := calcNextMarketHour(
		marketHourConfig.StartTime,
		marketHourConfig.EndTime,
		marketHourConfig.Period,
		marketHourDelta,
		time.Now(),
	)
	if err != nil {
		return nil, err
	}

	return &ServiceInfo{
		PubKey:              pubkey,
		VtxoTreeExpiry:      int64(s.vtxoTreeExpiry.Value),
		UnilateralExitDelay: int64(s.unilateralExitDelay.Value),
		BoardingExitDelay:   int64(s.boardingExitDelay.Value),
		RoundInterval:       s.roundInterval,
		Network:             s.network.Name,
		Dust:                dust,
		ForfeitAddress:      forfeitAddr,
		NextMarketHour: &NextMarketHour{
			StartTime:     marketHourNextStart,
			EndTime:       marketHourNextEnd,
			Period:        marketHourConfig.Period,
			RoundInterval: marketHourConfig.RoundInterval,
		},
		UtxoMinAmount: s.utxoMinAmount,
		UtxoMaxAmount: s.utxoMaxAmount,
		VtxoMinAmount: s.vtxoMinAmount,
		VtxoMaxAmount: s.vtxoMaxAmount,
	}, nil
}

func (s *covenantlessService) GetTxRequestQueue(
	ctx context.Context, requestIds ...string,
) ([]TxRequestInfo, error) {
	requests, err := s.txRequests.viewAll(requestIds)
	if err != nil {
		return nil, err
	}

	txReqsInfo := make([]TxRequestInfo, 0, len(requests))
	for _, request := range requests {
		signingType := "branch"
		cosigners := make([]string, 0)
		if request.musig2Data != nil {
			if request.musig2Data.SigningType == tree.SignAll {
				signingType = "all"
			}
			cosigners = request.musig2Data.CosignersPublicKeys
		}

		receivers := make([]struct {
			Address string
			Amount  uint64
		}, 0, len(request.Receivers))
		for _, receiver := range request.Receivers {
			if len(receiver.OnchainAddress) > 0 {
				receivers = append(receivers, struct {
					Address string
					Amount  uint64
				}{
					Address: receiver.OnchainAddress,
					Amount:  receiver.Amount,
				})
				continue
			}

			pubkey, err := hex.DecodeString(receiver.PubKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode pubkey: %s", err)
			}

			vtxoTapKey, err := schnorr.ParsePubKey(pubkey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse pubkey: %s", err)
			}

			address := common.Address{
				HRP:        s.network.Addr,
				Server:     s.pubkey,
				VtxoTapKey: vtxoTapKey,
			}

			addressStr, err := address.Encode()
			if err != nil {
				return nil, fmt.Errorf("failed to encode address: %s", err)
			}

			receivers = append(receivers, struct {
				Address string
				Amount  uint64
			}{
				Address: addressStr,
				Amount:  receiver.Amount,
			})
		}

		txReqsInfo = append(txReqsInfo, TxRequestInfo{
			Id:             request.Id,
			CreatedAt:      request.timestamp,
			Receivers:      receivers,
			Inputs:         request.Inputs,
			BoardingInputs: request.boardingInputs,
			Notes:          request.notes,
			LastPing:       request.pingTimestamp,
			SigningType:    signingType,
			Cosigners:      cosigners,
		})
	}

	return txReqsInfo, nil
}

func (s *covenantlessService) DeleteTxRequests(
	ctx context.Context, requestIds ...string,
) error {
	if len(requestIds) == 0 {
		return s.txRequests.deleteAll()
	}

	return s.txRequests.delete(requestIds)
}

func calcNextMarketHour(marketHourStartTime, marketHourEndTime time.Time, period, marketHourDelta time.Duration, now time.Time) (time.Time, time.Time, error) {
	// Validate input parameters
	if period <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("period must be greater than 0")
	}
	if !marketHourEndTime.After(marketHourStartTime) {
		return time.Time{}, time.Time{}, fmt.Errorf("market hour end time must be after start time")
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

	if !now.Before(currentStartTime) && now.Before(currentEndTime) && timeUntilEnd >= marketHourDelta {
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

func (s *covenantlessService) RegisterCosignerNonces(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, encodedNonces string,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	userPubkey := hex.EncodeToString(pubkey.SerializeCompressed())
	if _, ok := session.cosigners[userPubkey]; !ok {
		return fmt.Errorf(`cosigner %s not found for round "%s"`, userPubkey, roundID)
	}

	nonces, err := tree.DecodeNonces(hex.NewDecoder(strings.NewReader(encodedNonces)))
	if err != nil {
		return fmt.Errorf("failed to decode nonces: %s", err)
	}

	go func(session *musigSigningSession) {
		session.lock.Lock()
		defer session.lock.Unlock()

		if _, ok := session.nonces[pubkey]; ok {
			return // skip if we already have nonces for this pubkey
		}

		session.nonces[pubkey] = nonces

		if len(session.nonces) == session.nbCosigners-1 { // exclude the server
			go func() {
				session.nonceDoneC <- struct{}{}
			}()
		}
	}(session)

	return nil
}

func (s *covenantlessService) RegisterCosignerSignatures(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, encodedSignatures string,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	userPubkey := hex.EncodeToString(pubkey.SerializeCompressed())
	if _, ok := session.cosigners[userPubkey]; !ok {
		return fmt.Errorf(`cosigner %s not found for round "%s"`, userPubkey, roundID)
	}

	signatures, err := tree.DecodeSignatures(hex.NewDecoder(strings.NewReader(encodedSignatures)))
	if err != nil {
		return fmt.Errorf("failed to decode signatures: %s", err)
	}

	go func(session *musigSigningSession) {
		session.lock.Lock()
		defer session.lock.Unlock()

		if _, ok := session.signatures[pubkey]; ok {
			return // skip if we already have signatures for this pubkey
		}

		session.signatures[pubkey] = signatures

		if len(session.signatures) == session.nbCosigners-1 { // exclude the server
			go func() {
				session.sigDoneC <- struct{}{}
			}()
		}
	}(session)

	return nil
}

func (s *covenantlessService) start() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic in start: %v", r)
		}
	}()

	s.startRound()
}

func (s *covenantlessService) startRound() {
	defer s.wg.Done()

	select {
	case <-s.ctx.Done():
		return
	default:
	}
	// reset the forfeit txs map to avoid polluting the next batch of forfeits transactions
	s.forfeitTxs.reset()

	dustAmount, err := s.wallet.GetDustAmount(context.Background())
	if err != nil {
		log.WithError(err).Warn("failed to get dust amount")
		return
	}

	round := domain.NewRound(dustAmount)
	//nolint:all
	round.StartRegistration()
	s.currentRound = round
	close(s.forfeitsBoardingSigsChan)
	s.forfeitsBoardingSigsChan = make(chan struct{}, 1)

	log.Debugf("started registration stage for new round: %s", round.Id)

	roundEndTime := time.Now().Add(time.Duration(s.roundInterval) * time.Second)
	sleepingTime := s.roundInterval / 6
	if sleepingTime < 1 {
		sleepingTime = 1
	}
	time.Sleep(time.Duration(sleepingTime) * time.Second)
	s.wg.Add(1)
	go s.startFinalization(roundEndTime)
}
func (s *covenantlessService) startFinalization(roundEndTime time.Time) {
	defer s.wg.Done()

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	log.Debugf("started finalization stage for round: %s", s.currentRound.Id)
	ctx := context.Background()
	round := s.currentRound

	roundRemainingDuration := time.Duration((s.roundInterval/3)*2-1) * time.Second
	thirdOfRemainingDuration := roundRemainingDuration / 3

	var notes []note.Note
	var recoveredVtxos []domain.Vtxo
	var roundAborted bool
	var vtxoKeys []domain.VtxoKey
	defer func() {
		s.wg.Add(1)

		if roundAborted {
			go s.startRound()
			return
		}

		delete(s.treeSigningSessions, round.Id)

		if err := s.saveEvents(ctx, round.Id, round.Events()); err != nil {
			log.WithError(err).Warn("failed to store new round events")
		}

		if round.IsFailed() {
			s.roundInputs.remove(vtxoKeys)
			go s.startRound()
			return
		}

		go s.finalizeRound(notes, recoveredVtxos, roundEndTime)
	}()

	if round.IsFailed() {
		return
	}

	// nolint:all
	availableBalance, _, _ := s.wallet.MainAccountBalance(ctx)

	// TODO: understand how many tx requests must be popped from the queue and actually registered for the round
	num := s.txRequests.len()
	if num == 0 {
		roundAborted = true
		err := fmt.Errorf("no tx requests registered")
		round.Fail(fmt.Errorf("round aborted: %s", err))
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}
	if num > s.roundMaxParticipantsCount {
		num = s.roundMaxParticipantsCount
	}
	requests, boardingInputs, redeeemedNotes, musig2data, vtxosToRecover := s.txRequests.pop(num)
	// save notes and recovered vtxos for finalize function
	notes = redeeemedNotes
	recoveredVtxos = vtxosToRecover
	for _, req := range requests {
		for _, in := range req.Inputs {
			vtxoKeys = append(vtxoKeys, in.VtxoKey)
		}
	}
	s.numOfBoardingInputsMtx.Lock()
	s.numOfBoardingInputs = len(boardingInputs)
	s.numOfBoardingInputsMtx.Unlock()

	totAmount := uint64(0)
	for _, request := range requests {
		totAmount += request.TotalOutputAmount()
	}
	if availableBalance <= totAmount {
		err := fmt.Errorf("not enough liquidity")
		round.Fail(err)
		log.WithError(err).Debugf("round %s aborted, balance: %d", round.Id, availableBalance)
		return
	}

	if _, err := round.RegisterTxRequests(requests); err != nil {
		round.Fail(fmt.Errorf("failed to register tx requests: %s", err))
		log.WithError(err).Warn("failed to register tx requests")
		return
	}

	connectorAddresses, err := s.repoManager.Rounds().GetSweptRoundsConnectorAddress(ctx)
	if err != nil {
		round.Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	// add server pubkey in musig2data and count the number of unique keys
	uniqueSignerPubkeys := make(map[string]struct{})
	serverPubKeyHex := hex.EncodeToString(s.serverSigningPubKey.SerializeCompressed())
	for _, data := range musig2data {
		if data == nil {
			continue
		}
		for _, pubkey := range data.CosignersPublicKeys {
			uniqueSignerPubkeys[pubkey] = struct{}{}
		}
		data.CosignersPublicKeys = append(data.CosignersPublicKeys, serverPubKeyHex)
	}
	log.Debugf("building tx for round %s", round.Id)
	unsignedRoundTx, vtxoTree, connectorAddress, connectors, err := s.builder.BuildRoundTx(
		s.pubkey, requests, boardingInputs, connectorAddresses, musig2data,
	)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create round tx: %s", err))
		log.WithError(err).Warn("failed to create round tx")
		return
	}
	log.Debugf("round tx created for round %s", round.Id)

	if err := s.forfeitTxs.init(connectors, requests); err != nil {
		round.Fail(fmt.Errorf("failed to initialize forfeit txs: %s", err))
		log.WithError(err).Warn("failed to initialize forfeit txs")
		return
	}

	if len(vtxoTree) > 0 {
		sweepClosure := tree.CSVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{PubKeys: []*secp256k1.PublicKey{s.pubkey}},
			Locktime:        s.vtxoTreeExpiry,
		}

		sweepScript, err := sweepClosure.Script()
		if err != nil {
			return
		}

		unsignedPsbt, err := psbt.NewFromRawBytes(strings.NewReader(unsignedRoundTx), true)
		if err != nil {
			round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
			log.WithError(err).Warn("failed to parse round tx")
			return
		}

		sharedOutputAmount := unsignedPsbt.UnsignedTx.TxOut[0].Value

		sweepLeaf := txscript.NewBaseTapLeaf(sweepScript)
		sweepTapTree := txscript.AssembleTaprootScriptTree(sweepLeaf)
		root := sweepTapTree.RootNode.TapHash()

		coordinator, err := tree.NewTreeCoordinatorSession(sharedOutputAmount, vtxoTree, root.CloneBytes())
		if err != nil {
			round.Fail(fmt.Errorf("failed to create tree coordinator: %s", err))
			log.WithError(err).Warn("failed to create tree coordinator")
			return
		}

		serverSignerSession := tree.NewTreeSignerSession(s.serverSigningKey)
		if err := serverSignerSession.Init(root.CloneBytes(), sharedOutputAmount, vtxoTree); err != nil {
			round.Fail(fmt.Errorf("failed to create tree signer session: %s", err))
			log.WithError(err).Warn("failed to create tree signer session")
			return
		}

		nonces, err := serverSignerSession.GetNonces()
		if err != nil {
			round.Fail(fmt.Errorf("failed to get nonces: %s", err))
			log.WithError(err).Warn("failed to get nonces")
			return
		}

		coordinator.AddNonce(s.serverSigningPubKey, nonces)

		signingSession := newMusigSigningSession(uniqueSignerPubkeys)
		s.treeSigningSessions[round.Id] = signingSession

		log.Debugf("signing session created for round %s with %d signers", round.Id, len(uniqueSignerPubkeys))

		s.currentRound.UnsignedTx = unsignedRoundTx
		// send back the unsigned tree & all cosigners pubkeys
		listOfCosignersPubkeys := make([]string, 0, len(uniqueSignerPubkeys))
		for pubkey := range uniqueSignerPubkeys {
			listOfCosignersPubkeys = append(listOfCosignersPubkeys, pubkey)
		}

		s.propagateRoundSigningStartedEvent(vtxoTree, listOfCosignersPubkeys)

		noncesTimer := time.NewTimer(thirdOfRemainingDuration)

		select {
		case <-noncesTimer.C:
			err := fmt.Errorf(
				"musig2 signing session timed out (nonce collection), collected %d/%d nonces",
				len(signingSession.nonces), len(uniqueSignerPubkeys),
			)
			round.Fail(err)
			log.Warn(err)
			return
		case <-signingSession.nonceDoneC:
			noncesTimer.Stop()
			for pubkey, nonce := range signingSession.nonces {
				coordinator.AddNonce(pubkey, nonce)
			}
		}

		log.Debugf("nonces collected for round %s", round.Id)

		aggregatedNonces, err := coordinator.AggregateNonces()
		if err != nil {
			round.Fail(fmt.Errorf("failed to aggregate nonces: %s", err))
			log.WithError(err).Warn("failed to aggregate nonces")
			return
		}

		log.Debugf("nonces aggregated for round %s", round.Id)

		serverSignerSession.SetAggregatedNonces(aggregatedNonces)

		// send the combined nonces to the clients
		s.propagateRoundSigningNoncesGeneratedEvent(aggregatedNonces)

		// sign the tree as server
		serverTreeSigs, err := serverSignerSession.Sign()
		if err != nil {
			round.Fail(fmt.Errorf("failed to sign tree: %s", err))
			log.WithError(err).Warn("failed to sign tree")
			return
		}
		coordinator.AddSignatures(s.serverSigningPubKey, serverTreeSigs)

		log.Debugf("tree signed by us for round %s", round.Id)

		signaturesTimer := time.NewTimer(thirdOfRemainingDuration)

		log.Debugf("waiting for cosigners to sign the tree")

		select {
		case <-signaturesTimer.C:
			err := fmt.Errorf(
				"musig2 signing session timed out (signatures collection), collected %d/%d signatures",
				len(signingSession.signatures), len(uniqueSignerPubkeys),
			)
			round.Fail(err)
			log.Warn(err)
			return
		case <-signingSession.sigDoneC:
			signaturesTimer.Stop()
			for pubkey, sig := range signingSession.signatures {
				coordinator.AddSignatures(pubkey, sig)
			}
		}

		log.Debugf("signatures collected for round %s", round.Id)

		signedTree, err := coordinator.SignTree()
		if err != nil {
			round.Fail(fmt.Errorf("failed to aggregate tree signatures: %s", err))
			log.WithError(err).Warn("failed to aggregate tree signatures")
			return
		}

		log.Debugf("vtxo tree signed for round %s", round.Id)

		vtxoTree = signedTree
	}

	_, err = round.StartFinalization(
		connectorAddress, connectors, vtxoTree, unsignedRoundTx, s.forfeitTxs.connectorsIndex,
	)
	if err != nil {
		round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *covenantlessService) propagateRoundSigningStartedEvent(unsignedVtxoTree tree.TxTree, cosignersPubkeys []string) {
	ev := RoundSigningStarted{
		Id:               s.currentRound.Id,
		UnsignedVtxoTree: unsignedVtxoTree,
		UnsignedRoundTx:  s.currentRound.UnsignedTx,
		CosignersPubkeys: cosignersPubkeys,
	}

	s.eventsCh <- ev
}

func (s *covenantlessService) propagateRoundSigningNoncesGeneratedEvent(combinedNonces tree.TreeNonces) {
	ev := RoundSigningNoncesGenerated{
		Id:     s.currentRound.Id,
		Nonces: combinedNonces,
	}

	s.eventsCh <- ev
}

func (s *covenantlessService) finalizeRound(notes []note.Note, recoveredVtxos []domain.Vtxo, roundEndTime time.Time) {
	defer s.wg.Done()

	var stopped bool

	defer func() {
		if !stopped {
			s.wg.Add(1)
			go s.startRound()
		}
	}()

	ctx := context.Background()
	s.currentRoundLock.Lock()
	round := s.currentRound
	s.currentRoundLock.Unlock()

	defer func() {
		vtxoKeys := make([]domain.VtxoKey, 0)
		for _, req := range round.TxRequests {
			for _, in := range req.Inputs {
				vtxoKeys = append(vtxoKeys, in.VtxoKey)
			}
		}
		s.roundInputs.remove(vtxoKeys)
	}()

	select {
	case <-s.ctx.Done():
		stopped = true
		return
	default:
	}

	if round.IsFailed() {
		return
	}

	var changes []domain.RoundEvent
	defer func() {
		if err := s.saveEvents(ctx, round.Id, changes); err != nil {
			log.WithError(err).Warn("failed to store new round events")
			return
		}
	}()

	roundTx, err := psbt.NewFromRawBytes(strings.NewReader(round.UnsignedTx), true)
	if err != nil {
		log.Debugf("failed to parse round tx: %s", round.UnsignedTx)
		changes = round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
		log.WithError(err).Warn("failed to parse round tx")
		return
	}
	includesBoardingInputs := false
	for _, in := range roundTx.Inputs {
		// TODO: this is ok as long as the server doesn't use taproot address too!
		// We need to find a better way to understand if an in input is ours or if
		// it's a boarding one.
		scriptType := txscript.GetScriptClass(in.WitnessUtxo.PkScript)
		if scriptType == txscript.WitnessV1TaprootTy {
			includesBoardingInputs = true
			break
		}
	}

	txToSign := round.UnsignedTx
	boardingInputs := make([]domain.VtxoKey, 0)
	forfeitTxs := make([]domain.ForfeitTx, 0)

	if len(s.forfeitTxs.forfeitTxs) > 0 || includesBoardingInputs {
		remainingTime := time.Until(roundEndTime)
		select {
		case <-s.forfeitsBoardingSigsChan:
			log.Debug("all forfeit txs and boarding inputs signatures have been sent")
		case <-time.After(remainingTime):
			log.Debug("timeout waiting for forfeit txs and boarding inputs signatures")
		}

		s.currentRoundLock.Lock()
		round := s.currentRound
		s.currentRoundLock.Unlock()

		roundTx, err := psbt.NewFromRawBytes(strings.NewReader(round.UnsignedTx), true)
		if err != nil {
			log.Debugf("failed to parse round tx: %s", round.UnsignedTx)
			changes = round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
			log.WithError(err).Warn("failed to parse round tx")
			return
		}
		txToSign = round.UnsignedTx

		forfeitTxList, err := s.forfeitTxs.pop()
		if err != nil {
			changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
			log.WithError(err).Warn("failed to finalize round")
			return
		}

		if err := s.verifyForfeitTxsSigs(forfeitTxList); err != nil {
			changes = round.Fail(err)
			log.WithError(err).Warn("failed to validate forfeit txs")
			return
		}

		boardingInputsIndexes := make([]int, 0)
		for i, in := range roundTx.Inputs {
			if len(in.TaprootLeafScript) > 0 {
				if len(in.TaprootScriptSpendSig) == 0 {
					err = fmt.Errorf("missing tapscript spend sig for input %d", i)
					changes = round.Fail(err)
					log.WithError(err).Warn("missing boarding sig")
					return
				}

				boardingInputsIndexes = append(boardingInputsIndexes, i)
				boardingInputs = append(boardingInputs, domain.VtxoKey{
					Txid: roundTx.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
					VOut: roundTx.UnsignedTx.TxIn[i].PreviousOutPoint.Index,
				})
			}
		}

		if len(boardingInputsIndexes) > 0 {
			txToSign, err = s.wallet.SignTransactionTapscript(ctx, txToSign, boardingInputsIndexes)
			if err != nil {
				changes = round.Fail(fmt.Errorf("failed to sign round tx: %s", err))
				log.WithError(err).Warn("failed to sign round tx")
				return
			}
		}

		for _, tx := range forfeitTxList {
			// nolint:all
			ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
			forfeitTxid := ptx.UnsignedTx.TxHash().String()
			forfeitTxs = append(forfeitTxs, domain.ForfeitTx{
				Txid: forfeitTxid,
				Tx:   tx,
			})
		}
	}

	log.Debugf("signing transaction %s\n", round.Id)

	signedRoundTx, err := s.wallet.SignTransaction(ctx, txToSign, true)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to sign round tx: %s", err))
		log.WithError(err).Warn("failed to sign round tx")
		return
	}

	txid, err := s.wallet.BroadcastTransaction(ctx, signedRoundTx)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to broadcast round tx: %s", err))
		return
	}

	changes, err = round.EndFinalization(forfeitTxs, txid)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	// mark the notes as spent
	for _, note := range notes {
		if err := s.repoManager.Notes().Add(ctx, note.ID); err != nil {
			log.WithError(err).Warn("failed to mark note as spent")
		}
	}

	recoveredVtxosKeys := make([]domain.VtxoKey, 0)
	for _, vtxo := range recoveredVtxos {
		recoveredVtxosKeys = append(recoveredVtxosKeys, vtxo.VtxoKey)
	}

	// mark the recovered vtxos as spent
	if err := s.repoManager.Vtxos().SpendVtxos(ctx, recoveredVtxosKeys, round.Txid); err != nil {
		log.WithError(err).Warn("failed to mark recovered vtxos as spent")
	}

	go func() {
		spentVtxos := append(s.getSpentVtxos(round.TxRequests), recoveredVtxos...)
		for i := range spentVtxos {
			spentVtxos[i].Spent = true
			spentVtxos[i].SpentBy = round.Txid
		}
		event := RoundTransactionEvent{
			RoundTxid:             round.Txid,
			SpentVtxos:            spentVtxos,
			SpendableVtxos:        s.getNewVtxos(round),
			ClaimedBoardingInputs: boardingInputs,
			TxHex:                 signedRoundTx,
		}
		s.transactionEventsCh <- event
		s.indexerTxEventsCh <- event
	}()

	log.Debugf("finalized round %s with round tx %s", round.Id, round.Txid)
}

func (s *covenantlessService) listenToScannerNotifications() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic in listenToScannerNotifications: %v", r)
		}
	}()

	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)

	mutx := &sync.Mutex{}
	for vtxoKeys := range chVtxos {
		go func(vtxoKeys map[string][]ports.VtxoWithValue) {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("recovered from panic in GetVtxos: %v", r)
				}
			}()

			for _, keys := range vtxoKeys {
				for _, v := range keys {
					vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{v.VtxoKey})
					if err != nil {
						log.WithError(err).Warn("failed to retrieve vtxos, skipping...")
						return
					}
					vtxo := vtxos[0]

					if !vtxo.Redeemed {
						go func() {
							defer func() {
								if r := recover(); r != nil {
									log.Errorf("recovered from panic in markAsRedeemed: %v", r)
								}
							}()

							if err := s.markAsRedeemed(ctx, vtxo); err != nil {
								log.WithError(err).Warnf("failed to mark vtxo %s:%d as redeemed", vtxo.Txid, vtxo.VOut)
							}
						}()
					}

					if vtxo.Spent {
						log.Infof("fraud detected on vtxo %s:%d", vtxo.Txid, vtxo.VOut)
						go func() {
							defer func() {
								if r := recover(); r != nil {
									log.Errorf("recovered from panic in reactToFraud: %v", r)
									// log the stack trace
									log.Errorf("stack trace: %s", string(debug.Stack()))
								}
							}()

							if err := s.reactToFraud(ctx, vtxo, mutx); err != nil {
								log.WithError(err).Warnf("failed to prevent fraud for vtxo %s:%d", vtxo.Txid, vtxo.VOut)
							}
						}()
					}
				}
			}
		}(vtxoKeys)
	}
}

func (s *covenantlessService) updateVtxoSet(round *domain.Round) {
	// Update the vtxo set only after a round is finalized.
	if !round.IsEnded() {
		return
	}

	ctx := context.Background()
	repo := s.repoManager.Vtxos()
	spentVtxos := getSpentVtxos(round.TxRequests)
	if len(spentVtxos) > 0 {
		for {
			if err := repo.SpendVtxos(ctx, spentVtxos, round.Txid); err != nil {
				log.WithError(err).Warn("failed to add new vtxos, retrying soon")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Debugf("spent %d vtxos", len(spentVtxos))
			break
		}
	}

	newVtxos := s.getNewVtxos(round)
	if len(newVtxos) > 0 {
		for {
			if err := repo.AddVtxos(ctx, newVtxos); err != nil {
				log.WithError(err).Warn("failed to add new vtxos, retrying soon")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Debugf("added %d new vtxos", len(newVtxos))
			break
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("recovered from panic in startWatchingVtxos: %v", r)
				}
			}()

			for {
				if err := s.startWatchingVtxos(newVtxos); err != nil {
					log.WithError(err).Warn(
						"failed to start watching vtxos, retrying in a moment...",
					)
					continue
				}
				log.Debugf("started watching %d vtxos", len(newVtxos))
				return
			}
		}()

	}
}

func (s *covenantlessService) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	switch e := lastEvent.(type) {
	case domain.RoundFinalizationStarted:
		ev := domain.RoundFinalizationStarted{
			Id:               e.Id,
			VtxoTree:         e.VtxoTree,
			Connectors:       e.Connectors,
			RoundTx:          e.RoundTx,
			MinRelayFeeRate:  int64(s.wallet.MinRelayFeeRate(context.Background())),
			ConnectorAddress: e.ConnectorAddress,
			ConnectorsIndex:  e.ConnectorsIndex,
		}
		s.eventsCh <- ev
	case domain.RoundFinalized, domain.RoundFailed:
		s.eventsCh <- e
	}
}

func (s *covenantlessService) scheduleSweepVtxosForRound(round *domain.Round) {
	// Schedule the sweeping procedure only for completed round.
	if !round.IsEnded() {
		return
	}

	expirationTimestamp := s.sweeper.scheduler.AddNow(int64(s.vtxoTreeExpiry.Value))

	if err := s.sweeper.schedule(expirationTimestamp, round.Txid, round.VtxoTree); err != nil {
		log.WithError(err).Warn("failed to schedule sweep tx")
	}
}

func (s *covenantlessService) getNewVtxos(round *domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	now := time.Now()
	createdAt := now.Unix()
	expireAt := now.Add(time.Duration(s.vtxoTreeExpiry.Seconds()) * time.Second).Unix()

	leaves := round.VtxoTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				log.WithError(err).Warn("failed to parse vtxo tap key")
				continue
			}

			vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))
			vtxos = append(vtxos, domain.Vtxo{
				VtxoKey:   domain.VtxoKey{Txid: node.Txid, VOut: uint32(i)},
				PubKey:    vtxoPubkey,
				Amount:    uint64(out.Value),
				RoundTxid: round.Txid,
				CreatedAt: createdAt,
				ExpireAt:  expireAt,
			})
		}
	}
	return vtxos
}

func (s *covenantlessService) getSpentVtxos(requests map[string]domain.TxRequest) []domain.Vtxo {
	outpoints := getSpentVtxos(requests)
	vtxos, _ := s.repoManager.Vtxos().GetVtxos(context.Background(), outpoints)
	return vtxos
}

func (s *covenantlessService) startWatchingVtxos(vtxos []domain.Vtxo) error {
	scripts, err := s.extractVtxosScripts(vtxos)
	if err != nil {
		return err
	}

	return s.scanner.WatchScripts(context.Background(), scripts)
}

func (s *covenantlessService) stopWatchingVtxos(vtxos []domain.Vtxo) {
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

func (s *covenantlessService) restoreWatchingVtxos() error {
	ctx := context.Background()

	expiredRounds, err := s.repoManager.Rounds().GetExpiredRoundsTxid(ctx)
	if err != nil {
		return err
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, txid := range expiredRounds {
		fromRound, err := s.repoManager.Vtxos().GetVtxosForRound(ctx, txid)
		if err != nil {
			log.WithError(err).Warnf("failed to retrieve vtxos for round %s", txid)
			continue
		}
		for _, v := range fromRound {
			if !v.Swept && !v.Redeemed {
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

func (s *covenantlessService) extractVtxosScripts(vtxos []domain.Vtxo) ([]string, error) {
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

		script, err := common.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		indexedScripts[hex.EncodeToString(script)] = struct{}{}
	}
	scripts := make([]string, 0, len(indexedScripts))
	for script := range indexedScripts {
		scripts = append(scripts, script)
	}
	return scripts, nil
}

func (s *covenantlessService) saveEvents(
	ctx context.Context, id string, events []domain.RoundEvent,
) error {
	if len(events) <= 0 {
		return nil
	}
	round, err := s.repoManager.Events().Save(ctx, id, events...)
	if err != nil {
		return err
	}
	return s.repoManager.Rounds().AddOrUpdateRound(ctx, *round)
}

func (s *covenantlessService) chainParams() *chaincfg.Params {
	switch s.network.Name {
	case common.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return nil
	}
}

func (s *covenantlessService) reactToFraud(ctx context.Context, vtxo domain.Vtxo, mutx *sync.Mutex) error {
	mutx.Lock()
	defer mutx.Unlock()
	roundRepo := s.repoManager.Rounds()

	round, err := roundRepo.GetRoundWithTxid(ctx, vtxo.SpentBy)
	if err != nil {
		vtxosRepo := s.repoManager.Vtxos()

		// If the round is not found, the utxo may be spent by an out of round tx
		vtxos, err := vtxosRepo.GetVtxos(ctx, []domain.VtxoKey{
			{Txid: vtxo.SpentBy, VOut: 0},
		})
		if err != nil || len(vtxos) <= 0 {
			return fmt.Errorf("failed to retrieve round: %s", err)
		}

		storedVtxo := vtxos[0]
		if storedVtxo.Redeemed { // redeem tx is already onchain
			return nil
		}

		log.Debugf("vtxo %s:%d has been spent by out of round transaction", vtxo.Txid, vtxo.VOut)

		redeemTxHex, err := s.builder.FinalizeAndExtract(storedVtxo.RedeemTx)
		if err != nil {
			return fmt.Errorf("failed to finalize redeem tx: %s", err)
		}

		redeemTxid, err := s.wallet.BroadcastTransaction(ctx, redeemTxHex)
		if err != nil {
			return fmt.Errorf("failed to broadcast redeem tx: %s", err)
		}

		log.Debugf("broadcasted redeem tx %s", redeemTxid)
		return nil
	}

	// Find the forfeit tx of the VTXO
	forfeitTx, err := findForfeitTxBitcoin(round.ForfeitTxs, vtxo.VtxoKey)
	if err != nil {
		return fmt.Errorf("failed to find forfeit tx: %s", err)
	}

	if len(forfeitTx.UnsignedTx.TxIn) <= 0 {
		return fmt.Errorf("invalid forfeit tx: %s", forfeitTx.UnsignedTx.TxHash().String())
	}

	connector := forfeitTx.UnsignedTx.TxIn[0]
	connectorOutpoint := txOutpoint{
		connector.PreviousOutPoint.Hash.String(),
		connector.PreviousOutPoint.Index,
	}

	// compute, sign and broadcast the branch txs until the connector outpoint is created
	branch, err := round.Connectors.Branch(connectorOutpoint.txid)
	if err != nil {
		return fmt.Errorf("failed to get branch of connector: %s", err)
	}

	for _, node := range branch {
		_, err := s.wallet.GetTransaction(ctx, node.Txid)
		// if err, it means the tx is offchain
		if err != nil {
			signedTx, err := s.wallet.SignTransaction(ctx, node.Tx, true)
			if err != nil {
				return fmt.Errorf("failed to sign tx: %s", err)
			}

			txid, err := s.wallet.BroadcastTransaction(ctx, signedTx)
			if err != nil {
				return fmt.Errorf("failed to broadcast transaction: %s", err)
			}
			log.Debugf("broadcasted transaction %s", txid)
		}
	}

	if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{connectorOutpoint}); err != nil {
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

	forfeitTxid, err := s.wallet.BroadcastTransaction(ctx, forfeitTxHex)
	if err != nil {
		return fmt.Errorf("failed to broadcast forfeit tx: %s", err)
	}

	log.Debugf("broadcasted forfeit tx %s", forfeitTxid)
	return nil
}

func (s *covenantlessService) markAsRedeemed(ctx context.Context, vtxo domain.Vtxo) error {
	if err := s.repoManager.Vtxos().RedeemVtxos(ctx, []domain.VtxoKey{vtxo.VtxoKey}); err != nil {
		return err
	}

	log.Debugf("vtxo %s:%d redeemed", vtxo.Txid, vtxo.VOut)
	return nil
}

func (s *covenantlessService) verifyForfeitTxsSigs(txs []string) error {
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

func findForfeitTxBitcoin(
	forfeits []domain.ForfeitTx, vtxo domain.VtxoKey,
) (*psbt.Packet, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit.Tx), true)
		if err != nil {
			return nil, err
		}

		vtxoInput := forfeitTx.UnsignedTx.TxIn[1]

		if vtxoInput.PreviousOutPoint.Hash.String() == vtxo.Txid &&
			vtxoInput.PreviousOutPoint.Index == vtxo.VOut {
			return forfeitTx, nil
		}
	}

	return nil, fmt.Errorf("forfeit tx not found")
}

// musigSigningSession holds the state of ephemeral nonces and signatures in order to coordinate the signing of the tree
type musigSigningSession struct {
	lock        sync.Mutex
	nbCosigners int
	cosigners   map[string]struct{}
	nonces      map[*secp256k1.PublicKey]tree.TreeNonces
	nonceDoneC  chan struct{}

	signatures map[*secp256k1.PublicKey]tree.TreePartialSigs
	sigDoneC   chan struct{}
}

func newMusigSigningSession(cosigners map[string]struct{}) *musigSigningSession {
	return &musigSigningSession{
		nonces:     make(map[*secp256k1.PublicKey]tree.TreeNonces),
		nonceDoneC: make(chan struct{}),

		signatures:  make(map[*secp256k1.PublicKey]tree.TreePartialSigs),
		sigDoneC:    make(chan struct{}),
		lock:        sync.Mutex{},
		cosigners:   cosigners,
		nbCosigners: len(cosigners) + 1, // the server
	}
}

func (s *covenantlessService) GetMarketHourConfig(ctx context.Context) (*domain.MarketHour, error) {
	return s.repoManager.MarketHourRepo().Get(ctx)
}

func (s *covenantlessService) UpdateMarketHourConfig(
	ctx context.Context,
	marketHourStartTime, marketHourEndTime time.Time, period, roundInterval time.Duration,
) error {
	marketHour := domain.NewMarketHour(
		marketHourStartTime,
		marketHourEndTime,
		period,
		roundInterval,
	)
	if err := s.repoManager.MarketHourRepo().Upsert(ctx, *marketHour); err != nil {
		return fmt.Errorf("failed to upsert market hours: %w", err)
	}

	return nil
}
