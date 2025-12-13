package arksdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/redemption"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	log "github.com/sirupsen/logrus"
)

var ErrWaitingForConfirmation = fmt.Errorf("waiting for confirmation(s), please retry later")

func NewArkClient(sdkStore types.Store, opts ...ClientOption) (ArkClient, error) {
	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	if cfgData != nil {
		return nil, ErrAlreadyInitialized
	}

	client := &arkClient{
		store:                  sdkStore,
		syncMu:                 &sync.Mutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(client)
	}

	syncListeners := newReadyListeners()

	client.syncListeners = syncListeners

	return client, nil
}

func LoadArkClient(sdkStore types.Store, opts ...ClientOption) (ArkClient, error) {
	if sdkStore == nil {
		return nil, fmt.Errorf("missing sdk repository")
	}

	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData == nil {
		return nil, ErrNotInitialized
	}

	clientSvc, err := getClient(
		supportedClients, cfgData.ClientType, cfgData.ServerUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerOpts := []mempool_explorer.Option{
		mempool_explorer.WithTracker(cfgData.WithTransactionFeed),
	}
	if cfgData.ExplorerTrackingPollInterval > 0 {
		explorerOpts = append(
			explorerOpts, mempool_explorer.WithPollInterval(cfgData.ExplorerTrackingPollInterval),
		)
	}

	explorerSvc, err := mempool_explorer.NewExplorer(
		cfgData.ExplorerURL, cfgData.Network, explorerOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(cfgData.ClientType, cfgData.ServerUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	walletSvc, err := getWallet(sdkStore.ConfigStore(), cfgData, supportedWallets)
	if err != nil {
		return nil, fmt.Errorf("failed to setup wallet: %s", err)
	}

	syncListeners := newReadyListeners()

	client := &arkClient{
		Config:                 cfgData,
		wallet:                 walletSvc,
		store:                  sdkStore,
		explorer:               explorerSvc,
		client:                 clientSvc,
		indexer:                indexerSvc,
		syncListeners:          syncListeners,
		syncMu:                 &sync.Mutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

func LoadArkClientWithWallet(
	sdkStore types.Store, walletSvc wallet.WalletService, opts ...ClientOption,
) (ArkClient, error) {
	if sdkStore == nil {
		return nil, fmt.Errorf("missin sdk repository")
	}

	if walletSvc == nil {
		return nil, fmt.Errorf("missin wallet service")
	}

	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData == nil {
		return nil, ErrNotInitialized
	}

	clientSvc, err := getClient(
		supportedClients, cfgData.ClientType, cfgData.ServerUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerOpts := []mempool_explorer.Option{
		mempool_explorer.WithTracker(cfgData.WithTransactionFeed),
	}
	if cfgData.ExplorerTrackingPollInterval > 0 {
		explorerOpts = append(
			explorerOpts, mempool_explorer.WithPollInterval(cfgData.ExplorerTrackingPollInterval),
		)
	}

	explorerSvc, err := mempool_explorer.NewExplorer(
		cfgData.ExplorerURL, cfgData.Network, explorerOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(cfgData.ClientType, cfgData.ServerUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	client := &arkClient{
		Config:                 cfgData,
		wallet:                 walletSvc,
		store:                  sdkStore,
		explorer:               explorerSvc,
		client:                 clientSvc,
		indexer:                indexerSvc,
		syncMu:                 &sync.Mutex{},
		withFinalizePendingTxs: true,
	}
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

func (a *arkClient) Init(ctx context.Context, args InitArgs) error {
	return a.init(ctx, args)
}

func (a *arkClient) InitWithWallet(ctx context.Context, args InitWithWalletArgs) error {
	return a.initWithWallet(ctx, args)
}

func (a *arkClient) Balance(ctx context.Context) (*Balance, error) {
	if a.WithTransactionFeed {
		if err := a.safeCheck(); err != nil {
			return nil, err
		}
		return a.getBalanceFromStore(ctx)
	}

	return a.getBalanceFromExplorer(ctx)
}

func (a *arkClient) OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if a.UtxoMaxAmount == 0 {
		return "", fmt.Errorf("operation not allowed by the server")
	}

	_, _, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	return a.sendExpiredBoardingUtxos(ctx, boardingAddr.Address)
}

func (a *arkClient) WithdrawFromAllExpiredBoardings(
	ctx context.Context, to string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if _, err := btcutil.DecodeAddress(to, nil); err != nil {
		return "", fmt.Errorf("invalid receiver address '%s': must be onchain", to)
	}

	return a.sendExpiredBoardingUtxos(ctx, to)
}

func (a *arkClient) SendOffChain(
	ctx context.Context, receivers []types.Receiver, opts ...Option,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if len(receivers) <= 0 {
		return "", fmt.Errorf("missing receivers")
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	expectedSignerPubkey := schnorr.SerializePubKey(a.SignerPubKey)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", fmt.Errorf("all receiver addresses must be offchain addresses")
		}

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvSignerPubkey := schnorr.SerializePubKey(addr.Signer)
		if !bytes.Equal(expectedSignerPubkey, rcvSignerPubkey) {
			return "", fmt.Errorf(
				"invalid receiver address '%s': expected signer pubkey %x, got %x",
				receiver.To, expectedSignerPubkey, rcvSignerPubkey,
			)
		}

		sumOfReceivers += receiver.Amount
	}

	options := newDefaultSendOffChainOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	vtxos := make([]client.TapscriptsVtxo, 0)
	spendableVtxos, err := a.getVtxos(ctx, &CoinSelectOptions{
		WithoutExpirySorting: options.withoutExpirySorting,
	})
	if err != nil {
		return "", err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			if v.IsRecoverable() {
				continue
			}

			vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
			if err != nil {
				return "", err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.TapscriptsVtxo{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
			}
		}
	}

	// do not include boarding utxos
	_, selectedCoins, changeAmount, err := utils.CoinSelect(
		nil, vtxos, sumOfReceivers, a.Dust, options.withoutExpirySorting,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		receivers = append(receivers, types.Receiver{
			To: offchainAddrs[0].Address, Amount: changeAmount,
		})
	}

	inputs := make([]arkTxInput, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		vtxoScript, err := script.ParseVtxoScript(coin.Tapscripts)
		if err != nil {
			return "", err
		}

		forfeitClosure := vtxoScript.ForfeitClosures()[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return "", err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)

		inputs = append(inputs, arkTxInput{
			coin,
			forfeitLeaf.TapHash(),
		})
	}

	arkTx, checkpointTxs, err := buildOffchainTx(inputs, receivers, a.CheckpointExitPath(), a.Dust)
	if err != nil {
		return "", err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx)
	if err != nil {
		return "", err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return "", err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return "", err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return "", err
	}

	txid, err := a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
	if err != nil {
		return "", err
	}

	if !a.WithTransactionFeed {
		return txid, nil
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex

	spentVtxos := make([]types.Vtxo, 0, len(selectedCoins))
	spentAmount := uint64(0)
	commitmentTxids := make(map[string]struct{}, 0)
	smallestExpiration := time.Time{}
	for i, vtxo := range selectedCoins {
		if len(signedCheckpointTxs) <= i {
			log.Warnf("missing signed checkpoint tx, skipping marking vtxo as spent")
			return arkTxid, nil
		}

		checkpointTx, err := psbt.NewFromRawBytes(strings.NewReader(signedCheckpointTxs[i]), true)
		if err != nil {
			log.Warnf("failed to parse checkpoint tx: %s, skipping marking vtxo as spent", err)
			return arkTxid, nil
		}

		vtxo.Spent = true
		vtxo.ArkTxid = arkTxid
		vtxo.SpentBy = checkpointTx.UnsignedTx.TxID()
		spentVtxos = append(spentVtxos, vtxo.Vtxo)
		spentAmount += vtxo.Amount
		for _, commitmentTxid := range vtxo.CommitmentTxids {
			commitmentTxids[commitmentTxid] = struct{}{}
		}

		if vtxo.ExpiresAt.IsZero() {
			continue
		}

		if smallestExpiration.IsZero() {
			smallestExpiration = vtxo.ExpiresAt
			continue
		}

		if smallestExpiration.After(vtxo.ExpiresAt) {
			smallestExpiration = vtxo.ExpiresAt
		}
	}

	if smallestExpiration.IsZero() {
		log.Warnf("no expiration time found, skipping adding change vtxo")
		return arkTxid, nil
	}

	if _, err := a.store.VtxoStore().UpdateVtxos(ctx, spentVtxos); err != nil {
		log.Warnf("failed to update vtxos: %s, skipping marking vtxo as spent", err)
		return arkTxid, nil
	}

	log.Debugf("marked %d vtxos as spent", len(spentVtxos))

	createdAt := time.Now()

	if changeAmount > 0 {
		// subtract the change amount from the spent amount
		spentAmount -= changeAmount

		changeAddr, err := arklib.DecodeAddressV0(offchainAddrs[0].Address)
		if err != nil {
			return "", err
		}

		var changeScript []byte
		if changeAmount < a.Dust {
			changeScript, err = script.SubDustScript(changeAddr.VtxoTapKey)
		} else {
			changeScript, err = script.P2TRScript(changeAddr.VtxoTapKey)
		}
		if err != nil {
			return "", err
		}

		commitmentTxidsList := make([]string, 0, len(commitmentTxids))
		for commitmentTxid := range commitmentTxids {
			commitmentTxidsList = append(commitmentTxidsList, commitmentTxid)
		}

		// save change vtxo to DB
		if _, err := a.store.VtxoStore().AddVtxos(ctx, []types.Vtxo{
			{
				Outpoint: types.Outpoint{
					Txid: arkTxid,
					VOut: uint32(len(receivers) - 1),
				},
				Amount:          changeAmount,
				Unrolled:        false,
				Spent:           false,
				Swept:           changeAmount < a.Dust, // make it recoverable if change is sub-dust
				Preconfirmed:    true,
				CreatedAt:       createdAt,
				ExpiresAt:       smallestExpiration,
				Script:          hex.EncodeToString(changeScript),
				CommitmentTxids: commitmentTxidsList,
			},
		}); err != nil {
			log.Warnf("failed to add change vtxo: %s, skipping adding change vtxo", err)
			return arkTxid, nil
		}
	}

	// save sent transaction to DB
	if _, err := a.store.TransactionStore().AddTransactions(ctx, []types.Transaction{
		{
			TransactionKey: types.TransactionKey{
				ArkTxid: arkTxid,
			},
			Amount:    spentAmount,
			Type:      types.TxSent,
			CreatedAt: createdAt,
			Hex:       arkTx,
		},
	}); err != nil {
		log.Warnf("failed to add transactions: %s, skipping adding sent transaction", err)
		return arkTxid, nil
	}

	return arkTxid, nil
}

func (a *arkClient) RedeemNotes(
	ctx context.Context, notes []string, opts ...Option,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	amount := uint64(0)

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}

	for _, vStr := range notes {
		v, err := note.NewNoteFromString(vStr)
		if err != nil {
			return "", err
		}
		amount += uint64(v.Value)
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}
	if len(offchainAddrs) <= 0 {
		return "", fmt.Errorf("no funds detected")
	}

	receiversOutput := []types.Receiver{{
		To:     offchainAddrs[0].Address,
		Amount: amount,
	}}

	return a.joinBatchWithRetry(ctx, notes, receiversOutput, *options, nil, nil)
}

func (a *arkClient) Unroll(ctx context.Context) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	vtxos, err := a.getVtxos(ctx, nil)
	if err != nil {
		return err
	}

	if len(vtxos) == 0 {
		return fmt.Errorf("no vtxos to unroll")
	}

	totalVtxosAmount := uint64(0)
	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.Amount
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	redeemBranches, err := a.getRedeemBranches(ctx, vtxos)
	if err != nil {
		return err
	}

	isWaitingForConfirmation := false

	for _, branch := range redeemBranches {
		nextTx, err := branch.NextRedeemTx()
		if err != nil {
			if err, ok := err.(redemption.ErrPendingConfirmation); ok {
				// the branch tx is in the mempool, we must wait for confirmation
				// print only, do not make the function to fail
				// continue to try other branches
				log.Debug(err.Error())
				isWaitingForConfirmation = true
				continue
			}

			return err
		}

		if _, ok := transactionsMap[nextTx]; !ok {
			transactions = append(transactions, nextTx)
			transactionsMap[nextTx] = struct{}{}
		}
	}

	if len(transactions) == 0 {
		if isWaitingForConfirmation {
			return ErrWaitingForConfirmation
		}

		return nil
	}

	for _, parent := range transactions {
		var parentTx wire.MsgTx
		if err := parentTx.Deserialize(hex.NewDecoder(strings.NewReader(parent))); err != nil {
			return err
		}

		child, err := a.bumpAnchorTx(ctx, &parentTx)
		if err != nil {
			return err
		}

		// broadcast the package (parent + child)
		packageResponse, err := a.explorer.Broadcast(parent, child)
		if err != nil {
			return err
		}

		if a.WithTransactionFeed {
			parentTxid := parentTx.TxID()
			vtxosToUpdate := make([]types.Vtxo, 0, len(vtxos))
			for _, vtxo := range vtxos {
				if vtxo.Txid == parentTxid {
					vtxo.Unrolled = true
					vtxosToUpdate = append(vtxosToUpdate, vtxo)
				}
			}
			count, err := a.store.VtxoStore().UpdateVtxos(ctx, vtxosToUpdate)
			if err != nil {
				return fmt.Errorf("failed to update vtxos: %w", err)
			}
			if count > 0 {
				log.Debugf("marked %d vtxos as unrolled", count)
			}
		}

		log.Debugf("package broadcasted: %s", packageResponse)
	}

	return nil
}

func (a *arkClient) CompleteUnroll(
	ctx context.Context, to string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if len(to) == 0 {
		newAddr, _, _, err := a.wallet.NewAddress(ctx, false)
		if err != nil {
			return "", err
		}

		to = newAddr
	} else if _, err := btcutil.DecodeAddress(to, nil); err != nil {
		return "", fmt.Errorf("invalid receiver address '%s': must be onchain", to)
	}

	return a.completeUnilateralExit(ctx, to)
}

func (a *arkClient) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, opts ...Option,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	info, err := a.client.GetInfo(ctx)
	if err != nil {
		return "", err
	}

	// only 1 output
	fees := info.Fees.IntentFees.OnchainOutput

	if a.UtxoMaxAmount == 0 {
		return "", fmt.Errorf("operation not allowed by the server")
	}

	options := newDefaultSettleOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}
	if options.expiryThreshold <= 0 {
		options.expiryThreshold = defaultExpiryThreshold
	}

	netParams := utils.ToBitcoinNetwork(a.Network)
	if _, err := btcutil.DecodeAddress(addr, &netParams); err != nil {
		return "", fmt.Errorf("invalid onchain address")
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	getVtxosOpts := &CoinSelectOptions{
		WithRecoverableVtxos: options.withRecoverableVtxos,
	}
	spendableVtxos, err := a.getVtxos(ctx, getVtxosOpts)
	if err != nil {
		return "", err
	}
	balance := uint64(0)
	for _, vtxo := range spendableVtxos {
		balance += vtxo.Amount
	}
	if balance < amount {
		return "", fmt.Errorf("not enough funds to cover amount %d", amount)
	}
	// send all case: substract fees from exited amount
	if amount == balance {
		amount -= fees
	}

	boardingUtxos, vtxos, changeAmount, err := a.selectFunds(
		ctx, amount+fees, CoinSelectOptions{
			WithRecoverableVtxos: options.withRecoverableVtxos,
			ExpiryThreshold:      options.expiryThreshold,
		},
	)
	if err != nil {
		return "", err
	}

	receivers := []types.Receiver{{To: addr, Amount: amount}}

	if changeAmount > 0 {
		_, offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}

		receivers = append(receivers, types.Receiver{
			To:     offchainAddr.Address,
			Amount: changeAmount,
		})
	}

	return a.joinBatchWithRetry(ctx, nil, receivers, *options, vtxos, boardingUtxos)
}

func (a *arkClient) Settle(ctx context.Context, opts ...Option) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	return a.settle(ctx, nil, opts...)
}

func (a *arkClient) GetTransactionHistory(ctx context.Context) ([]types.Transaction, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	if a.WithTransactionFeed {
		history, err := a.store.TransactionStore().GetAllTransactions(ctx)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(history, func(i, j int) bool {
			return history[i].CreatedAt.IsZero() || history[i].CreatedAt.After(history[j].CreatedAt)
		})
		return history, nil
	}

	return a.fetchTxHistory(ctx)
}

func (a *arkClient) RegisterIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
	outputs []types.Receiver, cosignersPublicKeys []string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return "", err
	}

	inputs, tapLeaves, arkFields, err := toIntentInputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return "", err
	}

	proofTx, message, err := a.makeRegisterIntent(
		inputs, tapLeaves, outputs, cosignersPublicKeys, arkFields,
	)
	if err != nil {
		return "", err
	}

	return a.client.RegisterIntent(ctx, proofTx, message)
}

func (a *arkClient) DeleteIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return err
	}

	inputs, exitLeaves, arkFields, err := toIntentInputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return err
	}

	proofTx, message, err := a.makeDeleteIntent(inputs, exitLeaves, arkFields)
	if err != nil {
		return err
	}

	return a.client.DeleteIntent(ctx, proofTx, message)
}

func (a *arkClient) FinalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	return a.finalizePendingTxs(ctx, createdAfter)
}

func (a *arkClient) listenForArkTxs(ctx context.Context) {
	eventChan, closeFunc, err := a.client.GetTransactionsStream(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get transaction stream")
		return
	}
	defer closeFunc()

	log.Debugf("listening for ark txs")
	for {
		select {
		case <-ctx.Done():
			log.Debugf("stopping ark tx listener")
			return
		case event, ok := <-eventChan:
			if !ok {
				continue
			}
			if errors.Is(event.Err, io.EOF) {
				closeFunc()
				return
			}

			if event.Err != nil {
				log.WithError(event.Err).Warn("received error in transaction stream")
				continue
			}

			_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
			if err != nil {
				log.WithError(err).Error("failed to get offchain addresses")
				continue
			}

			myPubkeys := make(map[string]struct{})
			for _, addr := range offchainAddrs {
				// nolint
				decoded, _ := arklib.DecodeAddressV0(addr.Address)
				myPubkeys[hex.EncodeToString(schnorr.SerializePubKey(decoded.VtxoTapKey))] = struct{}{}
			}

			if event.CommitmentTx != nil {
				if err := a.handleCommitmentTx(ctx, myPubkeys, event.CommitmentTx); err != nil {
					log.WithError(err).Error("failed to process commitment tx")
					continue
				}
			}

			if event.ArkTx != nil {
				if err := a.handleArkTx(ctx, myPubkeys, event.ArkTx); err != nil {
					log.WithError(err).Error("failed to process ark tx")
					continue
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *arkClient) listenForOnchainTxs(ctx context.Context) {
	onchainAddrs, offchainAddrs, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get boarding addresses")
		return
	}

	addresses := make([]string, 0, len(boardingAddrs)+len(onchainAddrs)+len(offchainAddrs))
	type addressInfo struct {
		tapscripts []string
		delay      arklib.RelativeLocktime
	}
	addressByScript := make(map[string]addressInfo, 0)

	// we listen for boarding addresses to catch "boarding" events
	for _, addr := range boardingAddrs {
		addresses = append(addresses, addr.Address)

		script, err := toOutputScript(addr.Address, a.Network)
		if err != nil {
			log.WithError(err).Error("failed to get pk script for boarding address")
			continue
		}

		addressByScript[hex.EncodeToString(script)] = addressInfo{
			tapscripts: addr.Tapscripts,
			delay:      a.BoardingExitDelay, // TODO: ideally computed from tapscripts
		}
	}

	// we listen for classic P2TR addresses to catch onchain send/receive events
	for _, addr := range onchainAddrs {
		addresses = append(addresses, addr)

		script, err := toOutputScript(addr, a.Network)
		if err != nil {
			log.WithError(err).Error("failed to get pk script for onchain address")
			continue
		}

		addressByScript[hex.EncodeToString(script)] = addressInfo{
			tapscripts: []string{},                // no tapscripts for onchain address
			delay:      arklib.RelativeLocktime{}, // no delay for classic onchain address
		}
	}

	// we listen for offchain addresses to catch unrolling events
	for _, offchainAddr := range offchainAddrs {
		addr, err := toOnchainAddress(offchainAddr.Address, a.Network)
		if err != nil {
			log.WithError(err).Error("failed to get onchain address for offchain address")
			continue
		}

		addresses = append(addresses, addr)

		script, err := toOutputScript(addr, a.Network)
		if err != nil {
			log.WithError(err).Error("failed to get pk script for offchain address")
			continue
		}

		addressByScript[hex.EncodeToString(script)] = addressInfo{
			tapscripts: offchainAddr.Tapscripts,
			delay:      a.UnilateralExitDelay, // TODO: ideally computed from tapscripts
		}
	}

	if err := a.explorer.SubscribeForAddresses(addresses); err != nil {
		log.WithError(err).Error("failed to subscribe for onchain addresses")
		return
	}

	ch := a.explorer.GetAddressesEvents()

	log.Debugf("subscribed for %d addresses", len(addresses))
	for {
		select {
		case <-ctx.Done():
			log.Debug("stopping onchain transaction listener")
			if err := a.explorer.UnsubscribeForAddresses(addresses); err != nil {
				log.WithError(err).Error("failed to unsubscribe for onchain addresses")
			}
			return
		case update := <-ch:
			// TODO: we may want to forward this error so the user can try to reconnect.
			if update.Error != nil {
				log.WithError(update.Error).Error("received error from explorer")
				continue
			}
			txsToAdd := make([]types.Transaction, 0)
			txsToConfirm := make([]string, 0)
			utxosToConfirm := make(map[types.Outpoint]int64)
			utxosToSpend := make(map[types.Outpoint]string)
			if len(update.NewUtxos) > 0 {
				for _, u := range update.NewUtxos {
					txsToAdd = append(txsToAdd, types.Transaction{
						TransactionKey: types.TransactionKey{
							BoardingTxid: u.Txid,
						},
						Amount:    u.Amount,
						Type:      types.TxReceived,
						CreatedAt: u.CreatedAt,
					})
				}
			}
			if len(update.ConfirmedUtxos) > 0 {
				for _, u := range update.ConfirmedUtxos {
					txsToConfirm = append(txsToConfirm, u.Txid)
					utxosToConfirm[u.Outpoint] = u.CreatedAt.Unix()
				}
			}
			if len(update.SpentUtxos) > 0 {
				for _, u := range update.SpentUtxos {
					utxosToSpend[u.Outpoint] = u.SpentBy
				}
			}

			if len(txsToAdd) > 0 {
				a.dbMu.Lock()
				count, err := a.store.TransactionStore().AddTransactions(
					ctx, txsToAdd,
				)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("added %d boarding transaction(s)", count)
				}
			}

			if len(txsToConfirm) > 0 {
				a.dbMu.Lock()
				count, err := a.store.TransactionStore().ConfirmTransactions(
					ctx, txsToConfirm, time.Now(),
				)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to update boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("confirmed %d boarding transaction(s)", count)
				}
			}

			if len(update.Replacements) > 0 {
				a.dbMu.Lock()
				count, err := a.store.TransactionStore().RbfTransactions(ctx, update.Replacements)
				if err != nil {
					a.dbMu.Unlock()
					log.WithError(err).Error("failed to update rbf boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("replaced %d boarding transaction(s)", count)
				}

				for replacedTxid, replacementTxid := range update.Replacements {
					newTransaction, err := a.explorer.GetTxHex(replacementTxid)
					if err != nil {
						log.WithError(err).Error("failed to get boarding replacement transaction")
						continue
					}
					var tx wire.MsgTx
					if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(newTransaction))); err != nil {
						log.WithError(err).
							Error("failed to deserialize boarding replacement transaction")
						continue
					}

					utxoStore := a.store.UtxoStore()

					for outputIndex := range tx.TxOut {
						replacedUtxo := types.Outpoint{
							Txid: replacedTxid,
							VOut: uint32(outputIndex),
						}

						if utxos, err := utxoStore.GetUtxos(ctx, []types.Outpoint{replacedUtxo}); err == nil &&
							len(utxos) > 0 {
							if err := utxoStore.ReplaceUtxo(ctx, replacedUtxo, types.Outpoint{
								Txid: replacementTxid,
								VOut: uint32(outputIndex),
							}); err != nil {
								log.WithError(err).Error("failed to replace boarding utxo")
								continue
							}
						}
					}
				}
				a.dbMu.Unlock()
			}

			if len(update.NewUtxos) > 0 {
				utxosToAdd := make([]types.Utxo, 0, len(update.NewUtxos))
				for _, u := range update.NewUtxos {
					address, ok := addressByScript[u.Script]
					if !ok {
						log.WithField("script", u.Script).
							WithField("outpoint", u.Outpoint).
							Error("failed to find address for new utxo")
						continue
					}

					txHex, err := a.explorer.GetTxHex(u.Txid)
					if err != nil {
						log.WithField("txid", u.Txid).
							WithError(err).
							Error("failed to get boarding utxo transaction")
						continue
					}

					var spendableAt time.Time
					if !u.CreatedAt.IsZero() {
						spendableAt = u.CreatedAt.Add(
							time.Duration(address.delay.Seconds()) * time.Second,
						)
					}

					utxosToAdd = append(utxosToAdd, types.Utxo{
						Outpoint:    u.Outpoint,
						Amount:      u.Amount,
						Script:      u.Script,
						Delay:       address.delay,
						Spent:       false,
						SpentBy:     "",
						Tx:          txHex,
						Tapscripts:  address.tapscripts,
						CreatedAt:   u.CreatedAt,
						SpendableAt: spendableAt,
					})
				}

				a.dbMu.Lock()
				count, err := a.store.UtxoStore().AddUtxos(ctx, utxosToAdd)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding utxos")
					continue
				}
				if count > 0 {
					log.Debugf("added %d new boarding utxo(s)", count)
				}
			}

			if len(utxosToConfirm) > 0 {
				a.dbMu.Lock()
				count, err := a.store.UtxoStore().ConfirmUtxos(ctx, utxosToConfirm)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding utxos")
					continue
				}
				if count > 0 {
					log.Debugf("confirmed %d boarding utxo(s)", count)
				}
			}
			if len(utxosToSpend) > 0 {
				a.dbMu.Lock()
				count, err := a.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to mark boarding utxos as spent")
					continue
				}
				if count > 0 {
					log.Debugf("spent %d boarding utxo(s)", count)
				}
			}
		}
	}
}

func (a *arkClient) refreshDb(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	// Fetch new and spent vtxos.
	spendableVtxos, spentVtxos, err := a.listVtxosFromIndexer(ctx)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// Fetch new and spent utxos.
	allUtxos, err := a.getAllBoardingUtxos(ctx)
	if err != nil {
		return err
	}

	spendableUtxos := make([]types.Utxo, 0, len(allUtxos))
	spentUtxos := make([]types.Utxo, 0, len(allUtxos))
	commitmentTxsToIgnore := make(map[string]struct{})
	for _, utxo := range allUtxos {
		if utxo.Spent {
			spentUtxos = append(spentUtxos, utxo)
			commitmentTxsToIgnore[utxo.SpentBy] = struct{}{}
			continue
		}
		spendableUtxos = append(spendableUtxos, utxo)
	}

	// Rebuild tx history.
	unconfirmedTxs := make([]types.Transaction, 0)
	confirmedTxs := make([]types.Transaction, 0)
	for _, u := range allUtxos {
		tx := types.Transaction{
			TransactionKey: types.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      types.TxReceived,
			CreatedAt: u.CreatedAt,
			Settled:   u.Spent,
			SettledBy: u.SpentBy,
			Hex:       u.Tx,
		}

		if u.CreatedAt.IsZero() {
			unconfirmedTxs = append(unconfirmedTxs, tx)
			continue
		}
		confirmedTxs = append(confirmedTxs, tx)
	}

	onchainHistory := append(unconfirmedTxs, confirmedTxs...)

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	offchainHistory, err := a.vtxosToTxs(ctx, spendableVtxos, spentVtxos, commitmentTxsToIgnore)
	if err != nil {
		return err
	}

	history := append(onchainHistory, offchainHistory...)
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].CreatedAt.After(history[j].CreatedAt)
	})

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// TODO make DB queries transactional

	// TODO goroutines

	// Update tx history in db.
	if err := a.refreshTxDb(ctx, history); err != nil {
		return err
	}

	// Update utxos in db.
	if err := a.refreshUtxoDb(ctx, spendableUtxos, spentUtxos); err != nil {
		return err
	}

	// Update vtxos in db.
	return a.refreshVtxoDb(ctx, spendableVtxos, spentVtxos)
}

func (a *arkClient) refreshTxDb(ctx context.Context, newTxs []types.Transaction) error {
	// Fetch old data.
	oldTxs, err := a.store.TransactionStore().GetAllTransactions(ctx)
	if err != nil {
		return err
	}

	// Index the old data for quick lookups.
	oldTxsMap := make(map[string]types.Transaction, len(oldTxs))
	txsToUpdate := make(map[string]types.Transaction, 0)
	for _, tx := range oldTxs {
		if tx.CreatedAt.IsZero() || !tx.Settled {
			txsToUpdate[tx.TransactionKey.String()] = tx
		}
		oldTxsMap[tx.TransactionKey.String()] = tx
	}

	txsToAdd := make([]types.Transaction, 0, len(newTxs))
	txsToReplace := make([]types.Transaction, 0, len(newTxs))
	for _, tx := range newTxs {
		if _, ok := oldTxsMap[tx.TransactionKey.String()]; !ok {
			txsToAdd = append(txsToAdd, tx)
			continue
		}

		if _, ok := txsToUpdate[tx.TransactionKey.String()]; ok {
			txsToReplace = append(txsToReplace, tx)
		}
	}

	if len(txsToAdd) > 0 {
		count, err := a.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new transaction(s)", count)
		}
	}
	if len(txsToReplace) > 0 {
		count, err := a.store.TransactionStore().UpdateTransactions(ctx, txsToReplace)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("replaced %d transaction(s)", count)
		}
	}

	return nil
}

func (a *arkClient) refreshUtxoDb(
	ctx context.Context, spendableUtxos, spentUtxos []types.Utxo,
) error {
	// Fetch old data.
	oldSpendableUtxos, _, err := a.store.UtxoStore().GetAllUtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableUtxoMap := make(map[types.Outpoint]types.Utxo, 0)
	for _, u := range oldSpendableUtxos {
		oldSpendableUtxoMap[u.Outpoint] = u
	}

	utxosToAdd := make([]types.Utxo, 0, len(spendableUtxos))
	utxosToConfirm := make(map[types.Outpoint]int64)
	for _, utxo := range spendableUtxos {
		if _, ok := oldSpendableUtxoMap[utxo.Outpoint]; !ok {
			utxosToAdd = append(utxosToAdd, utxo)
		} else {
			var confirmedAt int64
			if !utxo.CreatedAt.IsZero() {
				confirmedAt = utxo.CreatedAt.Unix()
				utxosToConfirm[utxo.Outpoint] = confirmedAt
			}
		}
	}

	// Spent vtxos include swept and redeemed, let's make sure to update any vtxo that was
	// previously spendable.
	utxosToSpend := make(map[types.Outpoint]string)
	for _, utxo := range spentUtxos {
		if _, ok := oldSpendableUtxoMap[utxo.Outpoint]; ok {
			utxosToSpend[utxo.Outpoint] = utxo.SpentBy
		}
	}

	if len(utxosToAdd) > 0 {
		count, err := a.store.UtxoStore().AddUtxos(ctx, utxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new boarding utxo(s)", count)
		}
	}
	if len(utxosToConfirm) > 0 {
		count, err := a.store.UtxoStore().ConfirmUtxos(ctx, utxosToConfirm)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("confirmed %d boarding utxo(s)", count)
		}
	}
	if len(utxosToSpend) > 0 {
		count, err := a.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d boarding utxo(s)", count)
		}
	}

	return nil
}

func (a *arkClient) refreshVtxoDb(
	ctx context.Context, spendableVtxos, spentVtxos []types.Vtxo,
) error {
	// Fetch old data.
	oldSpendableVtxos, _, err := a.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableVtxoMap := make(map[types.Outpoint]types.Vtxo, 0)
	for _, v := range oldSpendableVtxos {
		oldSpendableVtxoMap[v.Outpoint] = v
	}

	vtxosToAdd := make([]types.Vtxo, 0, len(spendableVtxos))
	for _, vtxo := range spendableVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; !ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Spent vtxos include swept and redeemed, let's make sure to update any vtxo that was
	// previously spendable.
	vtxosToUpdate := make([]types.Vtxo, 0, len(spentVtxos))
	for _, vtxo := range spentVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; ok {
			vtxosToUpdate = append(vtxosToUpdate, vtxo)
		}
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new vtxo(s)", count)
		}
	}
	if len(vtxosToUpdate) > 0 {
		count, err := a.store.VtxoStore().UpdateVtxos(ctx, vtxosToUpdate)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("updated %d vtxo(s)", count)
		}
	}

	return nil
}

func (a *arkClient) getBalanceFromStore(ctx context.Context) (*Balance, error) {
	balance := &Balance{
		OnchainBalance: OnchainBalance{
			SpendableAmount: 0,
			LockedAmount:    make([]LockedOnchainBalance, 0),
		},
		OffchainBalance: OffchainBalance{
			Total:          0,
			NextExpiration: "",
			Details:        make([]VtxoDetails, 0),
		},
	}

	// offchain balance
	offchainBalance, amountByExpiration, err := a.getOffchainBalance(ctx)
	if err != nil {
		return nil, err
	}

	nextExpiration, details := getOffchainBalanceDetails(amountByExpiration)
	balance.OffchainBalance.Total = offchainBalance
	balance.OffchainBalance.NextExpiration = getFancyTimeExpiration(nextExpiration)
	balance.OffchainBalance.Details = details

	if a.UtxoMaxAmount == 0 {
		return balance, nil
	}

	// onchain balance
	utxoStore := a.store.UtxoStore()
	utxos, _, err := utxoStore.GetAllUtxos(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	for _, utxo := range utxos {
		if !utxo.IsConfirmed() {
			continue // TODO handle unconfirmed balance ? (not spendable on ark)
		}

		if now.After(utxo.SpendableAt) {
			balance.OnchainBalance.SpendableAmount += utxo.Amount
			continue
		}

		balance.OnchainBalance.LockedAmount = append(
			balance.OnchainBalance.LockedAmount,
			LockedOnchainBalance{
				SpendableAt: utxo.SpendableAt.Format(time.RFC3339),
				Amount:      utxo.Amount,
			},
		)
	}

	return balance, nil
}

func (a *arkClient) getBalanceFromExplorer(ctx context.Context) (*Balance, error) {
	if a.wallet == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	onchainAddrs, offchainAddrs, boardingAddrs, redeemAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	if a.UtxoMaxAmount == 0 {
		balance, amountByExpiration, err := a.getOffchainBalance(ctx)
		if err != nil {
			return nil, err
		}

		nextExpiration, details := getOffchainBalanceDetails(amountByExpiration)

		return &Balance{
			OffchainBalance: OffchainBalance{
				Total:          balance,
				NextExpiration: getFancyTimeExpiration(nextExpiration),
				Details:        details,
			},
		}, nil
	}

	const nbWorkers = 4
	wg := &sync.WaitGroup{}
	wg.Add(nbWorkers * len(offchainAddrs))

	chRes := make(chan balanceRes, nbWorkers*len(offchainAddrs))
	for i := range offchainAddrs {
		boardingAddr := boardingAddrs[i]
		redeemAddr := redeemAddrs[i]

		go func() {
			defer wg.Done()
			balance, amountByExpiration, err := a.getOffchainBalance(ctx)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}

			chRes <- balanceRes{
				offchainBalance:             balance,
				offchainBalanceByExpiration: amountByExpiration,
			}
		}()

		getDelayedBalance := func(addr string) {
			defer wg.Done()

			spendableBalance, lockedBalance, err := a.explorer.GetRedeemedVtxosBalance(
				addr, a.UnilateralExitDelay,
			)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}

			chRes <- balanceRes{
				onchainSpendableBalance: spendableBalance,
				onchainLockedBalance:    lockedBalance,
				err:                     err,
			}
		}

		go func() {
			defer wg.Done()
			totalOnchainBalance := uint64(0)
			for _, addr := range onchainAddrs {
				utxos, err := a.explorer.GetUtxos(addr)
				balance := uint64(0)
				for _, utxo := range utxos {
					balance += utxo.Amount
				}
				if err != nil {
					chRes <- balanceRes{err: err}
					return
				}
				totalOnchainBalance += balance
			}
			chRes <- balanceRes{onchainSpendableBalance: totalOnchainBalance}
		}()

		go getDelayedBalance(boardingAddr.Address)
		go getDelayedBalance(redeemAddr.Address)
	}

	wg.Wait()

	lockedOnchainBalance := []LockedOnchainBalance{}
	details := make([]VtxoDetails, 0)
	offchainBalance, onchainBalance := uint64(0), uint64(0)
	nextExpiration := int64(0)
	count := 0
	for res := range chRes {
		if res.err != nil {
			return nil, res.err
		}
		if res.offchainBalance > 0 {
			offchainBalance = res.offchainBalance
		}
		if res.onchainSpendableBalance > 0 {
			onchainBalance += res.onchainSpendableBalance
		}
		nextExpiration, details = getOffchainBalanceDetails(res.offchainBalanceByExpiration)

		if res.onchainLockedBalance != nil {
			for timestamp, amount := range res.onchainLockedBalance {
				fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
				lockedOnchainBalance = append(
					lockedOnchainBalance,
					LockedOnchainBalance{
						SpendableAt: fancyTime,
						Amount:      amount,
					},
				)
			}
		}

		count++
		if count == nbWorkers {
			break
		}
	}

	return &Balance{
		OnchainBalance: OnchainBalance{
			SpendableAmount: onchainBalance,
			LockedAmount:    lockedOnchainBalance,
		},
		OffchainBalance: OffchainBalance{
			Total:          offchainBalance,
			NextExpiration: getFancyTimeExpiration(nextExpiration),
			Details:        details,
		},
	}, nil
}

// bumpAnchorTx builds and signs a transaction bumping the fees for a given tx with P2A output.
// Makes use of the onchain P2TR account to select UTXOs to pay fees for parent.
func (a *arkClient) bumpAnchorTx(ctx context.Context, parent *wire.MsgTx) (string, error) {
	anchor, err := txutils.FindAnchorOutpoint(parent)
	if err != nil {
		return "", err
	}

	// estimate for the size of the bump transaction
	weightEstimator := input.TxWeightEstimator{}

	// WeightEstimator doesn't support P2A size, using P2WSH will lead to a small overestimation
	// TODO use the exact P2A size
	weightEstimator.AddNestedP2WSHInput(lntypes.VByte(3).ToWU())

	// We assume only one UTXO will be selected to have a correct estimation
	weightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault)
	weightEstimator.AddP2TROutput()

	childVSize := weightEstimator.Weight().ToVB()

	packageSize := childVSize + computeVSize(parent)
	feeRate, err := a.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}

	fees := uint64(math.Ceil(float64(packageSize) * feeRate))

	addresses, _, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	selectedCoins := make([]explorer.Utxo, 0)
	selectedAmount := uint64(0)
	amountToSelect := int64(fees) - txutils.ANCHOR_VALUE
	for _, addr := range addresses {
		utxos, err := a.explorer.GetUtxos(addr)
		if err != nil {
			return "", err
		}

		for _, utxo := range utxos {
			selectedCoins = append(selectedCoins, utxo)
			selectedAmount += utxo.Amount
			amountToSelect -= int64(selectedAmount)
			if amountToSelect <= 0 {
				break
			}
		}
	}

	if amountToSelect > 0 {
		return "", fmt.Errorf("not enough funds to select %d", amountToSelect)
	}

	changeAmount := selectedAmount - fees

	newAddr, _, _, err := a.wallet.NewAddress(ctx, true)
	if err != nil {
		return "", err
	}

	pkScript, err := toOutputScript(newAddr, a.Network)
	if err != nil {
		return "", err
	}

	inputs := []*wire.OutPoint{anchor}
	sequences := []uint32{
		wire.MaxTxInSequenceNum,
	}
	outputs := []*wire.TxOut{
		{
			Value:    int64(changeAmount),
			PkScript: pkScript,
		},
	}

	for _, utxo := range selectedCoins {
		txid, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return "", err
		}
		inputs = append(inputs, &wire.OutPoint{
			Hash:  *txid,
			Index: utxo.Vout,
		})
		sequences = append(sequences, wire.MaxTxInSequenceNum)
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

	tx, err := a.wallet.SignTransaction(ctx, a.explorer, b64)
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

func (a *arkClient) sendExpiredBoardingUtxos(ctx context.Context, to string) (string, error) {
	pkscript, err := toOutputScript(to, a.Network)
	if err != nil {
		return "", err
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	utxos, err := a.getExpiredBoardingUtxos(ctx, nil)
	if err != nil {
		return "", err
	}

	targetAmount := uint64(0)
	for _, u := range utxos {
		targetAmount += u.Amount
	}

	if targetAmount == 0 {
		return "", fmt.Errorf("no expired boarding funds available")
	}

	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    int64(targetAmount),
		PkScript: pkscript,
	})
	updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})

	if err := a.addInputs(ctx, updater, utxos); err != nil {
		return "", err
	}

	vbytes := computeVSize(updater.Upsbt.UnsignedTx)
	feeRate, err := a.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}
	feeAmount := uint64(math.Ceil(float64(vbytes)*feeRate) + 50)

	if targetAmount-feeAmount <= a.Dust {
		return "", fmt.Errorf("not enough funds to cover network fees")
	}

	updater.Upsbt.UnsignedTx.TxOut[0].Value -= int64(feeAmount)

	unsignedTx, _ := ptx.B64Encode()

	signedTx, err := a.wallet.SignTransaction(ctx, a.explorer, unsignedTx)
	if err != nil {
		return "", err
	}

	ptx, err = psbt.NewFromRawBytes(strings.NewReader(signedTx), true)
	if err != nil {
		return "", err
	}

	for i := range ptx.Inputs {
		if err := psbt.Finalize(ptx, i); err != nil {
			return "", err
		}
	}

	return ptx.B64Encode()
}

func (a *arkClient) completeUnilateralExit(ctx context.Context, to string) (string, error) {
	pkscript, err := toOutputScript(to, a.Network)
	if err != nil {
		return "", err
	}

	utxos, err := a.getMatureUtxos(ctx)
	if err != nil {
		return "", err
	}

	targetAmount := uint64(0)
	for _, u := range utxos {
		targetAmount += u.Amount
	}

	if targetAmount == 0 {
		return "", fmt.Errorf("no mature funds available")
	}

	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    int64(targetAmount),
		PkScript: pkscript,
	})
	updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})

	if err := a.addInputs(ctx, updater, utxos); err != nil {
		return "", err
	}

	vbytes := computeVSize(updater.Upsbt.UnsignedTx)
	feeRate, err := a.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}

	feeAmount := uint64(math.Ceil(float64(vbytes)*feeRate) + 100)

	if targetAmount-feeAmount <= a.Dust {
		return "", fmt.Errorf("not enough funds to cover network fees")
	}

	updater.Upsbt.UnsignedTx.TxOut[0].Value -= int64(feeAmount)

	unsignedTx, _ := ptx.B64Encode()

	signedTx, err := a.wallet.SignTransaction(ctx, a.explorer, unsignedTx)
	if err != nil {
		return "", err
	}

	ptx, err = psbt.NewFromRawBytes(strings.NewReader(signedTx), true)
	if err != nil {
		return "", err
	}

	for i := range ptx.Inputs {
		if err := psbt.Finalize(ptx, i); err != nil {
			return "", err
		}
	}

	tx, err := psbt.Extract(ptx)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	if err := tx.Serialize(buf); err != nil {
		return "", err
	}

	txHex := hex.EncodeToString(buf.Bytes())
	return a.explorer.Broadcast(txHex)
}

func (a *arkClient) selectFunds(
	ctx context.Context, amount uint64, opts CoinSelectOptions,
) ([]types.Utxo, []client.TapscriptsVtxo, uint64, error) {
	_, offchainAddrs, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, nil, 0, fmt.Errorf("no offchain addresses found")
	}

	vtxos := make([]client.TapscriptsVtxo, 0)
	spendableVtxos, err := a.getVtxos(ctx, &opts)
	if err != nil {
		return nil, nil, 0, err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
			if err != nil {
				return nil, nil, 0, err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.TapscriptsVtxo{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
			}
		}
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx, boardingAddrs, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	var selectedBoardingCoins []types.Utxo
	var selectedCoins []client.TapscriptsVtxo

	// if no receivers, self send all selected coins
	if amount <= 0 {
		selectedBoardingCoins = boardingUtxos
		selectedCoins = vtxos

		amount := uint64(0)
		for _, utxo := range boardingUtxos {
			amount += utxo.Amount
		}
		for _, utxo := range vtxos {
			amount += utxo.Amount
		}

		return selectedBoardingCoins, selectedCoins, 0, nil
	}

	return utils.CoinSelect(
		boardingUtxos, vtxos, amount, a.Dust, opts.WithoutExpirySorting,
	)
}

func (a *arkClient) settle(
	ctx context.Context, receivers []types.Receiver, settleOpts ...Option,
) (string, error) {
	options := newDefaultSettleOptions()
	for _, opt := range settleOpts {
		if err := opt(options); err != nil {
			return "", err
		}
	}
	if options.expiryThreshold <= 0 {
		options.expiryThreshold = defaultExpiryThreshold
	}

	expectedSignerPubkey := schnorr.SerializePubKey(a.SignerPubKey)
	outputs := make([]types.Receiver, 0)
	sumOfReceivers := uint64(0)

	// validate receivers and create outputs
	for _, receiver := range receivers {
		rcvAddr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvSignerPubkey := schnorr.SerializePubKey(rcvAddr.Signer)

		if !bytes.Equal(expectedSignerPubkey, rcvSignerPubkey) {
			return "", fmt.Errorf(
				"invalid receiver address '%s': expected signer pubkey %x, got %x",
				receiver.To, expectedSignerPubkey, rcvSignerPubkey,
			)
		}

		if receiver.Amount < a.Dust {
			return "", fmt.Errorf(
				"invalid amount (%d), must be greater than dust %d", receiver.Amount, a.Dust,
			)
		}

		outputs = append(outputs, types.Receiver{
			To:     receiver.To,
			Amount: receiver.Amount,
		})
		sumOfReceivers += receiver.Amount
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	// coinselect boarding utxos and vtxos
	boardingUtxos, vtxos, changeAmount, err := a.selectFunds(
		ctx, sumOfReceivers, CoinSelectOptions{
			WithRecoverableVtxos: options.withRecoverableVtxos,
			ExpiryThreshold:      options.expiryThreshold,
		},
	)
	if err != nil {
		return "", err
	}

	_, offchainAddr, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	// if no outputs, self send all selected coins
	if len(outputs) <= 0 {
		amount := uint64(0)
		for _, utxo := range boardingUtxos {
			amount += utxo.Amount
		}
		for _, utxo := range vtxos {
			amount += utxo.Amount
		}

		outputs = append(outputs, types.Receiver{
			To:     offchainAddr.Address,
			Amount: amount,
		})
	}

	// add change output if any
	if changeAmount > 0 {
		outputs = append(outputs, types.Receiver{
			To:     offchainAddr.Address,
			Amount: changeAmount,
		})
	}

	return a.joinBatchWithRetry(ctx, nil, outputs, *options, vtxos, boardingUtxos)
}

func (a *arkClient) makeRegisterIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof,
	outputs []types.Receiver, cosignersPublicKeys []string, arkFields [][]*psbt.Unknown,
) (string, string, error) {
	message, outputsTxOut, err := registerIntentMessage(outputs, cosignersPublicKeys)
	if err != nil {
		return "", "", err
	}

	return a.makeIntent(message, inputs, outputsTxOut, leafProofs, arkFields)
}

func (a *arkClient) makeGetPendingTxIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
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

	return a.makeIntent(message, inputs, nil, leafProofs, arkFields)
}

func (a *arkClient) makeDeleteIntent(
	inputs []intent.Input, leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
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

	return a.makeIntent(message, inputs, nil, leafProofs, arkFields)
}

func (a *arkClient) makeIntent(
	message string, inputs []intent.Input, outputsTxOut []*wire.TxOut,
	leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
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

	signedTx, err := a.wallet.SignTransaction(context.Background(), a.explorer, unsignedProofTx)
	if err != nil {
		return "", "", err
	}

	return signedTx, message, nil
}

func (a *arkClient) addInputs(
	ctx context.Context, updater *psbt.Updater, utxos []types.Utxo,
) error {
	// TODO works only with single-key wallet
	_, offchain, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return err
	}

	vtxoScript, err := script.ParseVtxoScript(offchain.Tapscripts)
	if err != nil {
		return err
	}

	for _, utxo := range utxos {
		previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return err
		}

		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *previousHash,
				Index: utxo.VOut,
			},
			Sequence: sequence,
		})

		exitClosures := vtxoScript.ExitClosures()
		if len(exitClosures) <= 0 {
			return fmt.Errorf("no exit closures found")
		}

		exitClosure := exitClosures[0]

		exitScript, err := exitClosure.Script()
		if err != nil {
			return err
		}

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return err
		}

		exitLeaf := txscript.NewBaseTapLeaf(exitScript)
		leafProof, err := taprootTree.GetTaprootMerkleProof(exitLeaf.TapHash())
		if err != nil {
			return fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{
			TaprootLeafScript: []*psbt.TaprootTapLeafScript{
				{
					ControlBlock: leafProof.ControlBlock,
					Script:       leafProof.Script,
					LeafVersion:  txscript.BaseLeafVersion,
				},
			},
		})
	}

	return nil
}

func (a *arkClient) populateVtxosWithTapscripts(
	ctx context.Context, vtxos []types.Vtxo,
) ([]client.TapscriptsVtxo, error) {
	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, fmt.Errorf("no offchain addresses found")
	}

	vtxosWithTapscripts := make([]client.TapscriptsVtxo, 0)

	for _, v := range vtxos {
		found := false
		for _, offchainAddr := range offchainAddrs {
			vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
			if err != nil {
				return nil, err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxosWithTapscripts = append(vtxosWithTapscripts, client.TapscriptsVtxo{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no offchain address found for vtxo %s", v.Txid)
		}
	}

	return vtxosWithTapscripts, nil
}

func (a *arkClient) joinBatchWithRetry(
	ctx context.Context, notes []string, outputs []types.Receiver, options settleOptions,
	selectedCoins []client.TapscriptsVtxo, selectedBoardingCoins []types.Utxo,
) (string, error) {
	inputs, exitLeaves, arkFields, err := toIntentInputs(
		selectedBoardingCoins, selectedCoins, notes,
	)
	if err != nil {
		return "", err
	}

	signerSessions, signerPubKeys, err := a.handleOptions(options, inputs, notes)
	if err != nil {
		return "", err
	}

	deleteIntent := func() {
		proof, message, err := a.makeDeleteIntent(inputs, exitLeaves, arkFields)
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

	maxRetry := 3
	retryCount := 0
	var batchErr error
	for retryCount < maxRetry {
		proofTx, message, err := a.makeRegisterIntent(
			inputs, exitLeaves, outputs, signerPubKeys, arkFields,
		)
		if err != nil {
			return "", err
		}

		intentID, err := a.client.RegisterIntent(ctx, proofTx, message)
		if err != nil {
			return "", fmt.Errorf("failed to register intent: %w", err)
		}

		log.Debugf("registered inputs and outputs with request id: %s", intentID)

		commitmentTxid, err := a.handleBatchEvents(
			ctx, intentID, selectedCoins, notes, selectedBoardingCoins, outputs, signerSessions,
			options.eventsCh, options.cancelCh,
		)
		if err != nil {
			deleteIntent()
			log.WithError(err).Warn("batch failed, retrying...")
			retryCount++
			time.Sleep(100 * time.Millisecond)
			batchErr = err
			continue
		}

		return commitmentTxid, nil
	}

	return "", fmt.Errorf("reached max atttempt of retries, last batch error: %s", batchErr)
}

func (a *arkClient) handleBatchEvents(
	ctx context.Context,
	intentId string, vtxos []client.TapscriptsVtxo, notes []string, boardingUtxos []types.Utxo,
	receivers []types.Receiver, signerSessions []tree.SignerSession,
	replayEventsCh chan<- any, cancelCh <-chan struct{},
) (string, error) {
	topics := make([]string, 0)
	for _, n := range notes {
		parsedNote, err := note.NewNoteFromString(n)
		if err != nil {
			return "", err
		}
		outpoint, _, err := parsedNote.IntentProofInput()
		if err != nil {
			return "", err
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

	options := []BatchSessionOption{WithCancel(cancelCh)}

	if skipVtxoTreeSigning {
		options = append(options, WithSkipVtxoTreeSigning())
	}

	if replayEventsCh != nil {
		options = append(options, WithReplay(replayEventsCh))
	}

	eventsCh, close, err := a.client.GetEventStream(ctx, topics)
	defer close()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("connection closed by server")
		}
		return "", err
	}

	batchEventsHandler := newBatchEventsHandler(
		a, intentId, vtxos, boardingUtxos, receivers, signerSessions,
	)

	commitmentTxid, err := JoinBatchSession(ctx, eventsCh, batchEventsHandler, options...)
	if err != nil {
		return "", err
	}

	return commitmentTxid, nil
}

func (a *arkClient) getMatureUtxos(ctx context.Context) ([]types.Utxo, error) {
	_, _, _, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	utxos := make([]types.Utxo, 0)
	for _, addr := range redemptionAddrs {
		fetchedUtxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, err
		}

		for _, utxo := range fetchedUtxos {
			u := utxo.ToUtxo(a.UnilateralExitDelay, addr.Tapscripts)
			if u.SpendableAt.Before(now) {
				utxos = append(utxos, u)
			}
		}
	}

	return utxos, nil
}

func (a *arkClient) getRedeemBranches(
	ctx context.Context, vtxos []types.Vtxo,
) (map[string]*redemption.CovenantlessRedeemBranch, error) {
	redeemBranches := make(map[string]*redemption.CovenantlessRedeemBranch, 0)

	for _, vtxo := range vtxos {
		redeemBranch, err := redemption.NewRedeemBranch(ctx, a.explorer, a.indexer, vtxo)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}

func (a *arkClient) getOffchainBalance(ctx context.Context) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)
	opts := &CoinSelectOptions{WithRecoverableVtxos: true}
	vtxos, err := a.getVtxos(ctx, opts)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.Amount

		if !vtxo.ExpiresAt.IsZero() {
			expiration := vtxo.ExpiresAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.Amount
		}
	}

	return balance, amountByExpiration, nil
}

func (a *arkClient) getAllBoardingUtxos(ctx context.Context) ([]types.Utxo, error) {
	_, _, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	utxos := []types.Utxo{}
	for _, addr := range boardingAddrs {
		txs, err := a.explorer.GetTxs(addr.Address)
		if err != nil {
			return nil, err
		}
		for _, tx := range txs {
			for i, vout := range tx.Vout {
				if vout.Address == addr.Address {
					createdAt := time.Time{}
					utxoTime := time.Now()
					if tx.Status.Confirmed {
						createdAt = time.Unix(tx.Status.BlockTime, 0)
						utxoTime = time.Unix(tx.Status.BlockTime, 0)
					}

					txHex, err := a.explorer.GetTxHex(tx.Txid)
					if err != nil {
						return nil, err
					}
					spentStatuses, err := a.explorer.GetTxOutspends(tx.Txid)
					if err != nil {
						return nil, err
					}
					spent := false
					spentBy := ""
					if len(spentStatuses) > i {
						if spentStatuses[i].Spent {
							spent = true
							spentBy = spentStatuses[i].SpentBy
						}
					}

					utxos = append(utxos, types.Utxo{
						Outpoint: types.Outpoint{
							Txid: tx.Txid,
							VOut: uint32(i),
						},
						Amount: vout.Amount,
						Script: vout.Script,
						Delay:  a.BoardingExitDelay,
						SpendableAt: utxoTime.Add(
							time.Duration(a.BoardingExitDelay.Seconds()) * time.Second,
						),
						CreatedAt:  createdAt,
						Tapscripts: addr.Tapscripts,
						Spent:      spent,
						SpentBy:    spentBy,
						Tx:         txHex,
					})
				}
			}
		}
	}

	return utxos, nil
}

func (a *arkClient) getClaimableBoardingUtxos(
	_ context.Context, boardingAddrs []wallet.TapscriptsAddress, opts *CoinSelectOptions,
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

		boardingUtxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		for _, utxo := range boardingUtxos {
			if opts != nil && len(opts.OutpointsFilter) > 0 {
				utxoOutpoint := types.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}
				found := false
				for _, outpoint := range opts.OutpointsFilter {
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

func (a *arkClient) getExpiredBoardingUtxos(
	ctx context.Context, opts *CoinSelectOptions,
) ([]types.Utxo, error) {
	_, _, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	expired := make([]types.Utxo, 0)
	for _, addr := range boardingAddrs {
		boardingScript, err := script.ParseVtxoScript(addr.Tapscripts)
		if err != nil {
			return nil, err
		}

		boardingTimeout, err := boardingScript.SmallestExitDelay()
		if err != nil {
			return nil, err
		}

		boardingUtxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		for _, utxo := range boardingUtxos {
			if opts != nil && len(opts.OutpointsFilter) > 0 {
				utxoOutpoint := types.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}
				found := false
				for _, outpoint := range opts.OutpointsFilter {
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
			if u.SpendableAt.Before(now) || u.SpendableAt.Equal(now) {
				expired = append(expired, u)
			}
		}
	}

	return expired, nil
}

func (a *arkClient) getVtxos(ctx context.Context, opts *CoinSelectOptions) ([]types.Vtxo, error) {
	spendable, err := a.ListSpendableVtxos(ctx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.OutpointsFilter) > 0 {
		spendable = filterByOutpoints(spendable, opts.OutpointsFilter)
	}

	recoverableVtxos := make([]types.Vtxo, 0)
	spendableVtxos := make([]types.Vtxo, 0, len(spendable))
	if opts != nil && opts.WithRecoverableVtxos {
		for _, vtxo := range spendable {
			if vtxo.IsRecoverable() {
				recoverableVtxos = append(recoverableVtxos, vtxo)
				continue
			}
			spendableVtxos = append(spendableVtxos, vtxo)
		}
	} else {
		spendableVtxos = make([]types.Vtxo, len(spendable))
		copy(spendableVtxos, spendable)
	}

	allVtxos := append(recoverableVtxos, spendableVtxos...)

	if opts != nil && opts.RecomputeExpiry {
		// if sorting by expiry is required, we need to get the expiration date of each vtxo
		redeemBranches, err := a.getRedeemBranches(ctx, spendableVtxos)
		if err != nil {
			return nil, err
		}

		for vtxoTxid, branch := range redeemBranches {
			expiration, err := branch.ExpiresAt()
			if err != nil {
				return nil, err
			}

			for i, vtxo := range allVtxos {
				if vtxo.Txid == vtxoTxid {
					allVtxos[i].ExpiresAt = *expiration
					break
				}
			}
		}
	}

	if opts != nil && opts.ExpiryThreshold > 0 {
		allVtxos = utils.FilterVtxosByExpiry(allVtxos, opts.ExpiryThreshold)
	}

	if opts == nil || !opts.WithoutExpirySorting {
		allVtxos = utils.SortVtxosByExpiry(allVtxos)
	}

	return allVtxos, nil
}

func (a *arkClient) getBoardingTxs(ctx context.Context) ([]types.Transaction, error) {
	allUtxos, err := a.getAllBoardingUtxos(ctx)
	if err != nil {
		return nil, err
	}

	unconfirmedTxs := make([]types.Transaction, 0)
	confirmedTxs := make([]types.Transaction, 0)
	for _, u := range allUtxos {
		tx := types.Transaction{
			TransactionKey: types.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      types.TxReceived,
			CreatedAt: u.CreatedAt,
			Settled:   u.Spent,
			SettledBy: u.SpentBy,
			Hex:       u.Tx,
		}

		if u.CreatedAt.IsZero() {
			unconfirmedTxs = append(unconfirmedTxs, tx)
			continue
		}
		confirmedTxs = append(confirmedTxs, tx)
	}

	txs := append(unconfirmedTxs, confirmedTxs...)
	return txs, nil
}

func (a *arkClient) handleCommitmentTx(
	ctx context.Context, myPubkeys map[string]struct{}, commitmentTx *client.TxNotification,
) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	vtxosToAdd := make([]types.Vtxo, 0)
	vtxosToSpend := make(map[types.Outpoint]string, 0)
	txsToAdd := make([]types.Transaction, 0)
	txsToSettle := make([]string, 0)

	for _, vtxo := range commitmentTx.SpendableVtxos {
		// remove opcodes from P2TR script
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos is ours.
	spentVtxos := make([]types.Outpoint, 0, len(commitmentTx.SpentVtxos))
	indexedSpentVtxos := make(map[types.Outpoint]types.Vtxo)
	for _, vtxo := range commitmentTx.SpentVtxos {
		spentVtxos = append(spentVtxos, types.Outpoint{
			Txid: vtxo.Txid,
			VOut: vtxo.VOut,
		})
		indexedSpentVtxos[vtxo.Outpoint] = vtxo
	}
	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, spentVtxos)
	if err != nil {
		return err
	}

	rawTx := &wire.MsgTx{}
	reader := hex.NewDecoder(strings.NewReader(commitmentTx.Tx))
	if err := rawTx.Deserialize(reader); err != nil {
		return err
	}

	// Check if any of the claimed boarding utxos is ours.
	boardingTxids := make([]string, 0, len(rawTx.TxIn))
	for _, in := range rawTx.TxIn {
		boardingTxids = append(boardingTxids, in.PreviousOutPoint.Hash.String())
	}
	pendingBoardingTxs, err := a.store.TransactionStore().GetTransactions(
		ctx, boardingTxids,
	)
	if err != nil {
		return err
	}
	pendingBoardingTxids := make([]string, 0, len(pendingBoardingTxs))
	for _, tx := range pendingBoardingTxs {
		pendingBoardingTxids = append(pendingBoardingTxids, tx.BoardingTxid)
	}

	// Add all our pending boarding txs to the list of those to settle.
	txsToSettle = append(txsToSettle, pendingBoardingTxids...)

	// Add also our preconfirmed txs the list of those to settle, and also add the related
	// vtxos to the list of those to mark as spent.
	for _, vtxo := range myVtxos {
		vtxosToSpend[vtxo.Outpoint] = indexedSpentVtxos[vtxo.Outpoint].SpentBy
		if !vtxo.Preconfirmed {
			continue
		}
		txsToSettle = append(txsToSettle, vtxo.Txid)
	}

	// If no vtxos have been spent, add a new tx record.
	if len(vtxosToSpend) <= 0 {
		if len(vtxosToAdd) > 0 && len(pendingBoardingTxs) <= 0 {
			amount := uint64(0)
			for _, v := range vtxosToAdd {
				amount += v.Amount
			}
			txsToAdd = append(txsToAdd, types.Transaction{
				TransactionKey: types.TransactionKey{
					CommitmentTxid: commitmentTx.Txid,
				},
				Amount:    amount,
				Type:      types.TxReceived,
				Settled:   true,
				CreatedAt: time.Now(),
				Hex:       commitmentTx.Tx,
			})
		} else {
			vtxosToAddAmount := uint64(0)
			for _, v := range vtxosToAdd {
				vtxosToAddAmount += v.Amount
			}
			settledBoardingAmount := uint64(0)
			for _, tx := range pendingBoardingTxs {
				settledBoardingAmount += tx.Amount
			}
			if vtxosToAddAmount > 0 && vtxosToAddAmount < settledBoardingAmount {
				txsToAdd = append(txsToAdd, types.Transaction{
					TransactionKey: types.TransactionKey{
						CommitmentTxid: commitmentTx.Txid,
					},
					Amount:    settledBoardingAmount - vtxosToAddAmount,
					Type:      types.TxSent,
					Settled:   true,
					CreatedAt: time.Now(),
					Hex:       commitmentTx.Tx,
				})
			}
		}
	} else {
		if len(txsToSettle) <= 0 {
			amount := uint64(0)
			for _, v := range myVtxos {
				amount += v.Amount
			}
			for _, v := range vtxosToAdd {
				amount -= v.Amount
			}

			if amount > 0 {
				txsToAdd = append(txsToAdd, types.Transaction{
					TransactionKey: types.TransactionKey{
						CommitmentTxid: commitmentTx.Txid,
					},
					Amount:    amount,
					Type:      types.TxSent,
					Settled:   true,
					CreatedAt: time.Now(),
					Hex:       commitmentTx.Tx,
				})
			}
		}
	}

	if len(txsToAdd) > 0 {
		count, err := a.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		log.Debugf("added %d transaction(s)", count)
	}

	if len(txsToSettle) > 0 {
		count, err := a.store.TransactionStore().
			SettleTransactions(ctx, txsToSettle, commitmentTx.Txid)
		if err != nil {
			return err
		}
		log.Debugf("settled %d transaction(s)", count)
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		log.Debugf("added %d vtxo(s)", count)
	}

	if len(vtxosToSpend) > 0 {
		count, err := a.store.VtxoStore().SettleVtxos(ctx, vtxosToSpend, commitmentTx.Txid)
		if err != nil {
			return err
		}
		log.Debugf("spent %d vtxo(s)", count)
	}

	return nil
}

func (a *arkClient) handleArkTx(
	ctx context.Context, myPubkeys map[string]struct{}, arkTx *client.TxNotification,
) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	vtxosToAdd := make([]types.Vtxo, 0)
	vtxosToSpend := make(map[types.Outpoint]string)
	txsToAdd := make([]types.Transaction, 0)

	for _, vtxo := range arkTx.SpendableVtxos {
		// remove opcodes from P2TR script
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos are ours.
	spentVtxos := make([]types.Outpoint, 0, len(arkTx.SpentVtxos))
	for _, vtxo := range arkTx.SpentVtxos {
		spentVtxos = append(spentVtxos, types.Outpoint{
			Txid: vtxo.Txid,
			VOut: vtxo.VOut,
		})
	}
	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, spentVtxos)
	if err != nil {
		return err
	}
	txsToSettle := make([]string, 0, len(vtxosToSpend))
	for _, vtxo := range myVtxos {
		vtxosToSpend[vtxo.Outpoint] = arkTx.CheckpointTxs[vtxo.Outpoint].Txid
		txsToSettle = append(txsToSettle, vtxo.Txid)
	}

	// If not spent vtxos, add a new received tx to the history.
	if len(vtxosToSpend) <= 0 {
		if len(vtxosToAdd) > 0 {
			amount := uint64(0)
			for _, v := range vtxosToAdd {
				amount += v.Amount
			}
			txsToAdd = append(txsToAdd, types.Transaction{
				TransactionKey: types.TransactionKey{
					ArkTxid: arkTx.Txid,
				},
				Amount:    amount,
				Type:      types.TxReceived,
				CreatedAt: time.Now(),
				Hex:       arkTx.Tx,
			})
		}
	} else {
		// Otherwise, add a new spent tx to the history.
		inAmount := uint64(0)
		for _, vtxo := range myVtxos {
			inAmount += vtxo.Amount
		}
		outAmount := uint64(0)
		for _, vtxo := range vtxosToAdd {
			outAmount += vtxo.Amount
		}
		txsToAdd = append(txsToAdd, types.Transaction{
			TransactionKey: types.TransactionKey{
				ArkTxid: arkTx.Txid,
			},
			Amount:    inAmount - outAmount,
			Type:      types.TxSent,
			Settled:   true,
			CreatedAt: time.Now(),
		})
	}

	if len(txsToAdd) > 0 {
		count, err := a.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		log.Debugf("added %d transaction(s)", count)
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		log.Debugf("added %d vtxo(s)", count)
	}

	if len(vtxosToSpend) > 0 {
		count, err := a.store.VtxoStore().SpendVtxos(ctx, vtxosToSpend, arkTx.Txid)
		if err != nil {
			return err
		}
		log.Debugf("spent %d vtxo(s)", count)

		count, err = a.store.TransactionStore().SettleTransactions(ctx, txsToSettle, "")
		if err != nil {
			return err
		}
		log.Debugf("settled %d transaction(s)", count)
	}

	return nil
}

func (a *arkClient) handleOptions(
	options settleOptions, inputs []intent.Input, notesInputs []string,
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

		signerSession, err := a.wallet.NewVtxoTreeSigner(
			context.Background(),
			inputsToDerivationPath(outpoints, notesInputs),
		)
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

func (a *arkClient) fetchTxHistory(ctx context.Context) ([]types.Transaction, error) {
	spendable, spent, err := a.listVtxosFromIndexer(ctx)
	if err != nil {
		return nil, err
	}

	onchainHistory, err := a.getBoardingTxs(ctx)
	if err != nil {
		return nil, err
	}
	commitmentTxsToIgnore := make(map[string]struct{})
	for _, tx := range onchainHistory {
		if tx.SettledBy != "" {
			commitmentTxsToIgnore[tx.SettledBy] = struct{}{}
		}
	}

	offchainHistory, err := a.vtxosToTxs(ctx, spendable, spent, commitmentTxsToIgnore)
	if err != nil {
		return nil, err
	}

	history := append(onchainHistory, offchainHistory...)
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].CreatedAt.After(history[j].CreatedAt)
	})

	return history, nil
}

func (i *arkClient) vtxosToTxs(
	ctx context.Context, spendable, spent []types.Vtxo, commitmentTxsToIgnore map[string]struct{},
) ([]types.Transaction, error) {
	txs := make([]types.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx
	vtxosLeftToCheck := append([]types.Vtxo{}, spent...)
	for _, vtxo := range append(spendable, spent...) {
		if _, ok := commitmentTxsToIgnore[vtxo.CommitmentTxids[0]]; !vtxo.Preconfirmed && ok {
			continue
		}

		settleVtxos := findVtxosSpentInSettlement(vtxosLeftToCheck, vtxo)
		settleAmount := reduceVtxosAmount(settleVtxos)
		if vtxo.Amount <= settleAmount {
			continue // settlement, ignore
		}

		spentVtxos := findVtxosSpentInPayment(vtxosLeftToCheck, vtxo)
		spentAmount := reduceVtxosAmount(spentVtxos)
		if vtxo.Amount <= spentAmount {
			continue // change, ignore
		}

		commitmentTxid := vtxo.CommitmentTxids[0]
		arkTxid := ""
		settled := !vtxo.Preconfirmed
		settledBy := ""
		if vtxo.Preconfirmed {
			arkTxid = vtxo.Txid
			commitmentTxid = ""
			settled = vtxo.Spent
			settledBy = vtxo.SettledBy
		}

		txs = append(txs, types.Transaction{
			TransactionKey: types.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    vtxo.Amount - settleAmount - spentAmount,
			Type:      types.TxReceived,
			CreatedAt: vtxo.CreatedAt,
			Settled:   settled,
			SettledBy: settledBy,
		})
	}

	// Sendings

	// All "spentBy" vtxos are payments unless:
	// - they are settlements

	// aggregate spent by spentId
	vtxosBySpentBy := make(map[string][]types.Vtxo)
	for _, v := range spent {
		if len(v.SpentBy) <= 0 {
			continue
		}
		if v.SettledBy != "" {
			continue
		}

		if _, ok := vtxosBySpentBy[v.ArkTxid]; !ok {
			vtxosBySpentBy[v.ArkTxid] = make([]types.Vtxo, 0)
		}
		vtxosBySpentBy[v.ArkTxid] = append(vtxosBySpentBy[v.ArkTxid], v)
	}

	for sb := range vtxosBySpentBy {
		resultedVtxos := findVtxosResultedFromSpentBy(append(spendable, spent...), sb)
		resultedAmount := reduceVtxosAmount(resultedVtxos)
		spentAmount := reduceVtxosAmount(vtxosBySpentBy[sb])
		if spentAmount <= resultedAmount {
			continue // settlement, ignore
		}
		vtxo := getVtxo(resultedVtxos, vtxosBySpentBy[sb])
		if resultedAmount == 0 {
			// send all: fetch the created vtxo to source creation and expiration timestamps
			opts := &indexer.GetVtxosRequestOption{}
			// nolint
			opts.WithOutpoints([]types.Outpoint{{Txid: sb, VOut: 0}})
			resp, err := i.indexer.GetVtxos(ctx, *opts)
			if err != nil {
				return nil, err
			}
			// Pending tx, skip
			// TODO: maybe we want to handle this somehow?
			if len(resp.Vtxos) <= 0 {
				continue
			}
			vtxo = resp.Vtxos[0]
		}

		commitmentTxid := vtxo.CommitmentTxids[0]
		arkTxid := ""
		if vtxo.Preconfirmed {
			arkTxid = vtxo.Txid
			commitmentTxid = ""
		}

		txs = append(txs, types.Transaction{
			TransactionKey: types.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    spentAmount - resultedAmount,
			Type:      types.TxSent,
			CreatedAt: vtxo.CreatedAt,
			Settled:   true,
		})

	}

	return txs, nil
}

func toOutputScript(onchainAddress string, network arklib.Network) ([]byte, error) {
	netParams := utils.ToBitcoinNetwork(network)
	rcvAddr, err := btcutil.DecodeAddress(onchainAddress, &netParams)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(rcvAddr)
}

func toOnchainAddress(arkAddress string, network arklib.Network) (string, error) {
	netParams := utils.ToBitcoinNetwork(network)

	decodedAddr, err := arklib.DecodeAddressV0(arkAddress)
	if err != nil {
		return "", err
	}

	witnessProgram := schnorr.SerializePubKey(decodedAddr.VtxoTapKey)

	addr, err := btcutil.NewAddressTaproot(witnessProgram, &netParams)
	if err != nil {
		return "", err
	}

	return addr.String(), nil
}

func verifySignedCheckpoints(
	originalCheckpoints, signedCheckpoints []string, signerpubkey *btcec.PublicKey,
) error {
	// index by txid
	indexedOriginalCheckpoints := make(map[string]*psbt.Packet)
	indexedSignedCheckpoints := make(map[string]*psbt.Packet)

	for _, cp := range originalCheckpoints {
		originalPtx, err := psbt.NewFromRawBytes(strings.NewReader(cp), true)
		if err != nil {
			return err
		}
		indexedOriginalCheckpoints[originalPtx.UnsignedTx.TxID()] = originalPtx
	}

	for _, cp := range signedCheckpoints {
		signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(cp), true)
		if err != nil {
			return err
		}
		indexedSignedCheckpoints[signedPtx.UnsignedTx.TxID()] = signedPtx
	}

	for txid, originalPtx := range indexedOriginalCheckpoints {
		signedPtx, ok := indexedSignedCheckpoints[txid]
		if !ok {
			return fmt.Errorf("signed checkpoint %s not found", txid)
		}
		if err := verifyOffchainPsbt(originalPtx, signedPtx, signerpubkey); err != nil {
			return err
		}
	}

	return nil
}

func verifySignedArk(original, signed string, signerPubKey *btcec.PublicKey) error {
	originalPtx, err := psbt.NewFromRawBytes(strings.NewReader(original), true)
	if err != nil {
		return err
	}

	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		return err
	}

	return verifyOffchainPsbt(originalPtx, signedPtx, signerPubKey)
}

func verifyOffchainPsbt(original, signed *psbt.Packet, signerpubkey *btcec.PublicKey) error {
	xonlySigner := schnorr.SerializePubKey(signerpubkey)

	if original.UnsignedTx.TxID() != signed.UnsignedTx.TxID() {
		return fmt.Errorf("invalid offchain tx : txids mismatch")
	}

	if len(original.Inputs) != len(signed.Inputs) {
		return fmt.Errorf(
			"input count mismatch: expected %d, got %d",
			len(original.Inputs),
			len(signed.Inputs),
		)
	}

	if len(original.UnsignedTx.TxIn) != len(signed.UnsignedTx.TxIn) {
		return fmt.Errorf(
			"transaction input count mismatch: expected %d, got %d",
			len(original.UnsignedTx.TxIn),
			len(signed.UnsignedTx.TxIn),
		)
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for inputIndex, signedInput := range signed.Inputs {

		if signedInput.WitnessUtxo == nil {
			return fmt.Errorf("witness utxo not found for input %d", inputIndex)
		}

		// fill prevouts map with the original witness data
		previousOutpoint := original.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		prevouts[previousOutpoint] = original.Inputs[inputIndex].WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txsigHashes := txscript.NewTxSigHashes(original.UnsignedTx, prevoutFetcher)

	// loop over every input and check that the signer's signature is present and valid
	for inputIndex, signedInput := range signed.Inputs {
		orignalInput := original.Inputs[inputIndex]
		if len(orignalInput.TaprootLeafScript) == 0 {
			return fmt.Errorf(
				"original input %d has no taproot leaf script, cannot verify signature",
				inputIndex,
			)
		}

		// check that every input has the signer's signature
		var signerSig *psbt.TaprootScriptSpendSig

		for _, sig := range signedInput.TaprootScriptSpendSig {
			if bytes.Equal(sig.XOnlyPubKey, xonlySigner) {
				signerSig = sig
				break
			}
		}

		if signerSig == nil {
			return fmt.Errorf("signer signature not found for input %d", inputIndex)
		}

		sig, err := schnorr.ParseSignature(signerSig.Signature)
		if err != nil {
			return fmt.Errorf("failed to parse signer signature for input %d: %s", inputIndex, err)
		}

		// verify the signature
		message, err := txscript.CalcTapscriptSignaturehash(
			txsigHashes,
			signedInput.SighashType,
			original.UnsignedTx,
			inputIndex,
			prevoutFetcher,
			txscript.NewBaseTapLeaf(orignalInput.TaprootLeafScript[0].Script),
		)
		if err != nil {
			return err
		}

		if !sig.Verify(message, signerpubkey) {
			return fmt.Errorf("invalid signer signature for input %d", inputIndex)
		}
	}
	return nil
}
