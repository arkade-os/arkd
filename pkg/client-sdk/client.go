package arksdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/indexer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

// SettleOptions is only available for covenantless clients
// it allows to customize the vtxo signing process
type SettleOptions struct {
	ExtraSignerSessions    []tree.SignerSession
	SigningType            *tree.SigningType
	WalletSignerDisabled   bool
	SelectRecoverableVtxos bool

	EventsCh chan<- client.RoundEvent
}

func WithRecoverableVtxos(o interface{}) error {
	opts, ok := o.(*SettleOptions)
	if !ok {
		return fmt.Errorf("invalid options type")
	}

	opts.SelectRecoverableVtxos = true
	return nil
}

func WithEventsCh(ch chan<- client.RoundEvent) Option {
	return func(o interface{}) error {
		opts, ok := o.(*SettleOptions)
		if !ok {
			return fmt.Errorf("invalid options type")
		}

		opts.EventsCh = ch
		return nil
	}
}

// WithoutWalletSigner disables the wallet signer
func WithoutWalletSigner(o interface{}) error {
	opts, ok := o.(*SettleOptions)
	if !ok {
		return fmt.Errorf("invalid options type")
	}

	opts.WalletSignerDisabled = true
	return nil
}

// WithSignAll sets the signing type to ALL instead of the default BRANCH
func WithSignAll(o interface{}) error {
	opts, ok := o.(*SettleOptions)
	if !ok {
		return fmt.Errorf("invalid options type")
	}

	t := tree.SignAll
	opts.SigningType = &t
	return nil
}

// WithExtraSigner allows to use a set of custom signer for the vtxo tree signing process
func WithExtraSigner(signerSessions ...tree.SignerSession) Option {
	return func(o interface{}) error {
		opts, ok := o.(*SettleOptions)
		if !ok {
			return fmt.Errorf("invalid options type")
		}

		if len(signerSessions) == 0 {
			return fmt.Errorf("no signer sessions provided")
		}

		opts.ExtraSignerSessions = signerSessions
		return nil
	}
}

type bitcoinReceiver struct {
	to     string
	amount uint64
}

func NewBitcoinReceiver(to string, amount uint64) Receiver {
	return bitcoinReceiver{to, amount}
}

func (r bitcoinReceiver) To() string {
	return r.to
}

func (r bitcoinReceiver) Amount() uint64 {
	return r.amount
}

func (r bitcoinReceiver) IsOnchain() bool {
	_, err := btcutil.DecodeAddress(r.to, nil)
	return err == nil
}

type covenantlessArkClient struct {
	*arkClient
}

func NewArkClient(sdkStore types.Store) (ArkClient, error) {
	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	if cfgData != nil {
		return nil, ErrAlreadyInitialized
	}

	return &covenantlessArkClient{
		&arkClient{
			store: sdkStore,
		},
	}, nil
}

func LoadArkClient(sdkStore types.Store) (ArkClient, error) {
	if sdkStore == nil {
		return nil, fmt.Errorf("missin sdk repository")
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

	explorerSvc, err := getExplorer(cfgData.ExplorerURL, cfgData.ExplorerWSURL, cfgData.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(cfgData.ClientType, cfgData.ServerUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	walletSvc, err := getWallet(
		sdkStore.ConfigStore(),
		explorerSvc,
		cfgData,
		supportedWallets,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup wallet: %s", err)
	}

	covenantlessClient := covenantlessArkClient{
		&arkClient{
			Config:   cfgData,
			wallet:   walletSvc,
			store:    sdkStore,
			explorer: explorerSvc,
			client:   clientSvc,
			indexer:  indexerSvc,
		},
	}

	if cfgData.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		covenantlessClient.txStreamCtxCancel = txStreamCtxCancel
		if err := covenantlessClient.refreshDb(context.Background()); err != nil {
			return nil, err
		}
		go covenantlessClient.listenForArkTxs(txStreamCtx)
		if cfgData.UtxoMaxAmount != 0 {
			go covenantlessClient.listenWebsocketBoardingTxns(txStreamCtx)
		}
	}

	return &covenantlessClient, nil
}

func LoadArkClientWithWallet(
	sdkStore types.Store, walletSvc wallet.WalletService,
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

	explorerSvc, err := getExplorer(cfgData.ExplorerURL, cfgData.ExplorerWSURL, cfgData.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(cfgData.ClientType, cfgData.ServerUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	covenantlessClient := covenantlessArkClient{
		&arkClient{
			Config:   cfgData,
			wallet:   walletSvc,
			store:    sdkStore,
			explorer: explorerSvc,
			client:   clientSvc,
			indexer:  indexerSvc,
		},
	}

	if cfgData.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		covenantlessClient.txStreamCtxCancel = txStreamCtxCancel
		if err := covenantlessClient.refreshDb(context.Background()); err != nil {
			return nil, err
		}
		go covenantlessClient.listenForArkTxs(txStreamCtx)
		if cfgData.UtxoMaxAmount != 0 {
			go covenantlessClient.listenWebsocketBoardingTxns(txStreamCtx)
		}
	}

	return &covenantlessClient, nil
}

func (a *covenantlessArkClient) Init(ctx context.Context, args InitArgs) error {
	if err := a.init(ctx, args); err != nil {
		return err
	}

	if args.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		a.txStreamCtxCancel = txStreamCtxCancel
		if err := a.refreshDb(context.Background()); err != nil {
			return err
		}
		go a.listenForArkTxs(txStreamCtx)
		if a.UtxoMaxAmount != 0 {
			go a.listenWebsocketBoardingTxns(txStreamCtx)
		}
	}

	return nil
}

func (a *covenantlessArkClient) InitWithWallet(ctx context.Context, args InitWithWalletArgs) error {
	if err := a.initWithWallet(ctx, args); err != nil {
		return err
	}

	if a.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		a.txStreamCtxCancel = txStreamCtxCancel
		if err := a.refreshDb(context.Background()); err != nil {
			return err
		}
		go a.listenForArkTxs(txStreamCtx)
		if a.UtxoMaxAmount != 0 {
			go a.listenWebsocketBoardingTxns(txStreamCtx)
		}
	}

	return nil
}

func (a *covenantlessArkClient) Balance(
	ctx context.Context, computeVtxoExpiration bool,
) (*Balance, error) {
	if a.wallet == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	offchainAddrs, boardingAddrs, redeemAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	if a.UtxoMaxAmount == 0 {
		balance, amountByExpiration, err := a.getOffchainBalance(
			ctx, computeVtxoExpiration,
		)
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

	const nbWorkers = 3
	wg := &sync.WaitGroup{}
	wg.Add(nbWorkers * len(offchainAddrs))

	chRes := make(chan balanceRes, nbWorkers*len(offchainAddrs))
	for i := range offchainAddrs {
		boardingAddr := boardingAddrs[i]
		redeemAddr := redeemAddrs[i]

		go func() {
			defer wg.Done()
			balance, amountByExpiration, err := a.getOffchainBalance(
				ctx, computeVtxoExpiration,
			)
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

func (a *covenantlessArkClient) OnboardAgainAllExpiredBoardings(
	ctx context.Context,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if a.UtxoMaxAmount == 0 {
		return "", fmt.Errorf("operation not allowed by the server")
	}

	_, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	return a.sendExpiredBoardingUtxos(ctx, boardingAddr.Address)
}

func (a *covenantlessArkClient) WithdrawFromAllExpiredBoardings(
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

func (a *covenantlessArkClient) SendOffChain(
	ctx context.Context,
	withExpiryCoinselect bool, receivers []Receiver,
	withZeroFees bool,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if len(receivers) <= 0 {
		return "", fmt.Errorf("missing receivers")
	}

	netParams := utils.ToBitcoinNetwork(a.Network)
	for _, receiver := range receivers {
		isOnchain, _, err := utils.ParseBitcoinAddress(receiver.To(), netParams)
		if err != nil {
			return "", err
		}
		if isOnchain {
			return "", fmt.Errorf("all receiver addresses must be offchain addresses")
		}
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	expectedServerPubkey := schnorr.SerializePubKey(a.ServerPubKey)

	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		rcvAddr, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvServerPubkey := schnorr.SerializePubKey(rcvAddr.Server)

		if !bytes.Equal(expectedServerPubkey, rcvServerPubkey) {
			return "", fmt.Errorf("invalid receiver address '%s': expected server %s, got %s", receiver.To(), hex.EncodeToString(expectedServerPubkey), hex.EncodeToString(rcvServerPubkey))
		}

		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}

		sumOfReceivers += receiver.Amount()
	}

	vtxos := make([]client.TapscriptsVtxo, 0)
	opts := &CoinSelectOptions{
		WithExpirySorting: withExpiryCoinselect,
	}
	spendableVtxos, err := a.getVtxos(ctx, opts)
	if err != nil {
		return "", err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.ServerPubKey, a.Network)
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
		nil, vtxos, sumOfReceivers, a.Dust, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		receivers = append(receivers, NewBitcoinReceiver(offchainAddrs[0].Address, changeAmount))
	}

	inputs := make([]redeemTxInput, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		vtxoScript, err := tree.ParseVtxoScript(coin.Tapscripts)
		if err != nil {
			return "", err
		}

		forfeitClosure := vtxoScript.ForfeitClosures()[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return "", err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)

		inputs = append(inputs, redeemTxInput{
			coin,
			forfeitLeaf.TapHash(),
		})
	}

	feeRate := chainfee.FeePerKwFloor
	redeemTx, err := buildRedeemTx(inputs, receivers, feeRate.FeePerVByte(), nil, withZeroFees)
	if err != nil {
		return "", err
	}

	signedRedeemTx, err := a.wallet.SignTransaction(ctx, a.explorer, redeemTx)
	if err != nil {
		return "", err
	}

	_, redeemTxid, err := a.client.SubmitRedeemTx(ctx, signedRedeemTx)
	if err != nil {
		return "", err
	}

	return redeemTxid, nil
}

func (a *covenantlessArkClient) RedeemNotes(ctx context.Context, notes []string, opts ...Option) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	amount := uint64(0)

	options := &SettleOptions{}
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}

	for _, vStr := range notes {
		v, err := note.NewFromString(vStr)
		if err != nil {
			return "", err
		}
		amount += uint64(v.Value)
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}
	if len(offchainAddrs) <= 0 {
		return "", fmt.Errorf("no funds detected")
	}

	receiversOutput := []client.Output{{
		Address: offchainAddrs[0].Address,
		Amount:  amount,
	}}

	return a.joinRoundWithRetry(ctx, notes, receiversOutput, *options, nil, nil)
}

func (a *covenantlessArkClient) StartUnilateralExit(ctx context.Context) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	vtxos, err := a.getVtxos(ctx, nil)
	if err != nil {
		return err
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

	for _, branch := range redeemBranches {
		branchTxs, err := branch.RedeemPath()
		if err != nil {
			return err
		}

		for _, txHex := range branchTxs {
			if _, ok := transactionsMap[txHex]; !ok {
				transactions = append(transactions, txHex)
				transactionsMap[txHex] = struct{}{}
			}
		}
	}

	for i, txHex := range transactions {
		for {
			txid, err := a.explorer.Broadcast(txHex)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "bad-txns-inputs-missingorspent") {
					time.Sleep(1 * time.Second)
				} else {
					return err
				}
			}

			if len(txid) > 0 {
				log.Infof("(%d/%d) broadcasted tx %s", i+1, len(transactions), txid)
				break
			}
		}
	}

	return nil
}

func (a *covenantlessArkClient) CompleteUnilateralExit(
	ctx context.Context, to string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if _, err := btcutil.DecodeAddress(to, nil); err != nil {
		return "", fmt.Errorf("invalid receiver address '%s': must be onchain", to)
	}

	return a.completeUnilateralExit(ctx, to)
}

func (a *covenantlessArkClient) CollaborativeExit(
	ctx context.Context,
	addr string, amount uint64, withExpiryCoinselect bool,
	opts ...Option,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if a.UtxoMaxAmount == 0 {
		return "", fmt.Errorf("operation not allowed by the server")
	}

	options := &SettleOptions{}
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}

	netParams := utils.ToBitcoinNetwork(a.Network)
	if _, err := btcutil.DecodeAddress(addr, &netParams); err != nil {
		return "", fmt.Errorf("invalid onchain address")
	}

	receivers := []client.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	boardingUtxos, vtxos, changeAmount, err := a.selectFunds(ctx, withExpiryCoinselect, options.SelectRecoverableVtxos, amount)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}

		receivers = append(receivers, client.Output{
			Address: offchainAddr.Address,
			Amount:  changeAmount,
		})
	}

	return a.joinRoundWithRetry(ctx, nil, receivers, *options, vtxos, boardingUtxos)
}

func (a *covenantlessArkClient) Settle(ctx context.Context, opts ...Option) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	return a.sendOffchain(ctx, false, nil, opts...)
}

func (a *covenantlessArkClient) GetTransactionHistory(
	ctx context.Context,
) ([]types.Transaction, error) {
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

	spendableVtxos, spentVtxos, err := a.ListVtxos(ctx)
	if err != nil {
		return nil, err
	}

	boardingTxs, roundsToIgnore, err := a.getBoardingTxs(ctx)
	if err != nil {
		return nil, err
	}

	offchainTxs, err := vtxosToTxHistory(spendableVtxos, spentVtxos, roundsToIgnore, a.indexer)
	if err != nil {
		return nil, err
	}

	history := append(boardingTxs, offchainTxs...)
	// Sort the slice by age
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].CreatedAt.IsZero() || history[i].CreatedAt.After(history[j].CreatedAt)
	})

	return history, nil
}

func (a *covenantlessArkClient) listenForArkTxs(ctx context.Context) {
	eventChan, closeFunc, err := a.client.GetTransactionsStream(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get transaction stream")
		return
	}
	defer closeFunc()

	for {
		select {
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

			offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
			if err != nil {
				log.WithError(err).Error("failed to get offchain addresses")
				continue
			}

			myPubkeys := make(map[string]struct{})
			for _, addr := range offchainAddrs {
				// nolint:all
				decoded, _ := common.DecodeAddress(addr.Address)
				pubkey := hex.EncodeToString(decoded.VtxoTapKey.SerializeCompressed()[1:])
				myPubkeys[pubkey] = struct{}{}
			}

			if event.Round != nil {
				if err := a.handleRoundTx(context.Background(), myPubkeys, event.Round); err != nil {
					log.WithError(err).Error("failed to process round tx")
					continue
				}
			}

			if event.Redeem != nil {
				if err := a.handleRedeemTx(context.Background(), myPubkeys, event.Redeem); err != nil {
					log.WithError(err).Error("failed to process redeem tx")
					continue
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *covenantlessArkClient) refreshDb(ctx context.Context) error {
	// fetch new data
	spendableVtxos, spentVtxos, err := a.ListVtxos(ctx)
	if err != nil {
		return err
	}

	boardingTxs, roundsToIgnore, err := a.getBoardingTxs(ctx)
	if err != nil {
		return err
	}

	offchainTxs, err := vtxosToTxHistory(spendableVtxos, spentVtxos, roundsToIgnore, a.indexer)
	if err != nil {
		return err
	}

	newTxs := append(offchainTxs, boardingTxs...)
	if err := a.refreshTxDb(newTxs); err != nil {
		return err
	}

	return a.refreshVtxoDb(spendableVtxos, spentVtxos)
}

func (a *covenantlessArkClient) refreshTxDb(newTxs []types.Transaction) error {
	ctx := context.Background()

	// fetch old data
	oldTxs, err := a.store.TransactionStore().GetAllTransactions(ctx)
	if err != nil {
		return err
	}

	// build a map for quick lookups
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
		log.Debugf("added %d new transaction(s)", count)
	}
	if len(txsToReplace) > 0 {
		count, err := a.store.TransactionStore().UpdateTransactions(ctx, txsToReplace)
		if err != nil {
			return err
		}
		log.Debugf("updated %d transaction(s)", count)
	}

	return nil
}

func (a *covenantlessArkClient) refreshVtxoDb(spendableVtxos, spentVtxos []client.Vtxo) error {
	ctx := context.Background()

	oldSpendableVtxos, _, err := a.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return err
	}

	oldSpendableVtxoMap := make(map[types.VtxoKey]types.Vtxo, 0)
	for _, v := range oldSpendableVtxos {
		oldSpendableVtxoMap[v.VtxoKey] = v
	}

	vtxosToAdd := make([]types.Vtxo, 0, len(spendableVtxos))
	for _, vtxo := range spendableVtxos {
		if _, ok := oldSpendableVtxoMap[types.VtxoKey(vtxo.Outpoint)]; !ok {
			vtxosToAdd = append(vtxosToAdd, toTypesVtxo(vtxo))
		}
	}

	vtxosToReplace := make([]types.Vtxo, 0, len(spentVtxos))
	for _, vtxo := range spentVtxos {
		if _, ok := oldSpendableVtxoMap[types.VtxoKey(vtxo.Outpoint)]; ok {
			vtxosToReplace = append(vtxosToReplace, toTypesVtxo(vtxo))
		}
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		log.Debugf("added %d new vtxo(s)", count)
	}
	if len(vtxosToReplace) > 0 {
		count, err := a.store.VtxoStore().UpdateVtxos(ctx, vtxosToReplace)
		if err != nil {
			return err
		}
		log.Debugf("updated %d vtxo(s)", count)
	}

	return nil
}

func (a *covenantlessArkClient) listenWebsocketBoardingTxns(ctx context.Context) {
	// try to add existing boarding utxos if present
	_, boardingAddresses, _, err := a.wallet.GetAddresses(ctx)
	if err == nil {
		for _, boardingAddress := range boardingAddresses {
			if err := a.explorer.TrackAddress(boardingAddress.Address); err != nil {
				log.WithError(err).Errorf("failed to track boarding address %s", boardingAddress.Address)
			}
		}
	}

	err = a.explorer.ListenAddresses(func(utxos []explorer.BlockUtxo) error {
		_, boardingAddresses, _, err := a.wallet.GetAddresses(ctx)
		if err != nil {
			return err
		}

		_, blockTime, err := a.explorer.GetTxBlockTime(utxos[0].Txid)
		if err != nil {
			return err
		}

		newPendingBoardingTxs := make([]types.Transaction, 0)

		for _, u := range utxos {
			found := false
			for _, addr := range boardingAddresses {
				if addr.Address == u.ScriptPubAddress {
					found = true
					break
				}
			}
			if found {
				newPendingBoardingTxs = append(newPendingBoardingTxs, types.Transaction{
					TransactionKey: types.TransactionKey{
						BoardingTxid: u.Txid,
					},
					Amount:    u.Value,
					Type:      types.TxReceived,
					CreatedAt: time.Unix(blockTime, 0),
				})
			}
		}

		count, err := a.store.TransactionStore().
			AddTransactions(ctx, newPendingBoardingTxs)
		if err != nil {
			return err

		}
		log.Debugf("added %d boarding transaction(s)", count)

		return nil
	})

	// falback to polling if websocket fails
	if err != nil {
		log.WithError(err).Error("Failed to listen for boarding utxos on websocket, falling back to polling")
		a.listenForBoardingTxs(ctx)
	}
}

func (a *covenantlessArkClient) listenForBoardingTxs(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
			if err != nil {
				log.WithError(err).Error("failed to get all boarding addresses")
				continue
			}
			txsToAdd, txsToConfirm, rbfTxs, err := a.getBoardingTransactions(ctx, boardingAddrs)
			if err != nil {
				log.WithError(err).Error("failed to get pending transactions")
				continue
			}

			if len(txsToAdd) > 0 {
				count, err := a.store.TransactionStore().AddTransactions(
					ctx, txsToAdd,
				)
				if err != nil {
					log.WithError(err).Error("failed to add new boarding transactions")
					continue
				}
				log.Debugf("added %d boarding transaction(s)", count)
			}

			if len(txsToConfirm) > 0 {
				count, err := a.store.TransactionStore().ConfirmTransactions(
					ctx, txsToConfirm, time.Now(),
				)
				if err != nil {
					log.WithError(err).Error("failed to update boarding transactions")
					continue
				}
				log.Debugf("confirmed %d boarding transaction(s)", count)
			}

			if len(rbfTxs) > 0 {
				count, err := a.store.TransactionStore().RbfTransactions(ctx, rbfTxs)
				if err != nil {
					log.WithError(err).Error("failed to update rbf boarding transactions")
					continue
				}
				log.Debugf("replaced %d transaction(s)", count)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *covenantlessArkClient) getBoardingTransactions(
	ctx context.Context, boardingAddrs []wallet.TapscriptsAddress,
) ([]types.Transaction, []string, map[string]types.Transaction, error) {
	oldTxs, err := a.store.TransactionStore().GetAllTransactions(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	rbfTxs := make(map[string]types.Transaction, 0)
	replacements := make(map[string]struct{}, 0)
	for _, tx := range oldTxs {
		if tx.IsBoarding() && tx.CreatedAt.IsZero() {
			isRbf, replacedBy, timestamp, err := a.explorer.IsRBFTx(tx.BoardingTxid, tx.Hex)
			if err != nil {
				return nil, nil, nil, err
			}
			if isRbf {
				txHex, err := a.explorer.GetTxHex(replacedBy)
				if err != nil {
					return nil, nil, nil, err
				}
				rawTx := &wire.MsgTx{}
				if err := rawTx.Deserialize(strings.NewReader(txHex)); err != nil {
					return nil, nil, nil, err
				}
				amount := uint64(0)
				netParams := utils.ToBitcoinNetwork(a.Network)
				for _, addr := range boardingAddrs {
					decoded, err := btcutil.DecodeAddress(addr.Address, &netParams)
					if err != nil {
						return nil, nil, nil, err
					}
					pkScript, err := txscript.PayToAddrScript(decoded)
					if err != nil {
						return nil, nil, nil, err
					}
					for _, out := range rawTx.TxOut {
						if bytes.Equal(out.PkScript, pkScript) {
							amount = uint64(out.Value)
							break
						}
					}
					if amount > 0 {
						break
					}
				}
				rbfTxs[tx.BoardingTxid] = types.Transaction{
					TransactionKey: types.TransactionKey{
						BoardingTxid: replacedBy,
					},
					CreatedAt: time.Unix(timestamp, 0),
					Hex:       txHex,
					Amount:    amount,
				}
				replacements[replacedBy] = struct{}{}
			}
		}
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx, boardingAddrs, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	txsToAdd := make([]types.Transaction, 0)
	txsToConfirm := make([]string, 0)
	for _, u := range boardingUtxos {
		if _, ok := replacements[u.Txid]; ok {
			continue
		}

		found := false
		for _, tx := range oldTxs {
			if tx.BoardingTxid == u.Txid {
				found = true
				if tx.CreatedAt.IsZero() && tx.CreatedAt != u.CreatedAt {
					txsToConfirm = append(txsToConfirm, tx.TransactionKey.String())
				}
				break
			}
		}

		if found {
			continue
		}

		txsToAdd = append(txsToAdd, types.Transaction{
			TransactionKey: types.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      types.TxReceived,
			CreatedAt: u.CreatedAt,
			Hex:       u.Tx,
		})
	}

	return txsToAdd, txsToConfirm, rbfTxs, nil
}

func (a *covenantlessArkClient) sendExpiredBoardingUtxos(
	ctx context.Context, to string,
) (string, error) {
	netParams := utils.ToBitcoinNetwork(a.Network)
	rcvAddr, err := btcutil.DecodeAddress(to, &netParams)
	if err != nil {
		return "", err
	}

	pkscript, err := txscript.PayToAddrScript(rcvAddr)
	if err != nil {
		return "", err
	}

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

	size := updater.Upsbt.UnsignedTx.SerializeSize()
	feeRate, err := a.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}
	feeAmount := uint64(math.Ceil(float64(size)*feeRate) + 50)

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

func (a *covenantlessArkClient) completeUnilateralExit(
	ctx context.Context, to string,
) (string, error) {
	netParams := utils.ToBitcoinNetwork(a.Network)
	rcvAddr, err := btcutil.DecodeAddress(to, &netParams)
	if err != nil {
		return "", err
	}

	pkscript, err := txscript.PayToAddrScript(rcvAddr)
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

	size := updater.Upsbt.UnsignedTx.SerializeSize()
	feeRate, err := a.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}

	feeAmount := uint64(math.Ceil(float64(size)*feeRate) + 50)

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

func (a *covenantlessArkClient) selectFunds(
	ctx context.Context,
	withExpiryCoinselect bool,
	selectRecoverableVtxos bool,
	amount uint64,
) ([]types.Utxo, []client.TapscriptsVtxo, uint64, error) {
	offchainAddrs, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, nil, 0, fmt.Errorf("no offchain addresses found")
	}

	vtxos := make([]client.TapscriptsVtxo, 0)
	opts := &CoinSelectOptions{
		WithExpirySorting:      withExpiryCoinselect,
		SelectRecoverableVtxos: selectRecoverableVtxos,
	}
	spendableVtxos, err := a.getVtxos(ctx, opts)
	if err != nil {
		return nil, nil, 0, err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.ServerPubKey, a.Network)
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
		boardingUtxos, vtxos, amount, a.Dust, withExpiryCoinselect,
	)
}

func (a *covenantlessArkClient) sendOffchain(
	ctx context.Context,
	withExpiryCoinselect bool,
	receivers []Receiver,
	settleOpts ...Option,
) (string, error) {
	options := &SettleOptions{}
	for _, opt := range settleOpts {
		if err := opt(options); err != nil {
			return "", err
		}
	}

	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	expectedServerPubkey := schnorr.SerializePubKey(a.ServerPubKey)
	outputs := make([]client.Output, 0)
	sumOfReceivers := uint64(0)

	// validate receivers and create outputs
	for _, receiver := range receivers {
		rcvAddr, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvServerPubkey := schnorr.SerializePubKey(rcvAddr.Server)

		if !bytes.Equal(expectedServerPubkey, rcvServerPubkey) {
			return "", fmt.Errorf("invalid receiver address '%s': expected server %s, got %s", receiver.To(), hex.EncodeToString(expectedServerPubkey), hex.EncodeToString(rcvServerPubkey))
		}

		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}

		outputs = append(outputs, client.Output{
			Address: receiver.To(),
			Amount:  receiver.Amount(),
		})
		sumOfReceivers += receiver.Amount()
	}

	// coinselect boarding utxos and vtxos
	boardingUtxos, vtxos, changeAmount, err := a.selectFunds(ctx, withExpiryCoinselect, options.SelectRecoverableVtxos, sumOfReceivers)
	if err != nil {
		return "", err
	}

	offchainAddr, _, err := a.wallet.NewAddress(ctx, false)
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

		outputs = append(outputs, client.Output{
			Address: offchainAddr.Address,
			Amount:  amount,
		})
	}

	// add change output if any
	if changeAmount > 0 {
		outputs = append(outputs, client.Output{
			Address: offchainAddr.Address,
			Amount:  changeAmount,
		})
	}

	return a.joinRoundWithRetry(ctx, nil, outputs, *options, vtxos, boardingUtxos)
}

func (a *covenantlessArkClient) makeBIP322Signature(
	inputs []bip322.Input,
	leafProofs []*common.TaprootMerkleProof,
	tapscripts map[string][]string,
	outputs []client.Output,
	musig2Data *tree.Musig2,
) (string, string, error) {
	validAt := time.Now()
	expireAt := validAt.Add(2 * time.Minute).Unix()
	outputsTxOut := make([]*wire.TxOut, 0)
	onchainOutputsIndexes := make([]int, 0)
	inputTapTrees := make([]string, 0)

	for _, input := range inputs {
		outpointStr := input.OutPoint.String()
		tapscripts, ok := tapscripts[outpointStr]
		if !ok {
			return "", "", fmt.Errorf("no tapscripts found for input %s", outpointStr)
		}

		encodedTapTree, err := tree.TapTree(tapscripts).Encode()
		if err != nil {
			return "", "", err
		}

		inputTapTrees = append(inputTapTrees, hex.EncodeToString(encodedTapTree))
	}

	for i, output := range outputs {
		txOut, isOnchain, err := output.ToTxOut()
		if err != nil {
			return "", "", err
		}

		if isOnchain {
			onchainOutputsIndexes = append(onchainOutputsIndexes, i)
		}

		outputsTxOut = append(outputsTxOut, txOut)
	}

	message, err := tree.IntentMessage{
		InputTapTrees:        inputTapTrees,
		OnchainOutputIndexes: onchainOutputsIndexes,
		ExpireAt:             expireAt,
		ValidAt:              validAt.Unix(),
		Musig2Data:           musig2Data,
	}.Encode()
	if err != nil {
		return "", "", err
	}

	proof, err := bip322.New(message, inputs, outputsTxOut)
	if err != nil {
		return "", "", err
	}

	for i, input := range proof.Inputs {
		// BIP322 proof has an additional input using the first vtxo script
		// so we need to use the previous leaf proof for the current input except for the first input
		var leafProof *common.TaprootMerkleProof
		if i == 0 {
			leafProof = leafProofs[0]
		} else {
			leafProof = leafProofs[i-1]
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

	proofTx := psbt.Packet(*proof)

	unsignedProofTx, err := proofTx.B64Encode()
	if err != nil {
		return "", "", err
	}

	signedTx, err := a.wallet.SignTransaction(context.Background(), a.explorer, unsignedProofTx)
	if err != nil {
		return "", "", err
	}

	signedProofTx, err := psbt.NewFromRawBytes(strings.NewReader(signedTx), true)
	if err != nil {
		return "", "", err
	}

	proof = (*bip322.FullProof)(signedProofTx)

	sig, err := proof.Signature()
	if err != nil {
		return "", "", err
	}

	encodedSig, err := sig.Encode()
	if err != nil {
		return "", "", err
	}

	return encodedSig, message, nil
}

func (a *covenantlessArkClient) addInputs(
	ctx context.Context,
	updater *psbt.Updater,
	utxos []types.Utxo,
) error {
	// TODO works only with single-key wallet
	offchain, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return err
	}

	vtxoScript, err := tree.ParseVtxoScript(offchain.Tapscripts)
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

func (a *covenantlessArkClient) joinRoundWithRetry(
	ctx context.Context, notes []string, outputs []client.Output, options SettleOptions,
	selectedCoins []client.TapscriptsVtxo, selectedBoardingCoins []types.Utxo,
) (string, error) {
	inputs, exitLeaves, tapscripts, err := toBIP322Inputs(selectedBoardingCoins, selectedCoins)
	if err != nil {
		return "", err
	}

	signerSessions, signerPubKeys, signingType, err := a.handleOptions(options, inputs, notes)
	if err != nil {
		return "", err
	}

	musig2Data := &tree.Musig2{
		CosignersPublicKeys: signerPubKeys,
		SigningType:         signingType,
	}

	var bip322Signature string
	var bip322Message string

	if len(inputs) > 0 {
		bip322Signature, bip322Message, err = a.makeBIP322Signature(
			inputs, exitLeaves, tapscripts,
			outputs, musig2Data,
		)
		if err != nil {
			return "", err
		}
	}

	maxRetry := 3
	retryCount := 0
	var roundErr error
	for retryCount < maxRetry {
		var requestID string
		var err error

		if len(inputs) > 0 {
			requestID, err = a.client.RegisterIntent(
				ctx, bip322Signature, bip322Message,
			)
			if err != nil {
				return "", err
			}
		}

		if len(notes) > 0 {
			if len(requestID) > 0 {
				return "", fmt.Errorf("cannot register notes and inputs at the same time")
			}

			requestID, err = a.client.RegisterNotesForNextRound(
				ctx, notes,
			)
			if err != nil {
				return "", err
			}

			if err := a.client.RegisterOutputsForNextRound(
				ctx, requestID, outputs, musig2Data,
			); err != nil {
				return "", err
			}
		}

		log.Infof("registered inputs and outputs with request id: %s", requestID)

		roundTxID, err := a.handleRoundStream(
			ctx, requestID, selectedCoins, selectedBoardingCoins, outputs, signerSessions, options.EventsCh,
		)
		if err != nil {
			log.WithError(err).Warn("round failed, retrying...")
			retryCount++
			time.Sleep(100 * time.Millisecond)
			roundErr = err
			continue
		}

		return roundTxID, nil
	}

	return "", fmt.Errorf("reached max atttempt of retries, last round error: %s", roundErr)
}

func (a *covenantlessArkClient) handleRoundStream(
	ctx context.Context,
	requestID string,
	vtxos []client.TapscriptsVtxo,
	boardingUtxos []types.Utxo,
	receivers []client.Output,
	signerSessions []tree.SignerSession,
	replayEventsCh chan<- client.RoundEvent,
) (string, error) {
	round, err := a.client.GetRound(ctx, "")
	if err != nil {
		return "", err
	}

	eventsCh, close, err := a.client.GetEventStream(ctx, requestID)
	if err != nil {
		if errors.Is(err, io.EOF) {
			close()
			return "", fmt.Errorf("connection closed by server")
		}
		return "", err
	}

	var pingStop func()
	for pingStop == nil {
		pingStop = a.ping(ctx, requestID)
	}

	defer func() {
		pingStop()
		close()
	}()

	vtxosToSign := make([]client.TapscriptsVtxo, 0)
	for _, vtxo := range vtxos {
		if !vtxo.IsRecoverable() {
			// recoverable vtxos don't need to sign a forfeit tx
			vtxosToSign = append(vtxosToSign, vtxo)
		}
	}

	const (
		start = iota
		roundSigningStarted
		roundSigningNoncesGenerated
		roundFinalization
	)

	step := start
	hasOffchainOutput := false
	for _, receiver := range receivers {
		if _, err := common.DecodeAddress(receiver.Address); err == nil {
			hasOffchainOutput = true
			break
		}
	}

	if !hasOffchainOutput {
		// if none of the outputs are offchain, we should skip the vtxo tree signing steps
		step = roundSigningNoncesGenerated
	}

	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("context done %s", ctx.Err())
		case notify := <-eventsCh:

			if notify.Err != nil {
				return "", notify.Err
			}
			if replayEventsCh != nil {
				go func() {
					replayEventsCh <- notify.Event
				}()
			}
			switch event := notify.Event; event.(type) {
			case client.RoundFinalizedEvent:
				if step != roundFinalization {
					continue
				}
				log.Infof("round completed %s", event.(client.RoundFinalizedEvent).Txid)
				return event.(client.RoundFinalizedEvent).Txid, nil
			case client.RoundFailedEvent:
				if event.(client.RoundFailedEvent).ID == round.ID {
					return "", fmt.Errorf("round failed: %s", event.(client.RoundFailedEvent).Reason)
				}
				continue
			case client.RoundSigningStartedEvent:
				pingStop()
				if step != start {
					continue
				}
				log.Info("a round signing started")
				skipped, err := a.handleRoundSigningStarted(
					ctx, signerSessions, event.(client.RoundSigningStartedEvent),
				)
				if err != nil {
					return "", err
				}
				if !skipped {
					step++
				}
				continue
			case client.RoundSigningNoncesGeneratedEvent:
				if step != roundSigningStarted {
					continue
				}
				pingStop()
				log.Info("round combined nonces generated")
				if err := a.handleRoundSigningNoncesGenerated(
					ctx, event.(client.RoundSigningNoncesGeneratedEvent), signerSessions,
				); err != nil {
					return "", err
				}
				step++
				continue
			case client.RoundFinalizationEvent:
				if step != roundSigningNoncesGenerated {
					continue
				}
				pingStop()
				log.Info("a round finalization started")

				signedForfeitTxs, signedRoundTx, err := a.handleRoundFinalization(
					ctx, event.(client.RoundFinalizationEvent), vtxosToSign, boardingUtxos, receivers,
				)
				if err != nil {
					return "", err
				}

				if len(signedForfeitTxs) <= 0 && len(vtxosToSign) > 0 {
					log.Info("no forfeit txs to sign, waiting for the next round")
					continue
				}

				log.Info("submitting forfeit transactions... ")
				if err := a.client.SubmitSignedForfeitTxs(ctx, signedForfeitTxs, signedRoundTx); err != nil {
					return "", err
				}

				log.Info("done.")
				log.Info("waiting for round finalization...")
				step++
				continue
			}
		}
	}
}

func (a *covenantlessArkClient) handleRoundSigningStarted(
	ctx context.Context, signerSessions []tree.SignerSession, event client.RoundSigningStartedEvent,
) (bool, error) {
	foundPubkeys := make([]string, 0, len(signerSessions))
	for _, session := range signerSessions {
		myPubkey := session.GetPublicKey()
		for _, cosigner := range event.CosignersPubkeys {
			if cosigner == myPubkey {
				foundPubkeys = append(foundPubkeys, myPubkey)
				break
			}
		}
	}

	if len(foundPubkeys) <= 0 {
		return true, nil
	}

	if len(foundPubkeys) != len(signerSessions) {
		return false, fmt.Errorf("not all signers found in cosigner list")
	}

	sweepClosure := tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{PubKeys: []*secp256k1.PublicKey{a.ServerPubKey}},
		Locktime:        a.VtxoTreeExpiry,
	}

	script, err := sweepClosure.Script()
	if err != nil {
		return false, err
	}

	roundTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedRoundTx), true)
	if err != nil {
		return false, err
	}

	sharedOutput := roundTx.UnsignedTx.TxOut[0]
	sharedOutputValue := sharedOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	generateAndSendNonces := func(session tree.SignerSession) error {
		if err := session.Init(root.CloneBytes(), sharedOutputValue, event.UnsignedTree); err != nil {
			return err
		}

		nonces, err := session.GetNonces()
		if err != nil {
			return err
		}

		return a.client.SubmitTreeNonces(ctx, event.ID, session.GetPublicKey(), nonces)
	}

	errChan := make(chan error, len(signerSessions))
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(len(signerSessions))

	for _, session := range signerSessions {
		go func(session tree.SignerSession) {
			defer waitGroup.Done()
			if err := generateAndSendNonces(session); err != nil {
				errChan <- err
			}
		}(session)
	}

	waitGroup.Wait()

	close(errChan)

	for err := range errChan {
		if err != nil {
			return false, err
		}
	}

	return false, nil
}

func (a *covenantlessArkClient) handleRoundSigningNoncesGenerated(
	ctx context.Context,
	event client.RoundSigningNoncesGeneratedEvent,
	signerSessions []tree.SignerSession,
) error {
	if len(signerSessions) <= 0 {
		return fmt.Errorf("tree signer session not set")
	}

	sign := func(session tree.SignerSession) error {
		session.SetAggregatedNonces(event.Nonces)

		sigs, err := session.Sign()
		if err != nil {
			return err
		}

		return a.client.SubmitTreeSignatures(
			ctx,
			event.ID,
			session.GetPublicKey(),
			sigs,
		)
	}

	errChan := make(chan error, len(signerSessions))
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(len(signerSessions))

	for _, session := range signerSessions {
		go func(session tree.SignerSession) {
			defer waitGroup.Done()
			if err := sign(session); err != nil {
				errChan <- err
			}
		}(session)
	}

	waitGroup.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *covenantlessArkClient) handleRoundFinalization(
	ctx context.Context,
	event client.RoundFinalizationEvent,
	vtxos []client.TapscriptsVtxo,
	boardingUtxos []types.Utxo,
	receivers []client.Output,
) ([]string, string, error) {
	if err := a.validateVtxoTree(event, receivers, vtxos); err != nil {
		return nil, "", fmt.Errorf("failed to verify vtxo tree: %s", err)
	}

	var forfeits []string

	if len(vtxos) > 0 {
		signedForfeits, err := a.createAndSignForfeits(
			ctx,
			vtxos, event.Connectors.Leaves(),
			event.ConnectorsIndex, event.MinRelayFeeRate,
		)
		if err != nil {
			return nil, "", err
		}

		forfeits = signedForfeits
	}

	// if no boarding utxos inputs, we don't need to sign the round transaction
	if len(boardingUtxos) <= 0 {
		return forfeits, "", nil
	}

	roundPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
	if err != nil {
		return nil, "", err
	}

	for _, boardingUtxo := range boardingUtxos {
		boardingVtxoScript, err := tree.ParseVtxoScript(boardingUtxo.Tapscripts)
		if err != nil {
			return nil, "", err
		}

		// add tapscript leaf
		forfeitClosures := boardingVtxoScript.ForfeitClosures()
		if len(forfeitClosures) <= 0 {
			return nil, "", fmt.Errorf("no forfeit closures found")
		}

		forfeitClosure := forfeitClosures[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, "", err
		}

		_, taprootTree, err := boardingVtxoScript.TapTree()
		if err != nil {
			return nil, "", err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		forfeitProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, "", fmt.Errorf("failed to get taproot merkle proof for boarding utxo: %s", err)
		}

		tapscript := &psbt.TaprootTapLeafScript{
			ControlBlock: forfeitProof.ControlBlock,
			Script:       forfeitProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		for i := range roundPtx.Inputs {
			previousOutpoint := roundPtx.UnsignedTx.TxIn[i].PreviousOutPoint

			if boardingUtxo.Txid == previousOutpoint.Hash.String() && boardingUtxo.VOut == previousOutpoint.Index {
				roundPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapscript}
				break
			}
		}
	}

	b64, err := roundPtx.B64Encode()
	if err != nil {
		return nil, "", err
	}

	signedRoundTx, err := a.wallet.SignTransaction(ctx, a.explorer, b64)
	if err != nil {
		return nil, "", err
	}

	return forfeits, signedRoundTx, nil
}

func (a *covenantlessArkClient) validateVtxoTree(
	event client.RoundFinalizationEvent, receivers []client.Output, vtxosInput []client.TapscriptsVtxo,
) error {
	roundTx := event.Tx
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(roundTx), true)
	if err != nil {
		return err
	}

	if !utils.IsOnchainOnly(receivers) {
		if err := tree.ValidateVtxoTree(
			event.Tree, roundTx, a.ServerPubKey, a.VtxoTreeExpiry,
		); err != nil {
			return err
		}
	}

	if err := a.validateReceivers(
		ptx, receivers, event.Tree,
	); err != nil {
		return err
	}

	if len(vtxosInput) > 0 {
		root, err := event.Connectors.Root()
		if err != nil {
			return err
		}

		getTxID := func(b64 string) string {
			tx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
			if err != nil {
				return ""
			}

			return tx.UnsignedTx.TxID()
		}

		if root.ParentTxid != getTxID(roundTx) {
			return fmt.Errorf("root's parent txid is not the same as the round txid: %s != %s", root.ParentTxid, getTxID(roundTx))
		}

		if err := event.Connectors.Validate(getTxID); err != nil {
			return err
		}

		if len(event.ConnectorsIndex) == 0 {
			return fmt.Errorf("empty connectors index")
		}

		for _, vtxo := range vtxosInput {
			if _, ok := event.ConnectorsIndex[vtxo.String()]; !ok {
				return fmt.Errorf("missing connector index for vtxo %s", vtxo.String())
			}
		}
	}

	return nil
}

func (a *covenantlessArkClient) validateReceivers(
	ptx *psbt.Packet,
	receivers []client.Output,
	vtxoTree tree.TxTree,
) error {
	netParams := utils.ToBitcoinNetwork(a.Network)
	for _, receiver := range receivers {
		isOnChain, onchainScript, err := utils.ParseBitcoinAddress(
			receiver.Address, netParams,
		)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s err = %s", receiver.Address, err)
		}

		if isOnChain {
			if err := a.validateOnChainReceiver(ptx, receiver, onchainScript); err != nil {
				return err
			}
		} else {
			if err := a.validateOffChainReceiver(
				vtxoTree, receiver,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *covenantlessArkClient) validateOnChainReceiver(
	ptx *psbt.Packet,
	receiver client.Output,
	onchainScript []byte,
) error {
	found := false
	for _, output := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(output.PkScript, onchainScript) {
			if output.Value != int64(receiver.Amount) {
				return fmt.Errorf(
					"invalid collaborative exit output amount: got %d, want %d",
					output.Value, receiver.Amount,
				)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("collaborative exit output not found: %s", receiver.Address)
	}
	return nil
}

func (a *covenantlessArkClient) validateOffChainReceiver(
	vtxoTree tree.TxTree,
	receiver client.Output,
) error {
	found := false

	rcvAddr, err := common.DecodeAddress(receiver.Address)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(rcvAddr.VtxoTapKey)

	leaves := vtxoTree.Leaves()
	for _, leaf := range leaves {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(leaf.Tx), true)
		if err != nil {
			return err
		}

		for _, output := range tx.UnsignedTx.TxOut {
			if len(output.PkScript) == 0 {
				continue
			}

			if bytes.Equal(output.PkScript[2:], vtxoTapKey) {
				if output.Value != int64(receiver.Amount) {
					continue
				}

				found = true
				break
			}
		}

		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf(
			"off-chain send output not found: %s", receiver.Address,
		)
	}

	return nil
}

func (a *covenantlessArkClient) createAndSignForfeits(
	ctx context.Context,
	vtxosToSign []client.TapscriptsVtxo,
	connectorsTxs []tree.Node,
	connectorsIndex map[string]client.Outpoint,
	feeRate chainfee.SatPerKVByte,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(a.ForfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := txscript.PayToAddrScript(parsedForfeitAddr)
	if err != nil {
		return nil, err
	}

	parsedScript, err := txscript.ParsePkScript(forfeitPkScript)
	if err != nil {
		return nil, err
	}

	signedForfeits := make([]string, 0, len(vtxosToSign))

	for _, vtxo := range vtxosToSign {
		connectorOutpoint := connectorsIndex[vtxo.String()]

		var connector *wire.TxOut
		for _, node := range connectorsTxs {
			if node.Txid == connectorOutpoint.Txid {
				tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
				if err != nil {
					return nil, err
				}
				if connectorOutpoint.VOut >= uint32(len(tx.UnsignedTx.TxOut)) {
					return nil, fmt.Errorf("connector index out of bounds: %d >= %d", connectorOutpoint.VOut, len(tx.UnsignedTx.TxOut))
				}
				connector = tx.UnsignedTx.TxOut[connectorOutpoint.VOut]
				break
			}
		}

		if connector == nil {
			return nil, fmt.Errorf("connector not found for vtxo %s", vtxo.String())
		}

		vtxoScript, err := tree.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		vtxoOutputScript, err := common.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, err
		}

		vtxoInput := &wire.OutPoint{
			Hash:  *vtxoTxHash,
			Index: vtxo.VOut,
		}

		forfeitClosures := vtxoScript.ForfeitClosures()
		if len(forfeitClosures) <= 0 {
			return nil, fmt.Errorf("no forfeit closures found")
		}

		forfeitClosure := forfeitClosures[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		leafProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, err
		}

		tapscript := psbt.TaprootTapLeafScript{
			ControlBlock: leafProof.ControlBlock,
			Script:       leafProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return nil, err
		}

		feeAmount, err := common.ComputeForfeitTxFee(
			feeRate,
			&waddrmgr.Tapscript{
				RevealedScript: leafProof.Script,
				ControlBlock:   ctrlBlock,
			},
			forfeitClosure.WitnessSize(),
			parsedScript.Class(),
		)
		if err != nil {
			return nil, err
		}

		vtxoLocktime := common.AbsoluteLocktime(0)
		if cltv, ok := forfeitClosure.(*tree.CLTVMultisigClosure); ok {
			vtxoLocktime = cltv.Locktime
		}

		connectorOutpointHash, err := chainhash.NewHashFromStr(connectorOutpoint.Txid)
		if err != nil {
			return nil, err
		}

		forfeit, err := tree.BuildForfeitTx(
			&wire.OutPoint{
				Hash:  *connectorOutpointHash,
				Index: connectorOutpoint.VOut,
			},
			vtxoInput,
			vtxo.Amount,
			uint64(connector.Value),
			feeAmount,
			vtxoOutputScript,
			connector.PkScript,
			forfeitPkScript,
			uint32(vtxoLocktime),
		)
		if err != nil {
			return nil, err
		}

		forfeit.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&tapscript}

		b64, err := forfeit.B64Encode()
		if err != nil {
			return nil, err
		}

		signedForfeit, err := a.wallet.SignTransaction(ctx, a.explorer, b64)
		if err != nil {
			return nil, err
		}

		signedForfeits = append(signedForfeits, signedForfeit)
	}

	return signedForfeits, nil
}

func (a *covenantlessArkClient) getMatureUtxos(
	ctx context.Context,
) ([]types.Utxo, error) {
	_, _, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
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

func (a *covenantlessArkClient) getRedeemBranches(
	ctx context.Context, vtxos []client.Vtxo,
) (map[string]*redemption.CovenantlessRedeemBranch, error) {
	vtxoTrees := make(map[string]tree.TxTree, 0)
	redeemBranches := make(map[string]*redemption.CovenantlessRedeemBranch, 0)

	for i := range vtxos {
		vtxo := vtxos[i]

		// TODO: handle exit for pending changes
		if vtxo.RedeemTx != "" {
			continue
		}

		if _, ok := vtxoTrees[vtxo.RoundTxid]; !ok {
			round, err := a.client.GetRound(ctx, vtxo.RoundTxid)
			if err != nil {
				return nil, err
			}

			vtxoTrees[vtxo.RoundTxid] = round.Tree
		}

		redeemBranch, err := redemption.NewRedeemBranch(
			a.explorer, vtxoTrees[vtxo.RoundTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}

func (a *covenantlessArkClient) getOffchainBalance(
	ctx context.Context, computeVtxoExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)
	opts := &CoinSelectOptions{
		WithExpirySorting: computeVtxoExpiration,
	}
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

func (a *covenantlessArkClient) getAllBoardingUtxos(ctx context.Context) ([]types.Utxo, map[string]struct{}, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, err
	}

	utxos := []types.Utxo{}
	ignoreVtxos := make(map[string]struct{}, 0)
	for _, addr := range boardingAddrs {
		txs, err := a.explorer.GetTxs(addr.Address)
		if err != nil {
			return nil, nil, err
		}
		for _, tx := range txs {
			for i, vout := range tx.Vout {
				var spent bool
				if vout.Address == addr.Address {
					txHex, err := a.explorer.GetTxHex(tx.Txid)
					if err != nil {
						return nil, nil, err
					}
					spentStatuses, err := a.explorer.GetTxOutspends(tx.Txid)
					if err != nil {
						return nil, nil, err
					}
					if s := spentStatuses[i]; s.Spent {
						ignoreVtxos[s.SpentBy] = struct{}{}
						spent = true
					}
					createdAt := time.Time{}
					if tx.Status.Confirmed {
						createdAt = time.Unix(tx.Status.Blocktime, 0)
					}
					utxos = append(utxos, types.Utxo{
						Txid:       tx.Txid,
						VOut:       uint32(i),
						Amount:     vout.Amount,
						CreatedAt:  createdAt,
						Tapscripts: addr.Tapscripts,
						Spent:      spent,
						Tx:         txHex,
					})
				}
			}
		}
	}

	return utxos, ignoreVtxos, nil
}

func (a *covenantlessArkClient) getClaimableBoardingUtxos(
	_ context.Context, boardingAddrs []wallet.TapscriptsAddress, opts *CoinSelectOptions,
) ([]types.Utxo, error) {
	claimable := make([]types.Utxo, 0)
	for _, addr := range boardingAddrs {
		boardingScript, err := tree.ParseVtxoScript(addr.Tapscripts)
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
				utxoOutpoint := client.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}
				found := false
				for _, outpoint := range opts.OutpointsFilter {
					if outpoint.Equals(utxoOutpoint) {
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

func (a *covenantlessArkClient) getExpiredBoardingUtxos(ctx context.Context, opts *CoinSelectOptions) ([]types.Utxo, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	expired := make([]types.Utxo, 0)
	for _, addr := range boardingAddrs {
		boardingScript, err := tree.ParseVtxoScript(addr.Tapscripts)
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
				utxoOutpoint := client.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}
				found := false
				for _, outpoint := range opts.OutpointsFilter {
					if outpoint.Equals(utxoOutpoint) {
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

func (a *covenantlessArkClient) getVtxos(ctx context.Context, opts *CoinSelectOptions) ([]client.Vtxo, error) {
	spendableVtxos, spentVtxos, err := a.ListVtxos(ctx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.OutpointsFilter) > 0 {
		spendableVtxos = filterByOutpoints(spendableVtxos, opts.OutpointsFilter)
		if opts.SelectRecoverableVtxos {
			spentVtxos = filterByOutpoints(spentVtxos, opts.OutpointsFilter)
		}
	}

	recoverableVtxos := make([]client.Vtxo, 0)
	if opts != nil && opts.SelectRecoverableVtxos {
		for _, vtxo := range spentVtxos {
			if vtxo.IsRecoverable() {
				recoverableVtxos = append(recoverableVtxos, vtxo)
			}
		}
	}

	allVtxos := append(recoverableVtxos, spendableVtxos...)

	if opts == nil || !opts.WithExpirySorting {
		return allVtxos, nil
	}

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

	return allVtxos, nil
}

func (a *covenantlessArkClient) getBoardingTxs(
	ctx context.Context,
) ([]types.Transaction, map[string]struct{}, error) {
	allUtxos, ignoreVtxos, err := a.getAllBoardingUtxos(ctx)
	if err != nil {
		return nil, nil, err
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
			Hex:       u.Tx,
		}

		if u.CreatedAt.IsZero() {
			unconfirmedTxs = append(unconfirmedTxs, tx)
			continue
		}
		confirmedTxs = append(confirmedTxs, tx)
	}

	txs := append(unconfirmedTxs, confirmedTxs...)
	return txs, ignoreVtxos, nil
}

func (a *covenantlessArkClient) handleRoundTx(
	ctx context.Context,
	myPubkeys map[string]struct{}, roundTx *client.RoundTransaction,
) error {
	vtxosToAdd := make([]types.Vtxo, 0)
	vtxosToSpend := make([]types.VtxoKey, 0)
	txsToAdd := make([]types.Transaction, 0)
	txsToSettle := make([]string, 0)

	for _, vtxo := range roundTx.SpendableVtxos {
		if _, ok := myPubkeys[vtxo.PubKey]; ok {
			vtxosToAdd = append(vtxosToAdd, types.Vtxo{
				VtxoKey: types.VtxoKey{
					Txid: vtxo.Txid,
					VOut: vtxo.VOut,
				},
				PubKey:    vtxo.PubKey,
				Amount:    vtxo.Amount,
				RoundTxid: vtxo.RoundTxid,
				ExpiresAt: vtxo.ExpiresAt,
				CreatedAt: time.Now(),
			})
		}
	}

	// Check if any of the spent vtxos is ours.
	spentVtxos := make([]types.VtxoKey, 0, len(roundTx.SpentVtxos))
	for _, vtxo := range roundTx.SpentVtxos {
		spentVtxos = append(spentVtxos, types.VtxoKey{
			Txid: vtxo.Txid,
			VOut: vtxo.VOut,
		})
	}
	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, spentVtxos)
	if err != nil {
		return err
	}

	// Check if any of the claimed boarding utxos is ours.
	boardingTxids := make([]string, 0, len(roundTx.ClaimedBoardingUtxos))
	for _, utxo := range roundTx.ClaimedBoardingUtxos {
		boardingTxids = append(boardingTxids, utxo.Txid)
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

	// Add also our pending vtxos settled in this round.
	for _, vtxo := range myVtxos {
		vtxosToSpend = append(vtxosToSpend, vtxo.VtxoKey)
		if !vtxo.Pending {
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
					RoundTxid: roundTx.Txid,
				},
				Amount:    amount,
				Type:      types.TxReceived,
				Settled:   true,
				CreatedAt: time.Now(),
				Hex:       roundTx.Hex,
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
						RoundTxid: roundTx.Txid,
					},
					Amount:    settledBoardingAmount - vtxosToAddAmount,
					Type:      types.TxSent,
					Settled:   true,
					CreatedAt: time.Now(),
					Hex:       roundTx.Hex,
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
						RoundTxid: roundTx.Txid,
					},
					Amount:    amount,
					Type:      types.TxSent,
					Settled:   true,
					CreatedAt: time.Now(),
					Hex:       roundTx.Hex,
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
		count, err := a.store.TransactionStore().SettleTransactions(ctx, txsToSettle)
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
		count, err := a.store.VtxoStore().SpendVtxos(ctx, vtxosToSpend, roundTx.Txid)
		if err != nil {
			return err
		}
		log.Debugf("spent %d vtxo(s)", count)
	}

	return nil
}

func (a *covenantlessArkClient) handleRedeemTx(
	ctx context.Context,
	myPubkeys map[string]struct{}, redeemTx *client.RedeemTransaction,
) error {
	vtxosToAdd := make([]types.Vtxo, 0)
	vtxosToSpend := make([]types.VtxoKey, 0)
	txsToAdd := make([]types.Transaction, 0)

	for _, vtxo := range redeemTx.SpendableVtxos {
		if _, ok := myPubkeys[vtxo.PubKey]; ok {
			vtxosToAdd = append(vtxosToAdd, types.Vtxo{
				VtxoKey: types.VtxoKey{
					Txid: vtxo.Txid,
					VOut: vtxo.VOut,
				},
				PubKey:    vtxo.PubKey,
				Amount:    vtxo.Amount,
				RoundTxid: vtxo.RoundTxid,
				ExpiresAt: vtxo.ExpiresAt,
				CreatedAt: time.Now(),
				RedeemTx:  vtxo.RedeemTx,
				Pending:   vtxo.IsPending,
			})
		}
	}

	// Check if any of the spent vtxos are ours.
	spentVtxos := make([]types.VtxoKey, 0, len(redeemTx.SpentVtxos))
	for _, vtxo := range redeemTx.SpentVtxos {
		spentVtxos = append(spentVtxos, types.VtxoKey{
			Txid: vtxo.Txid,
			VOut: vtxo.VOut,
		})
	}
	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, spentVtxos)
	if err != nil {
		return err
	}
	for _, vtxo := range myVtxos {
		vtxosToSpend = append(vtxosToSpend, vtxo.VtxoKey)
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
					RedeemTxid: redeemTx.Txid,
				},
				Amount:    amount,
				Type:      types.TxReceived,
				CreatedAt: time.Now(),
				Hex:       redeemTx.Hex,
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
				RedeemTxid: redeemTx.Txid,
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
		count, err := a.store.VtxoStore().SpendVtxos(ctx, vtxosToSpend, redeemTx.Txid)
		if err != nil {
			return err
		}
		log.Debugf("spent %d vtxo(s)", count)

		txids := make([]string, 0, len(vtxosToSpend))
		for _, v := range vtxosToSpend {
			txids = append(txids, v.Txid)
		}

		count, err = a.store.TransactionStore().SettleTransactions(ctx, txids)
		if err != nil {
			return err
		}
		log.Debugf("settled %d transaction(s)", count)
	}

	return nil
}

func (a *covenantlessArkClient) handleOptions(
	options SettleOptions, inputs []bip322.Input, notesInputs []string,
) ([]tree.SignerSession, []string, tree.SigningType, error) {
	var signingType tree.SigningType
	if options.SigningType != nil {
		signingType = *options.SigningType
	} else {
		signingType = tree.SignBranch
	}

	sessions := make([]tree.SignerSession, 0)
	sessions = append(sessions, options.ExtraSignerSessions...)

	if !options.WalletSignerDisabled {
		outpoints := make([]client.Outpoint, 0, len(inputs))
		for _, input := range inputs {
			outpoints = append(outpoints, client.Outpoint{
				Txid: input.OutPoint.Hash.String(),
				VOut: uint32(input.OutPoint.Index),
			})
		}

		signerSession, err := a.wallet.NewVtxoTreeSigner(
			context.Background(),
			inputsToDerivationPath(outpoints, notesInputs),
		)
		if err != nil {
			return nil, nil, signingType, err
		}
		sessions = append(sessions, signerSession)
	}

	if len(sessions) == 0 {
		return nil, nil, signingType, fmt.Errorf("no signer sessions")
	}

	signerPubKeys := make([]string, 0)
	for _, session := range sessions {
		signerPubKeys = append(signerPubKeys, session.GetPublicKey())
	}

	return sessions, signerPubKeys, signingType, nil
}

func findVtxosSpent(vtxos []client.Vtxo, id string) []client.Vtxo {
	var result []client.Vtxo
	leftVtxos := make([]client.Vtxo, 0)
	for _, v := range vtxos {
		if v.SpentBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func findVtxosSpentInSettlement(vtxos []client.Vtxo, vtxo client.Vtxo) []client.Vtxo {
	if vtxo.IsPending {
		return nil
	}
	return findVtxosSpent(vtxos, vtxo.RoundTxid)
}

func findVtxosSpentInPayment(vtxos []client.Vtxo, vtxo client.Vtxo) []client.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSpentBy(vtxos []client.Vtxo, spentByTxid string) []client.Vtxo {
	var result []client.Vtxo
	for _, v := range vtxos {
		if !v.IsPending && v.RoundTxid == spentByTxid {
			result = append(result, v)
			break
		}
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func reduceVtxosAmount(vtxos []client.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func getVtxo(usedVtxos []client.Vtxo, spentByVtxos []client.Vtxo) client.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return client.Vtxo{}
}

func vtxosToTxHistory(
	spendable, spent []client.Vtxo, boardingRounds map[string]struct{}, indexerSvc indexer.Indexer,
) ([]types.Transaction, error) {
	txs := make([]types.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx
	vtxosLeftToCheck := append([]client.Vtxo{}, spent...)
	for _, vtxo := range append(spendable, spent...) {
		if _, ok := boardingRounds[vtxo.RoundTxid]; !vtxo.IsPending && ok {
			continue
		}
		settleVtxos := findVtxosSpentInSettlement(vtxosLeftToCheck, vtxo)
		settleAmount := reduceVtxosAmount(settleVtxos)
		if vtxo.Amount <= settleAmount {
			continue // settlement or change, ignore
		}

		spentVtxos := findVtxosSpentInPayment(vtxosLeftToCheck, vtxo)
		spentAmount := reduceVtxosAmount(spentVtxos)
		if vtxo.Amount <= spentAmount {
			continue // settlement or change, ignore
		}

		txKey := types.TransactionKey{
			RoundTxid: vtxo.RoundTxid,
		}
		settled := !vtxo.IsPending
		if vtxo.IsPending {
			txKey = types.TransactionKey{
				RedeemTxid: vtxo.Txid,
			}
			settled = vtxo.SpentBy != ""
		}

		txs = append(txs, types.Transaction{
			TransactionKey: txKey,
			Amount:         vtxo.Amount - settleAmount - spentAmount,
			Type:           types.TxReceived,
			CreatedAt:      vtxo.CreatedAt,
			Settled:        settled,
		})
	}

	// Sendings

	// All "spentBy" vtxos are payments unless:
	// - they are settlements

	// aggregate spent by spentId
	vtxosBySpentBy := make(map[string][]client.Vtxo)
	for _, v := range spent {
		if len(v.SpentBy) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.SpentBy]; !ok {
			vtxosBySpentBy[v.SpentBy] = make([]client.Vtxo, 0)
		}
		vtxosBySpentBy[v.SpentBy] = append(vtxosBySpentBy[v.SpentBy], v)
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
			// send all: fetch the created vtxo (not belong to us) to source
			// creation and expiration timestamps
			opts := &indexer.GetVtxosRequestOption{}
			// nolint:all
			opts.WithOutpoints([]indexer.Outpoint{{Txid: sb, VOut: 0}})
			resp, err := indexerSvc.GetVtxos(context.Background(), *opts)
			if err != nil {
				return nil, err
			}
			vtxo = client.Vtxo{
				Outpoint: client.Outpoint{
					Txid: sb,
					VOut: 0,
				},
				RoundTxid: resp.Vtxos[0].CommitmentTxid,
				ExpiresAt: time.Unix(resp.Vtxos[0].ExpiresAt, 0),
				CreatedAt: time.Unix(resp.Vtxos[0].CreatedAt, 0),
				IsPending: !resp.Vtxos[0].IsLeaf,
			}
		}

		txKey := types.TransactionKey{
			RoundTxid: vtxo.RoundTxid,
		}
		if vtxo.IsPending {
			txKey = types.TransactionKey{
				RedeemTxid: vtxo.Txid,
			}
		}

		txs = append(txs, types.Transaction{
			TransactionKey: txKey,
			Amount:         spentAmount - resultedAmount,
			Type:           types.TxSent,
			CreatedAt:      vtxo.CreatedAt,
			Settled:        true,
		})

	}

	sort.SliceStable(txs, func(i, j int) bool {
		return txs[i].CreatedAt.After(txs[j].CreatedAt)
	})

	return txs, nil
}

type redeemTxInput struct {
	client.TapscriptsVtxo
	ForfeitLeafHash chainhash.Hash
}

func buildRedeemTx(
	vtxos []redeemTxInput,
	receivers []Receiver,
	feeRate chainfee.SatPerVByte,
	extraWitnessSizes map[client.Outpoint]int,
	withZeroFees bool,
) (string, error) {
	if len(vtxos) <= 0 {
		return "", fmt.Errorf("missing vtxos")
	}

	ins := make([]common.VtxoInput, 0, len(vtxos))

	for _, vtxo := range vtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := tree.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", err
		}

		closure, err := tree.DecodeClosure(leafProof.Script)
		if err != nil {
			return "", err
		}

		tapscript := &waddrmgr.Tapscript{
			RevealedScript: leafProof.Script,
			ControlBlock:   ctrlBlock,
		}

		extraWitnessSize := 0
		if size, ok := extraWitnessSizes[client.Outpoint{Txid: vtxo.Txid, VOut: vtxo.VOut}]; ok {
			extraWitnessSize = size
		}

		ins = append(ins, common.VtxoInput{
			Outpoint:           vtxoOutpoint,
			Tapscript:          tapscript,
			Amount:             int64(vtxo.Amount),
			WitnessSize:        closure.WitnessSize(extraWitnessSize),
			RevealedTapscripts: vtxo.Tapscripts,
		})
	}

	fees, err := common.ComputeRedeemTxFee(feeRate.FeePerKVByte(), ins, len(receivers))
	if err != nil {
		return "", err
	}

	if fees >= int64(receivers[len(receivers)-1].Amount()) {
		return "", fmt.Errorf("redeem tx fee is higher than the amount of the change receiver")
	}

	outs := make([]*wire.TxOut, 0, len(receivers))

	for i, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", fmt.Errorf("receiver %d is onchain", i)
		}

		addr, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", err
		}

		newVtxoScript, err := common.P2TRScript(addr.VtxoTapKey)
		if err != nil {
			return "", err
		}

		value := receiver.Amount()
		if !withZeroFees {
			// Deduct the min relay fee from the very last receiver which is supposed
			// to be the change in case it's not a send-all.
			if i == len(receivers)-1 {
				value -= uint64(fees)
			}
		}
		outs = append(outs, &wire.TxOut{
			Value:    int64(value),
			PkScript: newVtxoScript,
		})
	}

	return tree.BuildRedeemTx(ins, outs)
}

func inputsToDerivationPath(inputs []client.Outpoint, notesInputs []string) string {
	// sort arknotes
	slices.SortStableFunc(notesInputs, func(i, j string) int {
		return strings.Compare(i, j)
	})

	// sort outpoints
	slices.SortStableFunc(inputs, func(i, j client.Outpoint) int {
		txidCmp := strings.Compare(i.Txid, j.Txid)
		if txidCmp != 0 {
			return txidCmp
		}
		return int(i.VOut - j.VOut)
	})

	// serialize outpoints and arknotes

	var buf bytes.Buffer

	for _, input := range inputs {
		buf.WriteString(input.Txid)
		buf.WriteString(strconv.Itoa(int(input.VOut)))
	}

	for _, note := range notesInputs {
		buf.WriteString(note)
	}

	// hash the serialized data
	hash := sha256.Sum256(buf.Bytes())

	// convert hash to bip32 derivation path
	// split the 32-byte hash into 8 uint32 values (4 bytes each)
	path := "m"
	for i := 0; i < 8; i++ {
		// Convert 4 bytes to uint32 using big-endian encoding
		segment := binary.BigEndian.Uint32(hash[i*4 : (i+1)*4])
		path += fmt.Sprintf("/%d'", segment)
	}

	return path
}

func extractExitPath(tapscripts []string) ([]byte, *common.TaprootMerkleProof, uint32, error) {
	vtxoScript, err := tree.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, 0, err
	}

	exitClosures := vtxoScript.ExitClosures()
	if len(exitClosures) <= 0 {
		return nil, nil, 0, fmt.Errorf("no exit closures found")
	}

	exitClosure := exitClosures[0].(*tree.CSVMultisigClosure)

	exitScript, err := exitClosure.Script()
	if err != nil {
		return nil, nil, 0, err
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, 0, err
	}

	exitLeaf := txscript.NewBaseTapLeaf(exitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(exitLeaf.TapHash())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get taproot merkle proof: %s", err)
	}

	sequence, err := common.BIP68Sequence(exitClosure.Locktime)
	if err != nil {
		return nil, nil, 0, err
	}

	pkScript, err := common.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, 0, err
	}

	return pkScript, leafProof, sequence, nil
}

func toBIP322Inputs(boardingUtxos []types.Utxo, vtxos []client.TapscriptsVtxo) ([]bip322.Input, []*common.TaprootMerkleProof, map[string][]string, error) {
	inputs := make([]bip322.Input, 0, len(boardingUtxos)+len(vtxos))
	exitLeaves := make([]*common.TaprootMerkleProof, 0, len(boardingUtxos)+len(vtxos))
	tapscripts := make(map[string][]string)
	for _, coin := range vtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		tapscripts[outpoint.String()] = coin.Tapscripts

		pkScript, leafProof, vtxoSequence, err := extractExitPath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		exitLeaves = append(exitLeaves, leafProof)

		inputs = append(inputs, bip322.Input{
			OutPoint: outpoint,
			Sequence: vtxoSequence,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})
	}

	for _, coin := range boardingUtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		tapscripts[outpoint.String()] = coin.Tapscripts

		pkScript, leafProof, vtxoSequence, err := extractExitPath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		exitLeaves = append(exitLeaves, leafProof)

		inputs = append(inputs, bip322.Input{
			OutPoint: outpoint,
			Sequence: vtxoSequence,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})
	}

	return inputs, exitLeaves, tapscripts, nil
}
func getOffchainBalanceDetails(amountByExpiration map[int64]uint64) (int64, []VtxoDetails) {
	nextExpiration := int64(0)
	details := make([]VtxoDetails, 0)
	for timestamp, amount := range amountByExpiration {
		if nextExpiration == 0 || timestamp < nextExpiration {
			nextExpiration = timestamp
		}

		fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
		details = append(
			details,
			VtxoDetails{
				ExpiryTime: fancyTime,
				Amount:     amount,
			},
		)
	}
	return nextExpiration, details
}

func getFancyTimeExpiration(nextExpiration int64) string {
	if nextExpiration == 0 {
		return ""
	}

	fancyTimeExpiration := ""
	t := time.Unix(nextExpiration, 0)
	if t.Before(time.Now().Add(48 * time.Hour)) {
		// print the duration instead of the absolute time
		until := time.Until(t)
		seconds := math.Abs(until.Seconds())
		minutes := math.Abs(until.Minutes())
		hours := math.Abs(until.Hours())

		if hours < 1 {
			if minutes < 1 {
				fancyTimeExpiration = fmt.Sprintf("%d seconds", int(seconds))
			} else {
				fancyTimeExpiration = fmt.Sprintf("%d minutes", int(minutes))
			}
		} else {
			fancyTimeExpiration = fmt.Sprintf("%d hours", int(hours))
		}
	} else {
		fancyTimeExpiration = t.Format(time.RFC3339)
	}
	return fancyTimeExpiration
}

func toTypesVtxo(src client.Vtxo) types.Vtxo {
	return types.Vtxo{
		VtxoKey: types.VtxoKey{
			Txid: src.Txid,
			VOut: src.VOut,
		},
		PubKey:    src.PubKey,
		Amount:    src.Amount,
		RoundTxid: src.RoundTxid,
		ExpiresAt: src.ExpiresAt,
		CreatedAt: src.CreatedAt,
	}
}
