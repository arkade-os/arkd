package arksdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
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
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	log "github.com/sirupsen/logrus"
)

var (
	ErrWaitingForConfirmation = fmt.Errorf("waiting for confirmation(s), please retry later")
)

// SettleOptions is only available for covenantless clients
// it allows to customize the vtxo signing process
type SettleOptions struct {
	ExtraSignerSessions    []tree.SignerSession
	WalletSignerDisabled   bool
	SelectRecoverableVtxos bool

	CancelCh <-chan struct{}
	EventsCh chan<- any
}

// name alias, sub-dust vtxos are recoverable vtxos
var WithSubDustVtxos = WithRecoverableVtxos

func WithRecoverableVtxos(o any) error {
	opts, err := checkSettleOptionsType(o)
	if err != nil {
		return err
	}

	opts.SelectRecoverableVtxos = true
	return nil
}

func WithEventsCh(ch chan<- any) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.EventsCh = ch
		return nil
	}
}

// WithoutWalletSigner disables the wallet signer
func WithoutWalletSigner(o any) error {
	opts, err := checkSettleOptionsType(o)
	if err != nil {
		return err
	}

	opts.WalletSignerDisabled = true
	return nil
}

// WithExtraSigner allows to use a set of custom signer for the vtxo tree signing process
func WithExtraSigner(signerSessions ...tree.SignerSession) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		if len(signerSessions) == 0 {
			return fmt.Errorf("no signer sessions provided")
		}

		opts.ExtraSignerSessions = signerSessions
		return nil
	}
}

// WithCancelCh allows to cancel the settlement process
func WithCancelCh(ch <-chan struct{}) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.CancelCh = ch
		return nil
	}
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

	explorerSvc, err := getExplorer(cfgData.ExplorerURL, cfgData.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	indexerSvc, err := getIndexer(cfgData.ClientType, cfgData.ServerUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to setup indexer: %s", err)
	}

	walletSvc, err := getWallet(
		sdkStore.ConfigStore(),
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
			go covenantlessClient.listenForBoardingTxs(txStreamCtx)
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

	explorerSvc, err := getExplorer(cfgData.ExplorerURL, cfgData.Network.Name)
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
			go covenantlessClient.listenForBoardingTxs(txStreamCtx)
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
			go a.listenForBoardingTxs(txStreamCtx)
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
			go a.listenForBoardingTxs(txStreamCtx)
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

	onchainAddrs, offchainAddrs, boardingAddrs, redeemAddrs, err := a.wallet.GetAddresses(ctx)
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

	const nbWorkers = 4
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

		go func() {
			defer wg.Done()
			totalOnchainBalance := uint64(0)
			for _, addr := range onchainAddrs {
				balance, err := a.explorer.GetBalance(addr)
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

func (a *covenantlessArkClient) OnboardAgainAllExpiredBoardings(
	ctx context.Context,
) (string, error) {
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
	ctx context.Context, withExpiryCoinselect bool, receivers []types.Receiver,
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

	expectedServerPubkey := schnorr.SerializePubKey(a.ServerPubKey)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", fmt.Errorf("all receiver addresses must be offchain addresses")
		}

		addr, err := common.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvServerPubkey := schnorr.SerializePubKey(addr.Server)
		if !bytes.Equal(expectedServerPubkey, rcvServerPubkey) {
			return "", fmt.Errorf(
				"invalid receiver address '%s': expected server %x, got %x",
				receiver.To, expectedServerPubkey, rcvServerPubkey,
			)
		}

		sumOfReceivers += receiver.Amount
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
		receivers = append(receivers, types.Receiver{
			To: offchainAddrs[0].Address, Amount: changeAmount,
		})
	}

	inputs := make([]arkTxInput, 0, len(selectedCoins))

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

		inputs = append(inputs, arkTxInput{
			coin,
			forfeitLeaf.TapHash(),
		})
	}

	checkpointExitScript := &tree.CSVMultisigClosure{
		Locktime: a.UnilateralExitDelay,
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{a.ServerPubKey},
		},
	}

	arkTx, checkpointTxs, err := buildOffchainTx(inputs, receivers, checkpointExitScript, a.Dust)
	if err != nil {
		return "", err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx)
	if err != nil {
		return "", err
	}

	// TODO store signed ark tx client side ?
	arkTxid, _, signedCheckpointTxs, err := a.client.SubmitTx(ctx, signedArkTx, checkpointTxs)
	if err != nil {
		return "", err
	}

	finalCheckpoints := make([]string, 0, len(signedCheckpointTxs))

	for _, checkpoint := range signedCheckpointTxs {
		signedTx, err := a.wallet.SignTransaction(ctx, a.explorer, checkpoint)
		if err != nil {
			return "", nil
		}
		finalCheckpoints = append(finalCheckpoints, signedTx)
	}

	if err = a.client.FinalizeTx(ctx, arkTxid, finalCheckpoints); err != nil {
		return "", err
	}

	return arkTxid, nil
}

func (a *covenantlessArkClient) RedeemNotes(
	ctx context.Context, notes []string, opts ...Option,
) (string, error) {
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

	isWaitingForConfirmation := false

	for _, branch := range redeemBranches {
		nextTx, err := branch.NextRedeemTx()
		if err != nil {
			if err, ok := err.(redemption.ErrPendingConfirmation); ok {
				// the branch tx is in the mempool, we must wait for confirmation
				// print only, do not make the function to fail
				// continue to try other branches
				log.Info(err.Error())
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

		log.Infof("package broadcasted: %s", packageResponse)
	}

	return nil
}

// bumpAnchorTx builds and signs a transaction bumping the fees for a given tx with P2A output.
// Makes use of the onchain P2TR account to select UTXOs to pay fees for parent.
func (a *covenantlessArkClient) bumpAnchorTx(
	ctx context.Context, parent *wire.MsgTx,
) (string, error) {
	anchor, err := tree.FindAnchorOutpoint(parent)
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
	amountToSelect := int64(fees) - tree.ANCHOR_VALUE
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

	addr, err := btcutil.DecodeAddress(newAddr, nil)
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

	ptx.Inputs[0].WitnessUtxo = tree.AnchorOutput()

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

	childTx, err := tree.ExtractWithAnchors(signedPtx)
	if err != nil {
		return "", err
	}

	var serializedTx bytes.Buffer
	if err := childTx.Serialize(&serializedTx); err != nil {
		return "", err
	}

	return hex.EncodeToString(serializedTx.Bytes()), nil
}

func (a *covenantlessArkClient) CompleteUnilateralExit(
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

func (a *covenantlessArkClient) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, computeVtxoExpiry bool, opts ...Option,
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

	receivers := []types.Receiver{{To: addr, Amount: amount}}

	boardingUtxos, vtxos, changeAmount, err := a.selectFunds(
		ctx, computeVtxoExpiry, options.SelectRecoverableVtxos, amount,
	)
	if err != nil {
		return "", err
	}

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

	return a.fetchTxHistory(ctx)
}

func (a *covenantlessArkClient) RegisterIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
	outputs []types.Receiver, cosignersPublicKeys []string,
) (string, error) {
	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return "", err
	}

	inputs, exitLeaves, tapscripts, notesWitnesses, err := toBIP322Inputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return "", err
	}

	bip322Signature, bip322Message, err := a.makeRegisterIntentBIP322Signature(
		inputs, exitLeaves, tapscripts,
		outputs, cosignersPublicKeys, notesWitnesses,
	)
	if err != nil {
		return "", err
	}

	return a.client.RegisterIntent(ctx, bip322Signature, bip322Message)
}

func (a *covenantlessArkClient) DeleteIntent(
	ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
) error {
	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, vtxos)
	if err != nil {
		return err
	}

	inputs, exitLeaves, _, notesWitnesses, err := toBIP322Inputs(
		boardingUtxos, vtxosWithTapscripts, notes,
	)
	if err != nil {
		return err
	}

	bip322Signature, bip322Message, err := a.makeDeleteIntentBIP322Signature(
		inputs, exitLeaves, notesWitnesses,
	)
	if err != nil {
		return err
	}

	return a.client.DeleteIntent(ctx, bip322Signature, bip322Message)
}

func (a *covenantlessArkClient) listenForArkTxs(ctx context.Context) {
	eventChan, closeFunc, err := a.client.GetTransactionsStream(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get transaction stream")
		return
	}
	defer closeFunc()

	ctxBg := context.Background()
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

			_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
			if err != nil {
				log.WithError(err).Error("failed to get offchain addresses")
				continue
			}

			myScripts := make(map[string]struct{})
			for _, addr := range offchainAddrs {
				// nolint
				decoded, _ := common.DecodeAddressV0(addr.Address)
				// nolint
				script, _ := common.P2TRScript(decoded.VtxoTapKey)
				myScripts[hex.EncodeToString(script)] = struct{}{}
			}

			if event.CommitmentTx != nil {
				if err := a.handleCommitmentTx(ctxBg, myScripts, event.CommitmentTx); err != nil {
					log.WithError(err).Error("failed to process commitment tx")
					continue
				}
			}

			if event.ArkTx != nil {
				if err := a.handleArkTx(ctxBg, myScripts, event.ArkTx); err != nil {
					log.WithError(err).Error("failed to process ark tx")
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
	history, err := a.fetchTxHistory(ctx)
	if err != nil {
		return err
	}
	spendableVtxos, spentVtxos, err := a.ListVtxos(ctx)
	if err != nil {
		return err
	}

	if err := a.refreshTxDb(history); err != nil {
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

func (a *covenantlessArkClient) refreshVtxoDb(spendableVtxos, spentVtxos []types.Vtxo) error {
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
		if _, ok := oldSpendableVtxoMap[vtxo.VtxoKey]; !ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	vtxosToReplace := make([]types.Vtxo, 0, len(spentVtxos))
	for _, vtxo := range spentVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.VtxoKey]; ok {
			vtxosToReplace = append(vtxosToReplace, vtxo)
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

func (a *covenantlessArkClient) listenForBoardingTxs(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_, _, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
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
		if tx.BoardingTxid != "" && tx.CreatedAt.IsZero() {
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

func (a *covenantlessArkClient) selectFunds(
	ctx context.Context, computeVtxoExpiry bool, selectRecoverableVtxos bool, amount uint64,
) ([]types.Utxo, []client.TapscriptsVtxo, uint64, error) {
	_, offchainAddrs, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, nil, 0, fmt.Errorf("no offchain addresses found")
	}

	vtxos := make([]client.TapscriptsVtxo, 0)
	opts := &CoinSelectOptions{
		WithExpirySorting:      computeVtxoExpiry,
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
		boardingUtxos, vtxos, amount, a.Dust, computeVtxoExpiry,
	)
}

func (a *covenantlessArkClient) sendOffchain(
	ctx context.Context, computeVtxoExpiry bool, receivers []types.Receiver, settleOpts ...Option,
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
	outputs := make([]types.Receiver, 0)
	sumOfReceivers := uint64(0)

	// validate receivers and create outputs
	for _, receiver := range receivers {
		rcvAddr, err := common.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvServerPubkey := schnorr.SerializePubKey(rcvAddr.Server)

		if !bytes.Equal(expectedServerPubkey, rcvServerPubkey) {
			return "", fmt.Errorf(
				"invalid receiver address '%s': expected server %x, got %x",
				receiver.To, expectedServerPubkey, rcvServerPubkey,
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

	// coinselect boarding utxos and vtxos
	boardingUtxos, vtxos, changeAmount, err := a.selectFunds(
		ctx, computeVtxoExpiry, options.SelectRecoverableVtxos, sumOfReceivers,
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

func (a *covenantlessArkClient) makeRegisterIntentBIP322Signature(
	inputs []bip322.Input, leafProofs []*common.TaprootMerkleProof, tapscripts map[string][]string,
	outputs []types.Receiver, cosignersPublicKeys []string, notesWitnesses map[int][]byte,
) (string, string, error) {
	message, outputsTxOut, err := registerIntentMessage(
		inputs, outputs, tapscripts, cosignersPublicKeys,
	)
	if err != nil {
		return "", "", err
	}

	return a.makeBIP322Signature(message, inputs, outputsTxOut, leafProofs, notesWitnesses)
}

func (a *covenantlessArkClient) makeDeleteIntentBIP322Signature(
	inputs []bip322.Input, leafProofs []*common.TaprootMerkleProof, notesWitnesses map[int][]byte,
) (string, string, error) {
	message, err := tree.DeleteIntentMessage{
		BaseIntentMessage: tree.BaseIntentMessage{
			Type: tree.IntentMessageTypeDelete,
		},
		ExpireAt: time.Now().Add(2 * time.Minute).Unix(),
	}.Encode()
	if err != nil {
		return "", "", err
	}

	return a.makeBIP322Signature(message, inputs, nil, leafProofs, notesWitnesses)
}

func (a *covenantlessArkClient) makeBIP322Signature(
	message string, inputs []bip322.Input, outputsTxOut []*wire.TxOut,
	leafProofs []*common.TaprootMerkleProof, notesWitnesses map[int][]byte,
) (string, string, error) {
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

	sig, err := proof.Signature(finalizeWithNotes(notesWitnesses))
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
	ctx context.Context, updater *psbt.Updater, utxos []types.Utxo,
) error {
	// TODO works only with single-key wallet
	_, offchain, _, err := a.wallet.NewAddress(ctx, false)
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

func (a *covenantlessArkClient) populateVtxosWithTapscripts(
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
			vtxoAddr, err := v.Address(a.ServerPubKey, a.Network)
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

func (a *covenantlessArkClient) joinBatchWithRetry(
	ctx context.Context, notes []string, outputs []types.Receiver, options SettleOptions,
	selectedCoins []client.TapscriptsVtxo, selectedBoardingCoins []types.Utxo,
) (string, error) {
	inputs, exitLeaves, tapscripts, notesWitnesses, err := toBIP322Inputs(
		selectedBoardingCoins, selectedCoins, notes,
	)
	if err != nil {
		return "", err
	}

	signerSessions, signerPubKeys, err := a.handleOptions(options, inputs, notes)
	if err != nil {
		return "", err
	}

	bip322Signature, bip322Message, err := a.makeRegisterIntentBIP322Signature(
		inputs, exitLeaves, tapscripts, outputs, signerPubKeys, notesWitnesses,
	)
	if err != nil {
		return "", err
	}

	maxRetry := 3
	retryCount := 0
	var batchErr error
	for retryCount < maxRetry {
		intentID, err := a.client.RegisterIntent(
			ctx, bip322Signature, bip322Message,
		)
		if err != nil {
			return "", err
		}

		log.Infof("registered inputs and outputs with request id: %s", intentID)

		commitmentTxid, err := a.handleBatchEvents(
			ctx, intentID, selectedCoins, selectedBoardingCoins, outputs, signerSessions,
			options.EventsCh, options.CancelCh,
		)
		if err != nil {
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

func (a *covenantlessArkClient) handleBatchEvents(
	ctx context.Context,
	intentId string, vtxos []client.TapscriptsVtxo, boardingUtxos []types.Utxo,
	receivers []types.Receiver, signerSessions []tree.SignerSession,
	replayEventsCh chan<- any, cancelCh <-chan struct{},
) (string, error) {
	topics := make([]string, 0)
	for _, vtxo := range vtxos {
		topics = append(topics, vtxo.String())
	}
	for _, signer := range signerSessions {
		topics = append(topics, signer.GetPublicKey())
	}

	eventsCh, close, err := a.client.GetEventStream(ctx, topics)
	if err != nil {
		if errors.Is(err, io.EOF) {
			close()
			return "", fmt.Errorf("connection closed by server")
		}
		return "", err
	}

	vtxosToSign := make([]client.TapscriptsVtxo, 0)
	for _, vtxo := range vtxos {
		if !vtxo.IsRecoverable() {
			// recoverable vtxos don't need to sign a forfeit tx
			vtxosToSign = append(vtxosToSign, vtxo)
		}
	}

	const (
		start = iota
		batchStarted
		treeSigningStarted
		treeNoncesAggregated
		batchFinalization
	)

	step := start
	hasOffchainOutput := false
	for _, receiver := range receivers {
		if _, err := common.DecodeAddressV0(receiver.To); err == nil {
			hasOffchainOutput = true
			break
		}
	}

	// the graph chunks are received one after the other via BatchTreeEvent
	// we collect them and then build the graphs when necessary
	vtxoGraphChunks := make([]tree.TxGraphChunk, 0)
	connectorsGraphChunks := make([]tree.TxGraphChunk, 0)

	var vtxoGraph, connectorsGraph *tree.TxGraph

	if !hasOffchainOutput {
		// if none of the outputs are offchain, we should skip the vtxo tree signing steps
		step = treeNoncesAggregated
	}

	for {
		select {
		case <-cancelCh:
			return "", fmt.Errorf("canceled")
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

			batchId := ""

			switch event := notify.Event; event.(type) {
			case client.BatchStartedEvent:
				e := event.(client.BatchStartedEvent)
				skipped, err := a.handleBatchStarted(ctx, intentId, e)
				if err != nil {
					return "", err
				}
				if !skipped {
					batchId = event.(client.BatchStartedEvent).Id
					log.Infof("batch started %s, participation confirmed", batchId)
					step++

					if !hasOffchainOutput {
						// if none of the outputs are offchain, we should skip tree signing phase
						step = treeNoncesAggregated
					}
					continue
				}
				log.Info("intent id not found in batch proposal, waiting for next one...")
			case client.BatchFinalizedEvent:
				if step != batchFinalization {
					continue
				}
				txid := event.(client.BatchFinalizedEvent).Txid
				log.Infof("batch completed in commitment tx %s", txid)
				return event.(client.BatchFinalizedEvent).Txid, nil
			// the batch session failed, return error only if we joined.
			case client.BatchFailedEvent:
				e := event.(client.BatchFailedEvent)
				if e.Id == batchId {
					return "", fmt.Errorf("batch failed: %s", e.Reason)
				}
				continue
			// we received a tree tx event msg, let's update the vtxo/connector tree.
			case client.TreeTxEvent:
				if step != batchStarted && step != treeNoncesAggregated {
					continue
				}

				treeTxEvent := event.(client.TreeTxEvent)

				if treeTxEvent.BatchIndex == 0 {
					vtxoGraphChunks = append(vtxoGraphChunks, treeTxEvent.TxGraphChunk)
				} else {
					connectorsGraphChunks = append(connectorsGraphChunks, treeTxEvent.TxGraphChunk)
				}
				continue
			case client.TreeSignatureEvent:
				if step != treeNoncesAggregated {
					continue
				}
				if vtxoGraph == nil {
					return "", fmt.Errorf("vtxo graph not initialized")
				}

				if err := handleBatchTreeSignature(event.(client.TreeSignatureEvent), vtxoGraph); err != nil {
					return "", err
				}
				continue
			// the musig2 session started, let's send our nonces.
			case client.TreeSigningStartedEvent:
				if step != batchStarted {
					continue
				}
				vtxoGraph, err = tree.NewTxGraph(vtxoGraphChunks)
				if err != nil {
					return "", fmt.Errorf("failed to create branch of vtxo tree: %s", err)
				}

				log.Info("tree signing session started, sending nonces...")
				skipped, err := a.handleTreeSigningStarted(
					ctx, signerSessions, event.(client.TreeSigningStartedEvent), vtxoGraph,
				)
				if err != nil {
					return "", err
				}
				if !skipped {
					step++
				}
				continue
			// we received the aggregated nonces, let's send our signatures.
			case client.TreeNoncesAggregatedEvent:
				if step != treeSigningStarted {
					continue
				}
				log.Info("tree nonces aggregated, sending signatures...")
				if err := a.handleTreeNoncesAggregated(
					ctx, event.(client.TreeNoncesAggregatedEvent), signerSessions,
				); err != nil {
					return "", err
				}
				step++
				continue
			// we received the fully signed vtxo and connector trees, let's send our signed forfeit
			// txs and optionally signed boarding utxos included in the commitment tx.
			case client.BatchFinalizationEvent:
				if step != treeNoncesAggregated {
					continue
				}
				log.Info("vtxo and connector trees fully signed, sending forfeit transactions...")

				if vtxoGraph == nil {
					return "", fmt.Errorf("vtxo graph not initialized")
				}

				if len(connectorsGraphChunks) > 0 {
					connectorsGraph, err = tree.NewTxGraph(connectorsGraphChunks)
					if err != nil {
						return "", fmt.Errorf("failed to create branch of connector tree: %s", err)
					}
				}

				if len(vtxosToSign) > 0 && connectorsGraph == nil {
					return "", fmt.Errorf("connectors graph not sent")
				}

				signedForfeitTxs, signedCommitmentTx, err := a.handleBatchFinalization(
					ctx, event.(client.BatchFinalizationEvent),
					vtxosToSign, boardingUtxos, receivers,
					vtxoGraph, connectorsGraph,
				)
				if err != nil {
					return "", err
				}

				if len(signedForfeitTxs) <= 0 && len(vtxosToSign) > 0 {
					continue
				}

				if err := a.client.SubmitSignedForfeitTxs(
					ctx, signedForfeitTxs, signedCommitmentTx,
				); err != nil {
					return "", err
				}

				log.Info("done.")
				log.Info("waiting for batch finalization...")
				step++
				continue
			}
		}
	}
}

func (a *covenantlessArkClient) handleBatchStarted(
	ctx context.Context, intentId string, event client.BatchStartedEvent,
) (bool, error) {
	buf := sha256.Sum256([]byte(intentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, hash := range event.HashedIntentIds {
		if hash == hashedIntentId {
			if err := a.client.ConfirmRegistration(ctx, intentId); err != nil {
				return false, err
			}
			return false, nil
		}
	}

	return true, nil
}

func (a *covenantlessArkClient) handleTreeSigningStarted(
	ctx context.Context, signerSessions []tree.SignerSession,
	event client.TreeSigningStartedEvent, vtxoGraph *tree.TxGraph,
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

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}

	batchOutput := commitmentTx.UnsignedTx.TxOut[0]
	batchOutputAmount := batchOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	generateAndSendNonces := func(session tree.SignerSession) error {
		if err := session.Init(root.CloneBytes(), batchOutputAmount, vtxoGraph); err != nil {
			return err
		}

		nonces, err := session.GetNonces()
		if err != nil {
			return err
		}

		return a.client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces)
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

func (a *covenantlessArkClient) handleTreeNoncesAggregated(
	ctx context.Context,
	event client.TreeNoncesAggregatedEvent, signerSessions []tree.SignerSession,
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
			event.Id,
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

func (a *covenantlessArkClient) handleBatchFinalization(
	ctx context.Context,
	event client.BatchFinalizationEvent, vtxos []client.TapscriptsVtxo, boardingUtxos []types.Utxo,
	receivers []types.Receiver, vtxoGraph, connectorsGraph *tree.TxGraph,
) ([]string, string, error) {
	if err := a.validateVtxoTree(event, vtxoGraph, connectorsGraph, receivers, vtxos); err != nil {
		return nil, "", fmt.Errorf("failed to verify vtxo tree: %s", err)
	}

	var forfeits []string

	if len(vtxos) > 0 {
		signedForfeits, err := a.createAndSignForfeits(
			ctx,
			vtxos, connectorsGraph.Leaves(),
		)
		if err != nil {
			return nil, "", err
		}

		forfeits = signedForfeits
	}

	if len(boardingUtxos) <= 0 {
		return forfeits, "", nil
	}

	// if we have boarding inputs, we must sign the commitment transaction too.
	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
	if err != nil {
		return nil, "", err
	}

	for _, boardingUtxo := range boardingUtxos {
		boardingVtxoScript, err := tree.ParseVtxoScript(boardingUtxo.Tapscripts)
		if err != nil {
			return nil, "", err
		}

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
			return nil, "", fmt.Errorf(
				"failed to get taproot merkle proof for boarding utxo: %s", err,
			)
		}

		tapscript := &psbt.TaprootTapLeafScript{
			ControlBlock: forfeitProof.ControlBlock,
			Script:       forfeitProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		for i := range commitmentPtx.Inputs {
			prevout := commitmentPtx.UnsignedTx.TxIn[i].PreviousOutPoint

			if boardingUtxo.Txid == prevout.Hash.String() && boardingUtxo.VOut == prevout.Index {
				commitmentPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapscript}
				break
			}
		}
	}

	b64, err := commitmentPtx.B64Encode()
	if err != nil {
		return nil, "", err
	}

	signedCommitmentTx, err := a.wallet.SignTransaction(ctx, a.explorer, b64)
	if err != nil {
		return nil, "", err
	}

	return forfeits, signedCommitmentTx, nil
}

func (a *covenantlessArkClient) validateVtxoTree(
	event client.BatchFinalizationEvent,
	vtxoGraph, connectorsGraph *tree.TxGraph,
	receivers []types.Receiver, vtxosInput []client.TapscriptsVtxo,
) error {
	commitmentTx := event.Tx
	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		return err
	}

	// validate the vtxo tree is well formed
	if !utils.IsOnchainOnly(receivers) {
		if err := tree.ValidateVtxoTxGraph(
			vtxoGraph, commitmentPtx, a.ServerPubKey, a.VtxoTreeExpiry,
		); err != nil {
			return err
		}
	}

	// validate it contains our outputs
	if err := a.validateReceivers(
		commitmentPtx, receivers, vtxoGraph,
	); err != nil {
		return err
	}

	if len(vtxosInput) > 0 {
		rootParentTxid := vtxoGraph.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
		rootParentVout := vtxoGraph.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Index

		if rootParentTxid != commitmentPtx.UnsignedTx.TxID() {
			return fmt.Errorf("root's parent txid is not the same as the commitment txid: %s != %s", rootParentTxid, commitmentPtx.UnsignedTx.TxID())
		}

		if rootParentVout != 0 {
			return fmt.Errorf("root's parent vout is not the same as the shared output index: %d != %d", rootParentVout, 0)
		}

		if err := connectorsGraph.Validate(); err != nil {
			return err
		}

		connectorsLeaves := connectorsGraph.Leaves()
		if len(connectorsLeaves) != len(vtxosInput) {
			return fmt.Errorf("unexpected num of connectors received: expected %d, got %d", len(vtxosInput), len(connectorsLeaves))
		}
	}

	return nil
}

func (a *covenantlessArkClient) validateReceivers(
	ptx *psbt.Packet, receivers []types.Receiver, vtxoGraph *tree.TxGraph,
) error {
	netParams := utils.ToBitcoinNetwork(a.Network)
	for _, receiver := range receivers {
		isOnChain, onchainScript, err := utils.ParseBitcoinAddress(receiver.To, netParams)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s err = %s", receiver.To, err)
		}

		if isOnChain {
			if err := a.validateOnchainReceiver(ptx, receiver, onchainScript); err != nil {
				return err
			}
		} else {
			if err := a.validateOffchainReceiver(vtxoGraph, receiver); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *covenantlessArkClient) validateOnchainReceiver(
	ptx *psbt.Packet, receiver types.Receiver, onchainScript []byte,
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
		return fmt.Errorf("collaborative exit output not found: %s", receiver.To)
	}
	return nil
}

func (a *covenantlessArkClient) validateOffchainReceiver(
	vtxoGraph *tree.TxGraph, receiver types.Receiver,
) error {
	found := false

	rcvAddr, err := common.DecodeAddressV0(receiver.To)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(rcvAddr.VtxoTapKey)

	leaves := vtxoGraph.Leaves()
	for _, leaf := range leaves {
		for _, output := range leaf.UnsignedTx.TxOut {
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
		return fmt.Errorf("offchain send output not found: %s", receiver.To)
	}

	return nil
}

func (a *covenantlessArkClient) createAndSignForfeits(
	ctx context.Context,
	vtxosToSign []client.TapscriptsVtxo,
	connectorsLeaves []*psbt.Packet,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(a.ForfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := txscript.PayToAddrScript(parsedForfeitAddr)
	if err != nil {
		return nil, err
	}

	signedForfeitTxs := make([]string, 0, len(vtxosToSign))
	for i, vtxo := range vtxosToSign {
		connectorTx := connectorsLeaves[i]

		var connector *wire.TxOut
		var connectorOutpoint *wire.OutPoint
		for outIndex, output := range connectorTx.UnsignedTx.TxOut {
			if bytes.Equal(tree.ANCHOR_PKSCRIPT, output.PkScript) {
				continue
			}

			connector = output
			connectorOutpoint = &wire.OutPoint{
				Hash:  connectorTx.UnsignedTx.TxHash(),
				Index: uint32(outIndex),
			}
			break
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

		vtxoLocktime := common.AbsoluteLocktime(0)
		if cltv, ok := forfeitClosure.(*tree.CLTVMultisigClosure); ok {
			vtxoLocktime = cltv.Locktime
		}

		vtxoPrevout := &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoOutputScript,
		}

		vtxoSequence := wire.MaxTxInSequenceNum
		if vtxoLocktime != 0 {
			vtxoSequence = wire.MaxTxInSequenceNum - 1
		}

		forfeitTx, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{vtxoInput, connectorOutpoint},
			[]uint32{vtxoSequence, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{vtxoPrevout, connector},
			forfeitPkScript,
			uint32(vtxoLocktime),
		)
		if err != nil {
			return nil, err
		}

		forfeitTx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&tapscript}

		b64, err := forfeitTx.B64Encode()
		if err != nil {
			return nil, err
		}

		signedForfeitTx, err := a.wallet.SignTransaction(ctx, a.explorer, b64)
		if err != nil {
			return nil, err
		}

		signedForfeitTxs = append(signedForfeitTxs, signedForfeitTx)
	}

	return signedForfeitTxs, nil
}

func (a *covenantlessArkClient) getMatureUtxos(ctx context.Context) ([]types.Utxo, error) {
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

func (a *covenantlessArkClient) getRedeemBranches(
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

func (a *covenantlessArkClient) getAllBoardingUtxos(
	ctx context.Context,
) ([]types.Utxo, map[string]struct{}, error) {
	_, _, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
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
				utxoOutpoint := types.VtxoKey{
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

func (a *covenantlessArkClient) getExpiredBoardingUtxos(
	ctx context.Context, opts *CoinSelectOptions,
) ([]types.Utxo, error) {
	_, _, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
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
				utxoOutpoint := types.VtxoKey{
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

func (a *covenantlessArkClient) getVtxos(
	ctx context.Context, opts *CoinSelectOptions,
) ([]types.Vtxo, error) {
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

	recoverableVtxos := make([]types.Vtxo, 0)
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

func (a *covenantlessArkClient) handleCommitmentTx(
	ctx context.Context,
	myPubkeys map[string]struct{}, commitmentTx *client.TxNotification,
) error {
	vtxosToAdd := make([]types.Vtxo, 0)
	vtxosToSpend := make([]types.VtxoKey, 0)
	txsToAdd := make([]types.Transaction, 0)
	txsToSettle := make([]string, 0)

	for _, vtxo := range commitmentTx.SpendableVtxos {
		if _, ok := myPubkeys[vtxo.Script]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos is ours.
	spentVtxos := make([]types.VtxoKey, 0, len(commitmentTx.SpentVtxos))
	for _, vtxo := range commitmentTx.SpentVtxos {
		spentVtxos = append(spentVtxos, types.VtxoKey{
			Txid: vtxo.Txid,
			VOut: vtxo.VOut,
		})
	}
	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, spentVtxos)
	if err != nil {
		return err
	}

	rawTx := &wire.MsgTx{}
	reader := hex.NewDecoder(strings.NewReader(commitmentTx.TxHex))
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
		vtxosToSpend = append(vtxosToSpend, vtxo.VtxoKey)
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
				Hex:       commitmentTx.TxHex,
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
					Hex:       commitmentTx.TxHex,
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
					Hex:       commitmentTx.TxHex,
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
		count, err := a.store.VtxoStore().SpendVtxos(ctx, vtxosToSpend, commitmentTx.Txid)
		if err != nil {
			return err
		}
		log.Debugf("spent %d vtxo(s)", count)
	}

	return nil
}

func (a *covenantlessArkClient) handleArkTx(
	ctx context.Context, myScripts map[string]struct{}, arkTx *client.TxNotification,
) error {
	vtxosToAdd := make([]types.Vtxo, 0)
	vtxosToSpend := make([]types.VtxoKey, 0)
	txsToAdd := make([]types.Transaction, 0)

	for _, vtxo := range arkTx.SpendableVtxos {
		if _, ok := myScripts[vtxo.Script]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos are ours.
	spentVtxos := make([]types.VtxoKey, 0, len(arkTx.SpentVtxos))
	for _, vtxo := range arkTx.SpentVtxos {
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
					ArkTxid: arkTx.Txid,
				},
				Amount:    amount,
				Type:      types.TxReceived,
				CreatedAt: time.Now(),
				Hex:       arkTx.TxHex,
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
) ([]tree.SignerSession, []string, error) {
	sessions := make([]tree.SignerSession, 0)
	sessions = append(sessions, options.ExtraSignerSessions...)

	if !options.WalletSignerDisabled {
		outpoints := make([]types.VtxoKey, 0, len(inputs))
		for _, input := range inputs {
			outpoints = append(outpoints, types.VtxoKey{
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

func (a *covenantlessArkClient) fetchTxHistory(ctx context.Context) ([]types.Transaction, error) {
	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	indexedHistory := make(map[string]types.Transaction)
	for _, addr := range offchainAddrs {
		resp, err := a.indexer.GetTransactionHistory(ctx, addr.Address)
		if err != nil {
			return nil, err
		}
		for _, tx := range resp.History {
			indexedHistory[tx.String()] = tx
		}
	}

	boardingTxs, commitmentTxsToIgnore, err := a.getBoardingTxs(ctx)
	if err != nil {
		return nil, err
	}

	for txid := range commitmentTxsToIgnore {
		delete(indexedHistory, txid)
	}

	allHistory := append([]types.Transaction{}, boardingTxs...)
	for _, tx := range indexedHistory {
		allHistory = append(allHistory, tx)
	}

	sort.SliceStable(allHistory, func(i, j int) bool {
		return allHistory[i].CreatedAt.IsZero() || allHistory[i].CreatedAt.After(allHistory[j].CreatedAt)
	})

	return allHistory, nil
}
