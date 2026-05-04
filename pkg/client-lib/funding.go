package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

func (a *service) Receive(ctx context.Context) (
	onchainAddr string, offchainAddr, boardingAddr *types.Address, err error,
) {
	if a.wallet == nil {
		return "", nil, nil, fmt.Errorf("wallet not initialized")
	}

	onchainAddr, offchainAddr, boardingAddr, err = a.newAddress(ctx)
	if err != nil {
		return "", nil, nil, err
	}

	if a.UtxoMaxAmount == 0 {
		boardingAddr = nil
	}

	return onchainAddr, offchainAddr, boardingAddr, nil
}

func (a *service) GetAddresses(
	ctx context.Context,
) ([]string, []types.Address, []types.Address, []types.Address, error) {
	if err := a.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err := a.getAddresses(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddresses := make([]string, 0, len(onchainAddrs))
	for _, addr := range onchainAddrs {
		onchainAddresses = append(onchainAddresses, addr.Address)
	}
	return onchainAddresses, offchainAddrs, boardingAddrs, redemptionAddrs, nil
}

func (a *service) ListVtxos(
	ctx context.Context, opts ...ListVtxosOption,
) ([]types.Vtxo, []types.Vtxo, error) {
	o, err := ApplyListVtxosOptions(opts...)
	if err != nil {
		return nil, nil, err
	}

	var indexerOpts []indexer.GetVtxosOption
	if o.Before > 0 || o.After > 0 {
		indexerOpts = append(indexerOpts, indexer.WithTimeRange(o.Before, o.After))
	}

	return a.getVtxos(ctx, indexerOpts...)
}

func (a *service) Balance(ctx context.Context) (*Balance, error) {
	if a.wallet == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	onchainAddrs, _, boardingAddrs, redeemAddrs, err := a.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	if a.UtxoMaxAmount == 0 {
		balance, amountByExpiration, assetBalances, err := a.getOffchainBalance(ctx)
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
			AssetBalances: assetBalances,
		}, nil
	}

	var (
		offchainBalance    uint64
		amountByExpiration map[int64]uint64
		assetBalances      map[string]uint64
		onchainSpendable   uint64
		boardingSpendable  uint64
		boardingLocked     []LockedOnchainBalance
		redeemSpendable    uint64
		redeemLocked       []LockedOnchainBalance

		offchainErr, onchainErr, boardingErr, redeemErr error
	)

	wg := &sync.WaitGroup{}
	wg.Add(4)

	go func() {
		defer wg.Done()
		bal, byExp, assets, err := a.getOffchainBalance(ctx)
		if err != nil {
			offchainErr = err
			return
		}
		offchainBalance = bal
		amountByExpiration = byExp
		assetBalances = assets
	}()

	go func() {
		defer wg.Done()
		addresses := make([]string, 0, len(onchainAddrs))
		for _, addr := range onchainAddrs {
			addresses = append(addresses, addr.Address)
		}
		utxos, err := a.explorer.GetUtxos(addresses)
		if err != nil {
			onchainErr = err
			return
		}
		for _, u := range utxos {
			onchainSpendable += u.Amount
		}
	}()

	go func() {
		defer wg.Done()
		for _, addr := range boardingAddrs {
			spendable, locked, err := a.explorer.GetRedeemedVtxosBalance(
				addr.Address, a.UnilateralExitDelay,
			)
			if err != nil {
				boardingErr = err
				return
			}
			boardingSpendable += spendable
			for ts, amt := range locked {
				boardingLocked = append(boardingLocked, LockedOnchainBalance{
					SpendableAt: time.Unix(ts, 0).Format(time.RFC3339),
					Amount:      amt,
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		for _, addr := range redeemAddrs {
			spendable, locked, err := a.explorer.GetRedeemedVtxosBalance(
				addr.Address, a.UnilateralExitDelay,
			)
			if err != nil {
				redeemErr = err
				return
			}
			redeemSpendable += spendable
			for ts, amt := range locked {
				redeemLocked = append(redeemLocked, LockedOnchainBalance{
					SpendableAt: time.Unix(ts, 0).Format(time.RFC3339),
					Amount:      amt,
				})
			}
		}
	}()

	wg.Wait()

	for _, e := range []error{offchainErr, onchainErr, boardingErr, redeemErr} {
		if e != nil {
			return nil, e
		}
	}

	for assetId, amount := range assetBalances {
		if amount == 0 {
			delete(assetBalances, assetId)
		}
	}

	nextExpiration, details := getOffchainBalanceDetails(amountByExpiration)

	lockedOnchainBalance := make([]LockedOnchainBalance, 0, len(boardingLocked)+len(redeemLocked))
	lockedOnchainBalance = append(lockedOnchainBalance, boardingLocked...)
	lockedOnchainBalance = append(lockedOnchainBalance, redeemLocked...)

	return &Balance{
		OnchainBalance: OnchainBalance{
			SpendableAmount: onchainSpendable + boardingSpendable + redeemSpendable,
			LockedAmount:    lockedOnchainBalance,
		},
		OffchainBalance: OffchainBalance{
			Total:          offchainBalance,
			NextExpiration: getFancyTimeExpiration(nextExpiration),
			Details:        details,
		},
		AssetBalances: assetBalances,
	}, nil
}

func (a *service) GetTransactionHistory(ctx context.Context) ([]types.Transaction, error) {
	spendable, spent, err := a.getVtxos(ctx)
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

func (a *service) NotifyIncomingFunds(ctx context.Context, addr string) ([]types.Vtxo, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	decoded, err := arklib.DecodeAddressV0(addr)
	if err != nil {
		return nil, err
	}
	vtxoScript, err := script.P2TRScript(decoded.VtxoTapKey)
	if err != nil {
		return nil, err
	}

	scripts := []string{hex.EncodeToString(vtxoScript)}
	_, eventCh, closeFn, err := a.indexer.NewSubscription(ctx, scripts)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	for {
		event, ok := <-eventCh
		if !ok {
			return nil, fmt.Errorf("event chan closed")
		}
		if event.Connection != nil {
			continue
		}

		if event.Err != nil {
			return nil, event.Err
		}
		return event.Data.NewVtxos, nil
	}
}

func (a *service) newAddress(
	ctx context.Context,
) (onchainAddr string, offchainAddr, boardingAddr *types.Address, err error) {
	key, err := a.wallet.NewKey(ctx)
	if err != nil {
		return "", nil, nil, err
	}

	onchainAddr, offchainAddr, boardingAddr, _, err = a.deriveDefaultAddresses(*key)
	return onchainAddr, offchainAddr, boardingAddr, err
}

func (a *service) getAddresses(ctx context.Context) (
	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs []types.Address,
	err error,
) {
	keys := make([]wallet.KeyRef, 0)
	seenKeys := make(map[string]struct{})

	keyRefs, err := a.wallet.ListKeys(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for _, key := range keyRefs {
		if _, ok := seenKeys[key.Id]; ok {
			continue
		}
		seenKeys[key.Id] = struct{}{}
		keys = append(keys, key)
	}

	for _, key := range keys {
		onchainAddr, offchainAddr, boardingAddr, redemptionAddr, err := a.deriveDefaultAddresses(key)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		onchainAddrs = append(onchainAddrs, types.Address{KeyID: key.Id, Address: onchainAddr})
		offchainAddrs = append(offchainAddrs, *offchainAddr)
		boardingAddrs = append(boardingAddrs, *boardingAddr)
		redemptionAddrs = append(redemptionAddrs, *redemptionAddr)
	}

	return onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, nil
}

func (a *service) deriveDefaultAddresses(
	key wallet.KeyRef,
) (onchainAddr string, offchainAddr, boardingAddr, redemptionAddr *types.Address, err error) {
	netParams := utils.ToBitcoinNetwork(a.Network)

	defaultVtxoScript := script.NewDefaultVtxoScript(
		key.PubKey, a.SignerPubKey, a.UnilateralExitDelay,
	)
	vtxoTapKey, _, err := defaultVtxoScript.TapTree()
	if err != nil {
		return "", nil, nil, nil, err
	}

	offchainAddress := &arklib.Address{
		HRP:        a.Network.Addr,
		Signer:     a.SignerPubKey,
		VtxoTapKey: vtxoTapKey,
	}
	encodedOffchainAddr, err := offchainAddress.EncodeV0()
	if err != nil {
		return "", nil, nil, nil, err
	}

	tapscripts, err := defaultVtxoScript.Encode()
	if err != nil {
		return "", nil, nil, nil, err
	}

	boardingVtxoScript := script.NewDefaultVtxoScript(
		key.PubKey, a.SignerPubKey, a.BoardingExitDelay,
	)
	boardingTapKey, _, err := boardingVtxoScript.TapTree()
	if err != nil {
		return "", nil, nil, nil, err
	}

	boardingTaprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(boardingTapKey), &netParams,
	)
	if err != nil {
		return "", nil, nil, nil, err
	}

	boardingTapscripts, err := boardingVtxoScript.Encode()
	if err != nil {
		return "", nil, nil, nil, err
	}

	redemptionTaprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey), &netParams,
	)
	if err != nil {
		return "", nil, nil, nil, err
	}

	onchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
	onchainTaprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(onchainTapKey), &netParams,
	)
	if err != nil {
		return "", nil, nil, nil, err
	}

	onchainAddr = onchainTaprootAddr.EncodeAddress()
	offchainAddr = &types.Address{
		KeyID:      key.Id,
		Tapscripts: tapscripts,
		Address:    encodedOffchainAddr,
	}
	boardingAddr = &types.Address{
		KeyID:      key.Id,
		Tapscripts: boardingTapscripts,
		Address:    boardingTaprootAddr.EncodeAddress(),
	}
	redemptionAddr = &types.Address{
		KeyID:      key.Id,
		Tapscripts: tapscripts,
		Address:    redemptionTaprootAddr.EncodeAddress(),
	}

	return
}

func (a *service) getOffchainBalance(ctx context.Context) (
	uint64, map[int64]uint64, map[string]uint64, error,
) {
	amountByExpiration := make(map[int64]uint64, 0)
	assetBalances := make(map[string]uint64, 0)
	opts := &getVtxosFilter{withRecoverableVtxos: true}
	vtxos, err := a.getSpendableVtxos(ctx, opts)
	if err != nil {
		return 0, nil, nil, err
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

		for _, a := range vtxo.Assets {
			if _, ok := assetBalances[a.AssetId]; !ok {
				assetBalances[a.AssetId] = a.Amount
				continue
			}
			assetBalances[a.AssetId] += a.Amount
		}
	}

	return balance, amountByExpiration, assetBalances, nil
}

func (a *service) getBoardingTxs(ctx context.Context) ([]types.Transaction, error) {
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

func (a *service) getAllBoardingUtxos(ctx context.Context) ([]types.Utxo, error) {
	_, _, boardingAddrs, _, err := a.getAddresses(ctx)
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

func (i *service) vtxosToTxs(
	ctx context.Context, spendable, spent []types.Vtxo, commitmentTxsToIgnore map[string]struct{},
) ([]types.Transaction, error) {
	txs := make([]types.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx or a collaborative exit
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
		settledBy := ""
		if vtxo.Preconfirmed {
			arkTxid = vtxo.Txid
			commitmentTxid = ""
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
			SettledBy: settledBy,
			Assets:    NetVtxoAssets([]types.Vtxo{vtxo}, append(settleVtxos, spentVtxos...)),
		})
	}

	// Sendings

	// All spent vtxos are payments unless they are settlements of boarding utxos or refreshes

	// Aggregate settled vtxos by "settledBy" (commitment txid)
	vtxosBySettledBy := make(map[string][]types.Vtxo)
	// Aggregate spent vtxos by "arkTxid"
	vtxosBySpentBy := make(map[string][]types.Vtxo)
	for _, v := range spent {

		if v.SettledBy != "" {
			if _, ok := commitmentTxsToIgnore[v.SettledBy]; !ok {
				if _, ok := vtxosBySettledBy[v.SettledBy]; !ok {
					vtxosBySettledBy[v.SettledBy] = make([]types.Vtxo, 0)
				}
				vtxosBySettledBy[v.SettledBy] = append(vtxosBySettledBy[v.SettledBy], v)
				continue
			}
		}

		if len(v.ArkTxid) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.ArkTxid]; !ok {
			vtxosBySpentBy[v.ArkTxid] = make([]types.Vtxo, 0)
		}
		vtxosBySpentBy[v.ArkTxid] = append(vtxosBySpentBy[v.ArkTxid], v)
	}

	for sb := range vtxosBySettledBy {
		resultedVtxos := findVtxosResultedFromSettledBy(append(spendable, spent...), sb)
		resultedAmount := reduceVtxosAmount(resultedVtxos)
		forfeitAmount := reduceVtxosAmount(vtxosBySettledBy[sb])
		// If the forfeit amount is bigger than the resulted amount, we have a collaborative exit
		if forfeitAmount > resultedAmount {
			vtxo := getVtxo(resultedVtxos, vtxosBySettledBy[sb])

			txs = append(txs, types.Transaction{
				TransactionKey: types.TransactionKey{
					CommitmentTxid: vtxo.CommitmentTxids[0],
				},
				Amount:    forfeitAmount - resultedAmount,
				Type:      types.TxSent,
				CreatedAt: vtxo.CreatedAt,
				Assets:    NetVtxoAssets(vtxosBySettledBy[sb], resultedVtxos),
			})
		}
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
			resp, err := i.indexer.GetVtxos(ctx, indexer.WithOutpoints([]types.Outpoint{{Txid: sb, VOut: 0}}))
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
			SettledBy: vtxo.SettledBy,
			Assets:    NetVtxoAssets(vtxosBySpentBy[sb], resultedVtxos),
		})
	}

	return txs, nil
}

func (s *service) getReceiver(ctx context.Context, optReceiver string) (string, error) {
	if len(optReceiver) > 0 {
		if err := validateOffchainAddress(optReceiver); err != nil {
			return "", err
		}
		return optReceiver, nil
	}
	_, changeAddr, _, err := s.newAddress(ctx)
	if err != nil {
		return "", err
	}
	return changeAddr.Address, nil
}

func (s *service) getBoardingReceiver(ctx context.Context, optReceiver string) (string, error) {
	if len(optReceiver) > 0 {
		if err := validateOffchainAddress(optReceiver); err != nil {
			return "", err
		}
		return optReceiver, nil
	}
	_, _, changeAddr, err := s.newAddress(ctx)
	if err != nil {
		return "", err
	}
	return changeAddr.Address, nil
}

// NetVtxoAssets returns the per-asset balance for a vtxo movement:
// assets found in `gross` minus the portion in `subtract` that effectively
// stayed in the wallet (change, already-owned vtxos, etc.).
//
// The output preserves asset-id order as first encountered in `gross`, drops
// zero-net assets, and returns nil when there is no asset data (common pure-BTC
// case).
//
// It is exported so that external SDKs reproducing the same vtxosToTxs
// reconstruction (e.g. go-sdk) can derive Transaction.Assets with identical
// semantics, rather than keeping a parallel copy of the helper.
func NetVtxoAssets(gross, subtract []types.Vtxo) []types.Asset {
	grossSums, order := sumVtxoAssets(gross)
	if len(order) == 0 {
		return nil
	}
	subSums, _ := sumVtxoAssets(subtract)
	out := make([]types.Asset, 0, len(order))
	zero := new(big.Int)
	for _, id := range order {
		g := grossSums[id]
		s := subSums[id]
		if s == nil {
			s = zero
		}
		if g.Cmp(s) > 0 {
			diff := new(big.Int).Sub(g, s)
			out = append(out, types.Asset{AssetId: id, Amount: diff.Uint64()})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sumVtxoAssets aggregates per-asset amounts across the given vtxos, returning
// a map of asset id → total amount together with the asset ids in first-seen
// order (useful for deterministic output).
func sumVtxoAssets(vtxos []types.Vtxo) (map[string]*big.Int, []string) {
	sums := make(map[string]*big.Int)
	order := make([]string, 0)
	for _, v := range vtxos {
		for _, a := range v.Assets {
			if _, seen := sums[a.AssetId]; !seen {
				sums[a.AssetId] = new(big.Int)
				order = append(order, a.AssetId)
			}
			sums[a.AssetId].Add(sums[a.AssetId], new(big.Int).SetUint64(a.Amount))
		}
	}
	return sums, order
}
