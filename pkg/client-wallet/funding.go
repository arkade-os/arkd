package wallet

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
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

func (w *wallet) Receive(ctx context.Context) (
	string, *clientlib.Address, *clientlib.Address, error,
) {
	if w.identity == nil {
		return "", nil, nil, ErrNotInitialized
	}

	onchainAddr, offchainAddr, boardingAddr, _, err := w.getAddresses(ctx)
	if err != nil {
		return "", nil, nil, err
	}

	if w.UtxoMaxAmount == 0 {
		boardingAddr = nil
	}

	return onchainAddr.Address, offchainAddr, boardingAddr, nil
}

func (w *wallet) GetAddresses(
	ctx context.Context,
) ([]string, []clientlib.Address, []clientlib.Address, []clientlib.Address, error) {
	if err := w.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddr, offchainAddr, boardingAddr, redemptionAddr, err := w.getAddresses(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddrs := []string{onchainAddr.Address}
	offchainAddrs := []clientlib.Address{*offchainAddr}
	boardingAddrs := []clientlib.Address{*boardingAddr}
	redemptionAddrs := []clientlib.Address{*redemptionAddr}
	return onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, nil
}

func (w *wallet) ListVtxos(
	ctx context.Context, opts ...ListVtxosOption,
) ([]clientlib.Vtxo, []clientlib.Vtxo, error) {
	o, err := ApplyListVtxosOptions(opts...)
	if err != nil {
		return nil, nil, err
	}

	var indexerOpts []clientlib.GetVtxosOption
	if o.Before > 0 || o.After > 0 {
		indexerOpts = append(indexerOpts, clientlib.WithTimeRange(o.Before, o.After))
	}

	return w.getVtxos(ctx, indexerOpts...)
}

func (w *wallet) Balance(ctx context.Context) (*types.Balance, error) {
	if w.identity == nil {
		return nil, ErrNotInitialized
	}

	onchainAddr, _, boardingAddr, redeemAddr, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	if w.UtxoMaxAmount == 0 {
		balance, amountByExpiration, assetBalances, err := w.getOffchainBalance(ctx)
		if err != nil {
			return nil, err
		}

		nextExpiration, details := getOffchainBalanceDetails(amountByExpiration)

		return &types.Balance{
			OffchainBalance: types.OffchainBalance{
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
		boardingLocked     []types.LockedOnchainBalance
		redeemSpendable    uint64
		redeemLocked       []types.LockedOnchainBalance

		offchainErr, onchainErr, boardingErr, redeemErr error
	)

	wg := &sync.WaitGroup{}

	wg.Go(func() {
		bal, byExp, assets, err := w.getOffchainBalance(ctx)
		if err != nil {
			offchainErr = err
			return
		}
		offchainBalance = bal
		amountByExpiration = byExp
		assetBalances = assets
	})

	wg.Go(func() {
		utxos, err := w.explorer.GetUtxos([]string{onchainAddr.Address})
		if err != nil {
			onchainErr = err
			return
		}
		for _, u := range utxos {
			onchainSpendable += u.Amount
		}
	})

	wg.Go(func() {
		spendable, locked, err := w.explorer.GetRedeemedVtxosBalance(
			boardingAddr.Address, w.BoardingExitDelay,
		)
		if err != nil {
			boardingErr = err
			return
		}
		boardingSpendable += spendable
		for ts, amt := range locked {
			boardingLocked = append(boardingLocked, types.LockedOnchainBalance{
				SpendableAt: time.Unix(ts, 0).Format(time.RFC3339),
				Amount:      amt,
			})
		}
	})

	wg.Go(func() {
		spendable, locked, err := w.explorer.GetRedeemedVtxosBalance(
			redeemAddr.Address, w.UnilateralExitDelay,
		)
		if err != nil {
			redeemErr = err
			return
		}
		redeemSpendable += spendable
		for ts, amt := range locked {
			redeemLocked = append(redeemLocked, types.LockedOnchainBalance{
				SpendableAt: time.Unix(ts, 0).Format(time.RFC3339),
				Amount:      amt,
			})
		}
	})

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

	lockedOnchainBalance := make(
		[]types.LockedOnchainBalance, 0, len(boardingLocked)+len(redeemLocked),
	)
	lockedOnchainBalance = append(lockedOnchainBalance, boardingLocked...)
	lockedOnchainBalance = append(lockedOnchainBalance, redeemLocked...)

	return &types.Balance{
		OnchainBalance: types.OnchainBalance{
			SpendableAmount: onchainSpendable + boardingSpendable + redeemSpendable,
			LockedAmount:    lockedOnchainBalance,
		},
		OffchainBalance: types.OffchainBalance{
			Total:          offchainBalance,
			NextExpiration: getFancyTimeExpiration(nextExpiration),
			Details:        details,
		},
		AssetBalances: assetBalances,
	}, nil
}

func (w *wallet) GetTransactionHistory(ctx context.Context) ([]clientlib.Transaction, error) {
	spendable, spent, err := w.getVtxos(ctx)
	if err != nil {
		return nil, err
	}

	onchainHistory, err := w.getBoardingTxs(ctx)
	if err != nil {
		return nil, err
	}
	commitmentTxsToIgnore := make(map[string]struct{})
	for _, tx := range onchainHistory {
		if tx.SettledBy != "" {
			commitmentTxsToIgnore[tx.SettledBy] = struct{}{}
		}
	}

	offchainHistory, err := w.vtxosToTxs(ctx, spendable, spent, commitmentTxsToIgnore)
	if err != nil {
		return nil, err
	}

	history := append(onchainHistory, offchainHistory...)
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].CreatedAt.After(history[j].CreatedAt)
	})

	return history, nil
}

func (w *wallet) NotifyIncomingFunds(ctx context.Context, addr string) ([]clientlib.Vtxo, error) {
	if err := w.safeCheck(); err != nil {
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
	_, eventCh, closeFn, err := w.indexer.NewSubscription(ctx, scripts)
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

func (w *wallet) getAddresses(ctx context.Context) (
	*clientlib.Address, *clientlib.Address, *clientlib.Address, *clientlib.Address, error,
) {
	keyRefs, err := w.identity.ListKeys(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	key := keyRefs[0]

	addr, offchainAddr, boardingAddr, redemptionAddr, err := w.deriveDefaultAddresses(key)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddr := &clientlib.Address{Address: addr, KeyID: key.Id}
	return onchainAddr, offchainAddr, boardingAddr, redemptionAddr, nil
}

func (w *wallet) deriveDefaultAddresses(
	key clientlib.KeyRef,
) (onchainAddr string, offchainAddr, boardingAddr, redemptionAddr *clientlib.Address, err error) {
	netParams := clientlib.ToBitcoinNetwork(w.Network)

	defaultVtxoScript := script.NewDefaultVtxoScript(
		key.PubKey, w.SignerPubKey, w.UnilateralExitDelay,
	)
	vtxoTapKey, _, err := defaultVtxoScript.TapTree()
	if err != nil {
		return "", nil, nil, nil, err
	}

	offchainAddress := &arklib.Address{
		HRP:        w.Network.Addr,
		Signer:     w.SignerPubKey,
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
		key.PubKey, w.SignerPubKey, w.BoardingExitDelay,
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
	offchainAddr = &clientlib.Address{
		KeyID:      key.Id,
		Tapscripts: tapscripts,
		Address:    encodedOffchainAddr,
	}
	boardingAddr = &clientlib.Address{
		KeyID:      key.Id,
		Tapscripts: boardingTapscripts,
		Address:    boardingTaprootAddr.EncodeAddress(),
	}
	redemptionAddr = &clientlib.Address{
		KeyID:      key.Id,
		Tapscripts: tapscripts,
		Address:    redemptionTaprootAddr.EncodeAddress(),
	}

	return
}

func (w *wallet) getOffchainBalance(ctx context.Context) (
	uint64, map[int64]uint64, map[string]uint64, error,
) {
	amountByExpiration := make(map[int64]uint64, 0)
	assetBalances := make(map[string]uint64, 0)
	vtxos, err := w.getSpendableVtxos(ctx, nil)
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

func (w *wallet) getBoardingTxs(ctx context.Context) ([]clientlib.Transaction, error) {
	allUtxos, err := w.getAllBoardingUtxos(ctx)
	if err != nil {
		return nil, err
	}

	unconfirmedTxs := make([]clientlib.Transaction, 0)
	confirmedTxs := make([]clientlib.Transaction, 0)
	for _, u := range allUtxos {
		tx := clientlib.Transaction{
			TransactionKey: clientlib.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      clientlib.TxReceived,
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

func (w *wallet) getAllBoardingUtxos(ctx context.Context) ([]clientlib.Utxo, error) {
	_, _, boardingAddr, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}
	addr := boardingAddr.Address
	closure, err := boardingAddr.CollaborativeClosure()
	if err != nil {
		return nil, err
	}

	utxos := []clientlib.Utxo{}
	txs, err := w.explorer.GetTxs(addr)
	if err != nil {
		return nil, err
	}
	for _, tx := range txs {
		for i, vout := range tx.Vout {
			if vout.Address == addr {
				createdAt := time.Time{}
				utxoTime := time.Now()
				if tx.Status.Confirmed {
					createdAt = time.Unix(tx.Status.BlockTime, 0)
					utxoTime = time.Unix(tx.Status.BlockTime, 0)
				}

				txHex, err := w.explorer.GetTxHex(tx.Txid)
				if err != nil {
					return nil, err
				}
				spentStatuses, err := w.explorer.GetTxOutspends(tx.Txid)
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

				utxos = append(utxos, clientlib.Utxo{
					Outpoint: clientlib.Outpoint{
						Txid: tx.Txid,
						VOut: uint32(i),
					},
					Amount: vout.Amount,
					Script: vout.Script,
					Delay:  w.BoardingExitDelay,
					RedeemableAt: utxoTime.Add(
						time.Duration(w.BoardingExitDelay.Seconds()) * time.Second,
					),
					CreatedAt:      createdAt,
					Spent:          spent,
					SpentBy:        spentBy,
					Tx:             txHex,
					Tapscripts:     boardingAddr.Tapscripts,
					SigningClosure: closure,
				})
			}
		}
	}

	return utxos, nil
}

func (w *wallet) vtxosToTxs(
	ctx context.Context, spendable, spent []clientlib.Vtxo, commitmentTxsToIgnore map[string]struct{},
) ([]clientlib.Transaction, error) {
	txs := make([]clientlib.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx or a collaborative exit
	vtxosLeftToCheck := append([]clientlib.Vtxo{}, spent...)
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

		txs = append(txs, clientlib.Transaction{
			TransactionKey: clientlib.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    vtxo.Amount - settleAmount - spentAmount,
			Type:      clientlib.TxReceived,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: settledBy,
			Assets:    NetVtxoAssets([]clientlib.Vtxo{vtxo}, append(settleVtxos, spentVtxos...)),
		})
	}

	// Sendings

	// All spent vtxos are payments unless they are settlements of boarding utxos or refreshes

	// Aggregate settled vtxos by "settledBy" (commitment txid)
	vtxosBySettledBy := make(map[string][]clientlib.Vtxo)
	// Aggregate spent vtxos by "arkTxid"
	vtxosBySpentBy := make(map[string][]clientlib.Vtxo)
	for _, v := range spent {

		if v.SettledBy != "" {
			if _, ok := commitmentTxsToIgnore[v.SettledBy]; !ok {
				if _, ok := vtxosBySettledBy[v.SettledBy]; !ok {
					vtxosBySettledBy[v.SettledBy] = make([]clientlib.Vtxo, 0)
				}
				vtxosBySettledBy[v.SettledBy] = append(vtxosBySettledBy[v.SettledBy], v)
				continue
			}
		}

		if len(v.ArkTxid) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.ArkTxid]; !ok {
			vtxosBySpentBy[v.ArkTxid] = make([]clientlib.Vtxo, 0)
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

			txs = append(txs, clientlib.Transaction{
				TransactionKey: clientlib.TransactionKey{
					CommitmentTxid: vtxo.CommitmentTxids[0],
				},
				Amount:    forfeitAmount - resultedAmount,
				Type:      clientlib.TxSent,
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
			resp, err := w.indexer.GetVtxos(
				ctx, clientlib.WithOutpoints([]clientlib.Outpoint{{Txid: sb, VOut: 0}}),
			)
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

		txs = append(txs, clientlib.Transaction{
			TransactionKey: clientlib.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    spentAmount - resultedAmount,
			Type:      clientlib.TxSent,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: vtxo.SettledBy,
			Assets:    NetVtxoAssets(vtxosBySpentBy[sb], resultedVtxos),
		})
	}

	return txs, nil
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
func NetVtxoAssets(gross, subtract []clientlib.Vtxo) []clientlib.Asset {
	grossSums, order := sumVtxoAssets(gross)
	if len(order) == 0 {
		return nil
	}
	subSums, _ := sumVtxoAssets(subtract)
	out := make([]clientlib.Asset, 0, len(order))
	zero := new(big.Int)
	for _, id := range order {
		g := grossSums[id]
		s := subSums[id]
		if s == nil {
			s = zero
		}
		if g.Cmp(s) > 0 {
			diff := new(big.Int).Sub(g, s)
			out = append(out, clientlib.Asset{AssetId: id, Amount: diff.Uint64()})
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
func sumVtxoAssets(vtxos []clientlib.Vtxo) (map[string]*big.Int, []string) {
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
