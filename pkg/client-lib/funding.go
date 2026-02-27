package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

func (a *service) Receive(ctx context.Context) (string, string, string, error) {
	if a.wallet == nil {
		return "", "", "", fmt.Errorf("wallet not initialized")
	}

	onchainAddr, offchainAddr, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", "", "", err
	}

	if a.UtxoMaxAmount == 0 {
		boardingAddr.Address = ""
	}

	return onchainAddr, offchainAddr.Address, boardingAddr.Address, nil
}

func (a *service) GetAddresses(
	ctx context.Context,
) ([]string, []string, []string, []string, error) {
	if err := a.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	toStringList := func(l []wallet.TapscriptsAddress) []string {
		res := make([]string, 0, len(l))
		for _, v := range l {
			res = append(res, v.Address)
		}
		return res
	}

	return onchainAddrs, toStringList(offchainAddrs),
		toStringList(boardingAddrs), toStringList(redemptionAddrs), nil
}

func (a *service) ListVtxos(ctx context.Context) ([]types.Vtxo, []types.Vtxo, error) {
	return a.getVtxos(ctx)
}

func (a *service) Balance(ctx context.Context) (*Balance, error) {
	if a.wallet == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	onchainAddrs, offchainAddrs, boardingAddrs, redeemAddrs, err := a.wallet.GetAddresses(ctx)
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

	const nbWorkers = 4
	wg := &sync.WaitGroup{}
	wg.Add(nbWorkers * len(offchainAddrs))

	chRes := make(chan balanceRes, nbWorkers*len(offchainAddrs))
	for i := range offchainAddrs {
		boardingAddr := boardingAddrs[i]
		redeemAddr := redeemAddrs[i]

		go func() {
			defer wg.Done()
			balance, amountByExpiration, assetBalances, err := a.getOffchainBalance(ctx)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}

			chRes <- balanceRes{
				offchainBalance:             balance,
				offchainBalanceByExpiration: amountByExpiration,
				assetBalances:               assetBalances,
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
	assetBalances := make(map[string]uint64)
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

		if res.assetBalances != nil {
			for assetId, amount := range res.assetBalances {
				assetBalances[assetId] += amount
			}
		}

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

	// remove empty asset balances
	for assetId, amount := range assetBalances {
		if amount == 0 {
			delete(assetBalances, assetId)
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
	subId, err := a.indexer.SubscribeForScripts(ctx, "", scripts)
	if err != nil {
		return nil, err
	}

	eventCh, closeFn, err := a.indexer.GetSubscription(ctx, subId)
	if err != nil {
		return nil, err
	}
	defer func() {
		// nolint
		a.indexer.UnsubscribeForScripts(ctx, subId, scripts)
		closeFn()
	}()

	event, ok := <-eventCh
	if !ok {
		return nil, fmt.Errorf("event chan closed")
	}

	if event.Err != nil {
		return nil, event.Err
	}
	return event.NewVtxos, nil
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
			SettledBy: vtxo.SettledBy,
		})
	}

	return txs, nil
}
