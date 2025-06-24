package application

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	maxPageSizeVtxoTree       = 300
	maxPageSizeConnector      = 300
	maxPageSizeForfeitTxs     = 500
	maxPageSizeSpendableVtxos = 100
	maxPageSizeTxHistory      = 200
	maxPageSizeVtxoChain      = 100
	maxPageSizeVirtualTxs     = 100
)

type IndexerService interface {
	GetCommitmentTxInfo(ctx context.Context, txid string) (*CommitmentTxResp, error)
	GetCommitmentTxLeaves(ctx context.Context, txid string, page *Page) (*CommitmentTxLeavesResp, error)
	GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, page *Page) (*VtxoTreeResp, error)
	GetVtxoTreeLeaves(ctx context.Context, batchOutpoint Outpoint, page *Page) (*VtxoTreeLeavesResp, error)
	GetForfeitTxs(ctx context.Context, txid string, page *Page) (*ForfeitTxsResp, error)
	GetConnectors(ctx context.Context, txid string, page *Page) (*ConnectorResp, error)
	GetVtxos(ctx context.Context, pubkeys []string, spendableOnly, spendOnly bool, page *Page) (*GetVtxosResp, error)
	GetVtxosByOutpoint(ctx context.Context, outpoints []Outpoint, page *Page) (*GetVtxosResp, error)
	GetTransactionHistory(ctx context.Context, pubkey string, start, end int64, page *Page) (*TxHistoryResp, error)
	GetVtxoChain(ctx context.Context, vtxoKey Outpoint, page *Page) (*VtxoChainResp, error)
	GetVirtualTxs(ctx context.Context, txids []string, page *Page) (*VirtualTxsResp, error)
	GetSweptCommitmentTx(ctx context.Context, txid string) (*SweptCommitmentTxResp, error)
}

type indexerService struct {
	pubkey      *secp256k1.PublicKey
	repoManager ports.RepoManager
}

func NewIndexerService(
	pubkey *secp256k1.PublicKey,
	repoManager ports.RepoManager,
) IndexerService {
	svc := &indexerService{
		pubkey:      pubkey,
		repoManager: repoManager,
	}

	return svc
}

func (i *indexerService) GetCommitmentTxInfo(
	ctx context.Context, txid string,
) (*CommitmentTxResp, error) {
	roundStats, err := i.repoManager.Rounds().GetRoundStats(ctx, txid)
	if err != nil {
		return nil, err
	}

	batches := make(map[VOut]Batch)
	// TODO: currently commitment tx has only one batch, in future multiple batches will be supported
	batches[0] = Batch{
		TotalOutputAmount: roundStats.TotalBatchAmount,
		TotalOutputVtxos:  roundStats.TotalOutputVtxos,
		ExpiresAt:         roundStats.ExpiresAt,
		Swept:             roundStats.Swept,
	}

	return &CommitmentTxResp{
		StartedAt:         roundStats.Started,
		EndAt:             roundStats.Ended,
		Batches:           batches,
		TotalInputAmount:  roundStats.TotalForfeitAmount,
		TotalInputtVtxos:  roundStats.TotalInputVtxos,
		TotalOutputVtxos:  roundStats.TotalOutputVtxos,
		TotalOutputAmount: roundStats.TotalBatchAmount,
	}, nil
}

func (i *indexerService) GetCommitmentTxLeaves(ctx context.Context, txid string, page *Page) (*CommitmentTxLeavesResp, error) {
	leaves, err := i.repoManager.Vtxos().GetLeafVtxosForRound(ctx, txid)
	if err != nil {
		return nil, err
	}

	paginatedLeaves, pageResp := paginate(leaves, page, maxPageSizeVtxoTree)

	return &CommitmentTxLeavesResp{
		Leaves: paginatedLeaves,
		Page:   pageResp,
	}, nil
}

func (i *indexerService) GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, page *Page) (*VtxoTreeResp, error) {
	vtxoTree, err := i.repoManager.Rounds().GetVtxoTreeWithTxid(ctx, batchOutpoint.Txid) //TODO repo methods needs to be updated with multiple batches in future
	if err != nil {
		return nil, err
	}

	nodes, pageResp := paginate(vtxoTree, page, maxPageSizeVtxoTree)

	return &VtxoTreeResp{
		Nodes: nodes,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetVtxoTreeLeaves(ctx context.Context, outpoint Outpoint, page *Page) (*VtxoTreeLeavesResp, error) {
	leaves, err := i.repoManager.Vtxos().GetLeafVtxosForRound(ctx, outpoint.Txid)
	if err != nil {
		return nil, err
	}

	paginatedLeaves, pageResp := paginate(leaves, page, maxPageSizeVtxoTree)

	return &VtxoTreeLeavesResp{
		Leaves: paginatedLeaves,
		Page:   pageResp,
	}, nil
}

func (i *indexerService) GetForfeitTxs(ctx context.Context, txid string, page *Page) (*ForfeitTxsResp, error) {
	forfeitTxs, err := i.repoManager.Rounds().GetRoundForfeitTxs(ctx, txid)
	if err != nil {
		return nil, err
	}

	txs := make([]string, 0, len(forfeitTxs))
	for _, tx := range forfeitTxs {
		txs = append(txs, tx.Txid)
	}

	res, pageResp := paginate(txs, page, maxPageSizeForfeitTxs)

	return &ForfeitTxsResp{
		Txs:  res,
		Page: pageResp,
	}, nil

}

func (i *indexerService) GetConnectors(ctx context.Context, txid string, page *Page) (*ConnectorResp, error) {
	connectorTree, err := i.repoManager.Rounds().GetRoundConnectorTree(ctx, txid)
	if err != nil {
		return nil, err
	}

	chunks, pageResp := paginate(connectorTree, page, maxPageSizeVtxoTree)

	return &ConnectorResp{
		Connectors: chunks,
		Page:       pageResp,
	}, nil
}

func (i *indexerService) GetVtxos(
	ctx context.Context, pubkeys []string, spendableOnly, spentOnly bool, page *Page,
) (*GetVtxosResp, error) {
	if spendableOnly && spentOnly {
		return nil, fmt.Errorf("spendable and spent only can't be true at the same time")
	}

	vtxos, err := i.repoManager.Vtxos().GetAllVtxosWithPubKeys(
		ctx, pubkeys, spendableOnly, spentOnly,
	)
	if err != nil {
		return nil, err
	}

	pagedVtxos, pageResp := paginate(vtxos, page, maxPageSizeSpendableVtxos)

	return &GetVtxosResp{
		Vtxos: pagedVtxos,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetVtxosByOutpoint(
	ctx context.Context, outpoints []Outpoint, page *Page,
) (*GetVtxosResp, error) {
	keys := make([]domain.VtxoKey, 0, len(outpoints))
	for _, outpoint := range outpoints {
		keys = append(keys, domain.VtxoKey{
			Txid: outpoint.Txid,
			VOut: outpoint.Vout,
		})
	}
	vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, keys)
	if err != nil {
		return nil, err
	}

	pagedVtxos, pageResp := paginate(vtxos, page, maxPageSizeSpendableVtxos)

	return &GetVtxosResp{
		Vtxos: pagedVtxos,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetTransactionHistory(
	ctx context.Context, pubkey string, start, end int64, page *Page,
) (*TxHistoryResp, error) {
	spendable, spent, err := i.repoManager.Vtxos().GetAllVtxosWithPubKey(ctx, pubkey)
	if err != nil {
		return nil, err
	}

	var roundTxids map[string]any
	if len(spent) > 0 {
		txids := make([]string, 0, len(spent))
		for _, vtxo := range spent {
			txids = append(txids, vtxo.SpentBy)
		}
		roundTxids, err = i.repoManager.Rounds().GetExistingRounds(ctx, txids)
		if err != nil {
			return nil, err
		}
	}

	txs, err := i.vtxosToTxs(ctx, spendable, spent, roundTxids)
	if err != nil {
		return nil, err
	}

	txs = filterByDate(txs, start, end)
	txsPaged, pageResp := paginate(txs, page, maxPageSizeTxHistory)

	return &TxHistoryResp{
		Records: txsPaged,
		Page:    pageResp,
	}, nil
}

func filterByDate(txs []TxHistoryRecord, start, end int64) []TxHistoryRecord {
	if start == 0 && end == 0 {
		return txs
	}

	var filteredTxs []TxHistoryRecord
	for _, tx := range txs {
		switch {
		case start > 0 && end > 0:
			if tx.CreatedAt.Unix() >= start && tx.CreatedAt.Unix() <= end {
				filteredTxs = append(filteredTxs, tx)
			}
		case start > 0 && end == 0:
			if tx.CreatedAt.Unix() >= start {
				filteredTxs = append(filteredTxs, tx)
			}
		case end > 0 && start == 0:
			if tx.CreatedAt.Unix() <= end {
				filteredTxs = append(filteredTxs, tx)
			}
		}
	}
	return filteredTxs
}

func (i *indexerService) GetVtxoChain(ctx context.Context, vtxoKey Outpoint, page *Page) (*VtxoChainResp, error) {
	chainMap := make(map[vtxoKeyWithCreatedAt]ChainWithExpiry)

	outpoint := domain.VtxoKey{
		Txid: vtxoKey.Txid,
		VOut: vtxoKey.Vout,
	}
	vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{outpoint})
	if err != nil {
		return nil, err
	}

	if len(vtxos) == 0 {
		return nil, fmt.Errorf("vtxo not found for outpoint: %v", outpoint)
	}
	vtxo := vtxos[0]

	if err := i.buildChain(ctx, vtxo, chainMap); err != nil {
		return nil, err
	}

	chainSlice := make([]vtxoKeyWithCreatedAt, 0, len(chainMap))
	for vtxo := range chainMap {
		chainSlice = append(chainSlice, vtxo)
	}

	sort.Slice(chainSlice, func(i, j int) bool {
		return chainSlice[i].CreatedAt > chainSlice[j].CreatedAt
	})

	pagedChainSlice, pageResp := paginate(chainSlice, page, maxPageSizeVtxoChain)

	chain := make([]ChainWithExpiry, 0, len(pagedChainSlice))
	for _, vtxo := range pagedChainSlice {
		chain = append(chain, chainMap[vtxo])
	}

	return &VtxoChainResp{
		Chain:              chain,
		Page:               pageResp,
		RootCommitmentTxid: vtxo.RootCommitmentTxid,
		Depth:              getMaxDepth(chainMap),
	}, nil
}

func (i *indexerService) buildChain(
	ctx context.Context,
	vtxo domain.Vtxo,
	chain map[vtxoKeyWithCreatedAt]ChainWithExpiry,
) error {
	key := vtxoKeyWithCreatedAt{
		VtxoKey:   vtxo.VtxoKey,
		CreatedAt: vtxo.CreatedAt,
	}
	if _, ok := chain[key]; !ok {
		chain[key] = ChainWithExpiry{
			Txid:      vtxo.Txid,
			Txs:       make([]ChainTx, 0),
			ExpiresAt: vtxo.ExpireAt,
		}
	} else {
		return nil
	}

	//finish chain if this is the leaf Vtxo
	if !vtxo.IsPending() {
		txs := chain[key].Txs
		txs = append(txs, ChainTx{
			Txid: vtxo.RootCommitmentTxid,
			Type: "commitment",
		})
		chain[key] = ChainWithExpiry{
			Txid:      vtxo.Txid,
			Txs:       txs,
			ExpiresAt: chain[key].ExpiresAt,
		}
		return nil
	}

	redeemPsbt, err := psbt.NewFromRawBytes(strings.NewReader(vtxo.RedeemTx), true)
	if err != nil {
		return err
	}

	for _, in := range redeemPsbt.UnsignedTx.TxIn {
		txs := chain[key].Txs
		txs = append(txs, ChainTx{
			Txid: in.PreviousOutPoint.Hash.String(),
			Type: "virtual",
		})
		chain[key] = ChainWithExpiry{
			Txid:      chain[key].Txid,
			Txs:       txs,
			ExpiresAt: chain[key].ExpiresAt,
		}
		parentOutpoint := domain.VtxoKey{
			Txid: in.PreviousOutPoint.Hash.String(),
			VOut: in.PreviousOutPoint.Index,
		}
		vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{parentOutpoint})
		if err != nil {
			return err
		}

		if len(vtxos) == 0 {
			return fmt.Errorf("vtxo not found for outpoint: %v", parentOutpoint)
		}

		if err := i.buildChain(ctx, vtxos[0], chain); err != nil {
			return err
		}
	}

	return nil
}

func (i *indexerService) GetVirtualTxs(ctx context.Context, txids []string, page *Page) (*VirtualTxsResp, error) {
	txs, err := i.repoManager.Rounds().GetTxsWithTxids(ctx, txids)
	if err != nil {
		return nil, err
	}

	virtualTxs, reps := paginate(txs, page, maxPageSizeVirtualTxs)

	return &VirtualTxsResp{
		Transactions: virtualTxs,
		Page:         reps,
	}, nil
}

func (i *indexerService) GetSweptCommitmentTx(ctx context.Context, txid string) (*SweptCommitmentTxResp, error) {
	// TODO currently not possible to find swept commitment tx, we need either to scan explorer which would be inefficient
	// or to store sweep txs it in the database

	return &SweptCommitmentTxResp{}, nil
}

func paginate[T any](items []T, params *Page, maxSize int32) ([]T, PageResp) {
	if params == nil {
		return items, PageResp{}
	}
	if params.PageSize <= 0 {
		params.PageSize = maxSize
	}
	if params.PageNum <= 0 {
		params.PageNum = 1
	}

	totalCount := int32(len(items))
	totalPages := int32(math.Ceil(float64(totalCount) / float64(params.PageSize)))
	next := min(params.PageNum+1, totalPages)

	resp := PageResp{
		Current: params.PageNum,
		Next:    next,
		Total:   totalPages,
	}

	if params.PageNum > totalPages && totalCount > 0 {
		return []T{}, resp
	}

	startIndex := (params.PageNum - 1) * params.PageSize
	endIndex := startIndex + params.PageSize

	if startIndex >= totalCount {
		return []T{}, resp
	}

	if endIndex > totalCount {
		endIndex = totalCount
	}

	return items[startIndex:endIndex], resp
}

func (i *indexerService) vtxosToTxs(
	ctx context.Context, spendable, spent []domain.Vtxo, roundTxids map[string]any,
) ([]TxHistoryRecord, error) {
	txs := make([]TxHistoryRecord, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx
	vtxosLeftToCheck := append([]domain.Vtxo{}, spent...)
	for _, vtxo := range append(spendable, spent...) {
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

		commitmentTxid := vtxo.RootCommitmentTxid
		virtualTxid := ""
		settled := !vtxo.IsPending()
		settledBy := ""
		if vtxo.IsPending() {
			virtualTxid = vtxo.Txid
			commitmentTxid = ""
			settled = vtxo.SpentBy != ""
			if _, ok := roundTxids[vtxo.SpentBy]; settled && ok {
				settledBy = vtxo.SpentBy
			}
		}

		txs = append(txs, TxHistoryRecord{
			CommitmentTxid: commitmentTxid,
			VirtualTxid:    virtualTxid,
			Amount:         vtxo.Amount - settleAmount - spentAmount,
			Type:           TxReceived,
			CreatedAt:      time.Unix(vtxo.CreatedAt, 0),
			Settled:        settled,
			SettledBy:      settledBy,
		})
	}

	// Sendings

	// All "spentBy" vtxos are payments unless:
	// - they are settlements

	// aggregate spent by spentId
	vtxosBySpentBy := make(map[string][]domain.Vtxo)
	for _, v := range spent {
		if len(v.SpentBy) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.SpentBy]; !ok {
			vtxosBySpentBy[v.SpentBy] = make([]domain.Vtxo, 0)
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
			// send all: fetch the created vtxo to source creation and expiration timestamps
			vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{{Txid: sb, VOut: 0}})
			if err != nil {
				return nil, err
			}
			vtxo = vtxos[0]
		}

		commitmentTxid := vtxo.RootCommitmentTxid
		virtualTxid := ""
		if vtxo.IsPending() {
			virtualTxid = vtxo.Txid
			commitmentTxid = ""
		}

		txs = append(txs, TxHistoryRecord{
			CommitmentTxid: commitmentTxid,
			VirtualTxid:    virtualTxid,
			Amount:         spentAmount - resultedAmount,
			Type:           TxSent,
			CreatedAt:      time.Unix(vtxo.CreatedAt, 0),
			Settled:        true,
		})

	}

	sort.SliceStable(txs, func(i, j int) bool {
		return txs[i].CreatedAt.After(txs[j].CreatedAt)
	})

	return txs, nil
}

func findVtxosSpentInSettlement(vtxos []domain.Vtxo, vtxo domain.Vtxo) []domain.Vtxo {
	if vtxo.IsPending() {
		return nil
	}
	return findVtxosSpent(vtxos, vtxo.RootCommitmentTxid)
}

func findVtxosSpent(vtxos []domain.Vtxo, id string) []domain.Vtxo {
	var result []domain.Vtxo
	leftVtxos := make([]domain.Vtxo, 0)
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

func reduceVtxosAmount(vtxos []domain.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []domain.Vtxo, vtxo domain.Vtxo) []domain.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSpentBy(vtxos []domain.Vtxo, spentByTxid string) []domain.Vtxo {
	var result []domain.Vtxo
	for _, v := range vtxos {
		if !v.IsPending() && v.RootCommitmentTxid == spentByTxid {
			result = append(result, v)
			break
		}
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []domain.Vtxo, spentByVtxos []domain.Vtxo) domain.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return domain.Vtxo{}
}

type vtxoKeyWithCreatedAt struct {
	domain.VtxoKey
	CreatedAt int64
}

func getMaxDepth(chainMap map[vtxoKeyWithCreatedAt]ChainWithExpiry) int32 {
	memo := make(map[string]int32)

	// Create a lookup from txid to ChainWithExpiry
	txidToChain := make(map[string]ChainWithExpiry)
	for _, chain := range chainMap {
		txidToChain[chain.Txid] = chain
	}

	// DFS function to get depth from a given txid
	var dfs func(string) int32
	dfs = func(txid string) int32 {
		if val, ok := memo[txid]; ok {
			return val
		}
		chain := txidToChain[txid]
		if len(chain.Txs) == 1 && chain.Txs[0].Type == "commitment" {
			memo[txid] = 1
			return 1
		}
		maxDepth := int32(0)
		for _, child := range chain.Txs {
			depth := dfs(child.Txid)
			maxDepth = max(depth, maxDepth)
		}
		memo[txid] = maxDepth + 1
		return memo[txid]
	}

	// Compute max depth starting from all root txids in the map
	max := int32(0)
	for _, chain := range chainMap {
		depth := dfs(chain.Txid)
		if depth > max {
			max = depth
		}
	}

	return max
}
