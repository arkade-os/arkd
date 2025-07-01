package application

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ark-network/ark/common/tree"
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
	vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, outpoints)
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
		indexedTxids := make(map[string]struct{})
		for _, vtxo := range spent {
			if vtxo.IsSettled() {
				indexedTxids[vtxo.SettledBy] = struct{}{}
			}
		}
		txids := make([]string, 0, len(spent))
		for txid := range indexedTxids {
			txids = append(txids, txid)
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
	chain := make([]ChainWithExpiry, 0)
	nextVtxos := []domain.Outpoint{vtxoKey}

	for len(nextVtxos) > 0 {
		vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, nextVtxos)
		if err != nil {
			return nil, err
		}

		if len(vtxos) == 0 {
			return nil, fmt.Errorf("vtxo not found for outpoint: %s", nextVtxos)
		}

		newNextVtxos := make([]domain.Outpoint, 0)

		for _, vtxo := range vtxos {
			// if the vtxo is preconfirmed, it means it has been created by an offchain tx
			// we need to add the virtual tx + the associated checkpoints txs
			// also, we have to populate the newNextVtxos with the checkpoints inputs
			// in order to continue the chain in the next iteration
			if vtxo.Preconfirmed {
				offchainTx, err := i.repoManager.OffchainTxs().GetOffchainTx(ctx, vtxo.Txid)
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve offchain tx: %s", err)
				}

				virtualTx := ChainWithExpiry{
					Txid:      vtxo.Txid,
					ExpiresAt: vtxo.ExpireAt,
					Type:      IndexerChainedTxTypeArk,
				}

				checkpointsTxs := make([]ChainWithExpiry, 0, len(offchainTx.CheckpointTxs))
				for _, b64 := range offchainTx.CheckpointTxs {
					ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
					if err != nil {
						return nil, fmt.Errorf("failed to deserialize checkpoint tx: %s", err)
					}

					txid := ptx.UnsignedTx.TxID()
					checkpointsTxs = append(checkpointsTxs, ChainWithExpiry{
						Txid:      txid,
						ExpiresAt: vtxo.ExpireAt,
						Type:      IndexerChainedTxTypeCheckpoint,
						Spends:    []string{ptx.UnsignedTx.TxIn[0].PreviousOutPoint.String()},
					})

					virtualTx.Spends = append(virtualTx.Spends, txid)

					// populate newNextVtxos with checkpoints inputs
					for _, in := range ptx.UnsignedTx.TxIn {
						newNextVtxos = append(newNextVtxos, domain.Outpoint{Txid: in.PreviousOutPoint.Hash.String(), VOut: in.PreviousOutPoint.Index})
					}
				}

				chain = append(chain, virtualTx)
				chain = append(chain, checkpointsTxs...)

				continue
			}

			// if the vtxo is not preconfirmed, it means it's a leaf of a batch tree
			// add the branch until the commitment tx
			vtxoTree, err := i.GetVtxoTree(ctx, Outpoint{
				Txid: vtxo.RootCommitmentTxid,
				VOut: 0,
			}, nil)
			if err != nil {
				return nil, err
			}

			graph, err := tree.NewTxGraph(vtxoTree.Nodes)
			if err != nil {
				return nil, err
			}
			branch, err := graph.SubGraph([]string{vtxo.Txid})
			if err != nil {
				return nil, err
			}

			fromRootToVtxo := make([]string, 0)
			if err := branch.Apply(func(tx *tree.TxGraph) (bool, error) {
				fromRootToVtxo = append(fromRootToVtxo, tx.Root.UnsignedTx.TxID())
				return true, nil
			}); err != nil {
				return nil, err
			}

			// reverse fromRootToVtxo
			fromVtxoToRoot := make([]ChainWithExpiry, 0, len(fromRootToVtxo))
			for i := len(fromRootToVtxo) - 1; i >= 0; i-- {
				fromVtxoToRoot = append(fromVtxoToRoot, ChainWithExpiry{
					Txid:      fromRootToVtxo[i],
					ExpiresAt: vtxo.ExpireAt,
					Type:      IndexerChainedTxTypeTree,
				})
			}

			for i := 0; i < len(fromVtxoToRoot); i++ {
				if i == len(fromVtxoToRoot)-1 {
					// the last tx is the root of the branch, always spend the commitment tx
					fromVtxoToRoot[i].Spends = []string{vtxo.RootCommitmentTxid}
				} else {
					// the other txs spend the next one
					fromVtxoToRoot[i].Spends = []string{fromVtxoToRoot[i+1].Txid}
				}
			}

			chain = append(chain, fromVtxoToRoot...)
			chain = append(chain, ChainWithExpiry{
				Txid:      vtxo.RootCommitmentTxid,
				ExpiresAt: vtxo.ExpireAt,
				Type:      IndexerChainedTxTypeCommitment,
			})
		}

		nextVtxos = newNextVtxos
	}

	pagedChainSlice, pageResp := paginate(chain, page, maxPageSizeVtxoChain)

	return &VtxoChainResp{
		Chain: pagedChainSlice,
		Page:  pageResp,
	}, nil
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
			continue // settlement, ignore
		}

		spentVtxos := findVtxosSpentInPayment(vtxosLeftToCheck, vtxo)
		spentAmount := reduceVtxosAmount(spentVtxos)
		if vtxo.Amount <= spentAmount {
			continue // change, ignore
		}

		commitmentTxid := vtxo.RootCommitmentTxid
		virtualTxid := ""
		settled := !vtxo.Preconfirmed
		settledBy := ""
		if vtxo.Preconfirmed {
			virtualTxid = vtxo.Txid
			commitmentTxid = ""
			settled = vtxo.Spent
			settledBy = vtxo.SettledBy
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
		if v.IsSettled() {
			continue
		}

		if _, ok := vtxosBySpentBy[v.ArkTxid]; !ok {
			vtxosBySpentBy[v.ArkTxid] = make([]domain.Vtxo, 0)
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
			vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{{Txid: sb, VOut: 0}})
			if err != nil {
				return nil, err
			}
			vtxo = vtxos[0]
		}

		commitmentTxid := vtxo.RootCommitmentTxid
		virtualTxid := ""
		if vtxo.Preconfirmed {
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
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSettled(vtxos, vtxo.RootCommitmentTxid)
}

func findVtxosSettled(vtxos []domain.Vtxo, id string) []domain.Vtxo {
	var result []domain.Vtxo
	leftVtxos := make([]domain.Vtxo, 0)
	for _, v := range vtxos {
		if v.SettledBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func findVtxosSpent(vtxos []domain.Vtxo, id string) []domain.Vtxo {
	var result []domain.Vtxo
	leftVtxos := make([]domain.Vtxo, 0)
	for _, v := range vtxos {
		if v.ArkTxid == id {
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
