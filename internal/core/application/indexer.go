package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	maxPageSizeVtxoTree       = 300
	maxPageSizeForfeitTxs     = 500
	maxPageSizeSpendableVtxos = 100
	maxPageSizeVtxoChain      = 100
	maxPageSizeVirtualTxs     = 100

	defaultAuthTokenTTL = 5 * time.Minute
)

var ErrInvalidInput = errors.New("invalid input")

type exposure string

const (
	exposurePublic   exposure = "public"
	exposureWithheld exposure = "withheld"
	exposurePrivate  exposure = "private"
)

type Intent struct {
	Proof   string
	Message string
}

type IndexerService interface {
	GetCommitmentTxInfo(ctx context.Context, txid string) (*CommitmentTxInfo, error)
	GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, page *Page) (*TreeTxResp, error)
	GetVtxoTreeLeaves(
		ctx context.Context, batchOutpoint Outpoint, page *Page,
	) (*VtxoTreeLeavesResp, error)
	GetForfeitTxs(ctx context.Context, txid string, page *Page) (*ForfeitTxsResp, error)
	GetConnectors(ctx context.Context, txid string, page *Page) (*TreeTxResp, error)
	GetVtxos(
		ctx context.Context,
		pubkeys []string, spendableOnly, spendOnly, recoverableOnly, pendingOnly bool,
		after, before int64, page *Page,
	) (*GetVtxosResp, error)
	GetVtxosByOutpoint(
		ctx context.Context, outpoints []Outpoint, page *Page,
	) (*GetVtxosResp, error)
	GetVtxoChain(
		ctx context.Context, authToken string, vtxoKey Outpoint, page *Page,
	) (*VtxoChainResp, error)
	GetVtxoChainByIntent(ctx context.Context, intent Intent, page *Page) (*VtxoChainResp, error)
	GetVirtualTxs(
		ctx context.Context, authToken string, txids []string, page *Page,
	) (*VirtualTxsResp, error)
	GetVirtualTxsByIntent(ctx context.Context, intent Intent, page *Page) (*VirtualTxsResp, error)
	GetBatchSweepTxs(ctx context.Context, batchOutpoint Outpoint) ([]string, error)
	GetAsset(ctx context.Context, assetID string) ([]Asset, error)
	ListTokens(ctx context.Context, token, hash, outpoint, txid string) ([]TokenEntry, error)
	RevokeTokens(ctx context.Context, token, hash, outpoint, txid string) (int, error)
}

type indexerService struct {
	repoManager  ports.RepoManager
	wallet       ports.WalletService
	authPrvkey   *btcec.PrivateKey // key used to sign auth tokens
	signerPubkey *btcec.PublicKey  // server's signing key, used for stripping signatures from txs
	txExposure   exposure
	authTokenTTL time.Duration
	tokenCache   *tokenCache
}

func NewIndexerService(
	repoManager ports.RepoManager,
	wallet ports.WalletService,
	privkey *btcec.PrivateKey,
	signerPubkey *btcec.PublicKey,
	txExposure string,
	authTokenExpirySec int64,
) (IndexerService, error) {
	// validate txExposure
	switch exposure(txExposure) {
	case exposurePublic, exposureWithheld, exposurePrivate:
	default:
		return nil, fmt.Errorf("invalid exposure value: %q", txExposure)
	}

	ttl := defaultAuthTokenTTL
	if authTokenExpirySec > 0 {
		ttl = time.Duration(authTokenExpirySec) * time.Second
	}

	svc := &indexerService{
		repoManager:  repoManager,
		wallet:       wallet,
		authPrvkey:   privkey,
		txExposure:   exposure(txExposure),
		authTokenTTL: ttl,
		tokenCache:   newTokenCache(ttl),
	}

	if signerPubkey != nil {
		svc.signerPubkey = signerPubkey
	}
	return svc, nil
}

func (i *indexerService) GetCommitmentTxInfo(
	ctx context.Context, txid string,
) (*CommitmentTxInfo, error) {
	roundStats, err := i.repoManager.Rounds().GetRoundStats(ctx, txid)
	if err != nil {
		return nil, err
	}
	if roundStats == nil {
		return nil, fmt.Errorf("batch not found")
	}

	batches := map[VOut]Batch{
		0: {
			TotalOutputAmount: roundStats.TotalBatchAmount,
			TotalOutputVtxos:  roundStats.TotalOutputVtxos,
			ExpiresAt:         roundStats.ExpiresAt,
			Swept:             roundStats.Swept,
		},
	}

	return &CommitmentTxInfo{
		StartedAt:         roundStats.Started,
		EndAt:             roundStats.Ended,
		Batches:           batches,
		TotalInputAmount:  roundStats.TotalForfeitAmount,
		TotalInputVtxos:   roundStats.TotalInputVtxos,
		TotalOutputVtxos:  roundStats.TotalOutputVtxos,
		TotalOutputAmount: roundStats.TotalBatchAmount,
	}, nil
}

func (i *indexerService) GetVtxoTree(
	ctx context.Context, batchOutpoint Outpoint, page *Page,
) (*TreeTxResp, error) {
	vtxoTree, err := i.repoManager.Rounds().GetRoundVtxoTree(ctx, batchOutpoint.Txid)
	if err != nil {
		return nil, err
	}

	txs, pageResp := paginate(vtxoTree, page, maxPageSizeVtxoTree)
	return &TreeTxResp{
		Txs:  txs,
		Page: pageResp,
	}, nil
}

func (i *indexerService) GetAsset(
	ctx context.Context, assetId string,
) ([]Asset, error) {
	assets, err := i.repoManager.Assets().GetAssets(ctx, []string{assetId})
	if err != nil {
		return nil, err
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("asset %s not found", assetId)
	}
	return assets, nil
}

func (i *indexerService) GetVtxoTreeLeaves(
	ctx context.Context, outpoint Outpoint, page *Page,
) (*VtxoTreeLeavesResp, error) {
	vtxos, err := i.repoManager.Vtxos().GetLeafVtxosForBatch(ctx, outpoint.Txid)
	if err != nil {
		return nil, err
	}

	leaves, pageResp := paginate(vtxos, page, maxPageSizeVtxoTree)
	return &VtxoTreeLeavesResp{
		Leaves: leaves,
		Page:   pageResp,
	}, nil
}

func (i *indexerService) GetForfeitTxs(
	ctx context.Context, txid string, page *Page,
) (*ForfeitTxsResp, error) {
	forfeitTxs, err := i.repoManager.Rounds().GetRoundForfeitTxs(ctx, txid)
	if err != nil {
		return nil, err
	}

	list := make([]string, 0, len(forfeitTxs))
	for _, tx := range forfeitTxs {
		list = append(list, tx.Txid)
	}

	txs, pageResp := paginate(list, page, maxPageSizeForfeitTxs)
	return &ForfeitTxsResp{
		Txs:  txs,
		Page: pageResp,
	}, nil

}

func (i *indexerService) GetConnectors(
	ctx context.Context, txid string, page *Page,
) (*TreeTxResp, error) {
	connectorTree, err := i.repoManager.Rounds().GetRoundConnectorTree(ctx, txid)
	if err != nil {
		return nil, err
	}

	txs, pageResp := paginate(connectorTree, page, maxPageSizeVtxoTree)
	return &TreeTxResp{
		Txs:  txs,
		Page: pageResp,
	}, nil
}

func (i *indexerService) GetVtxos(
	ctx context.Context,
	pubkeys []string,
	spendableOnly, spentOnly, recoverableOnly, pendingOnly bool,
	after, before int64,
	page *Page,
) (*GetVtxosResp, error) {
	if err := validateTimeRange(after, before); err != nil {
		return nil, err
	}
	options := []bool{spendableOnly, spentOnly, recoverableOnly, pendingOnly}
	count := 0
	for _, v := range options {
		if v {
			count++
		}
	}
	if count > 1 {
		return nil, fmt.Errorf(
			"spendable, spent, recoverable and pending filters are mutually exclusive",
		)
	}

	var allVtxos []domain.Vtxo
	var err error
	if pendingOnly {
		allVtxos, err = i.repoManager.Vtxos().
			GetPendingSpentVtxosWithPubKeys(ctx, pubkeys, after, before)
		if err != nil {
			return nil, err
		}
	} else {
		allVtxos, err = i.repoManager.Vtxos().GetAllVtxosWithPubKeys(ctx, pubkeys, after, before)
		if err != nil {
			return nil, err
		}

		if spendableOnly {
			spendableVtxos := make([]domain.Vtxo, 0, len(allVtxos))
			for _, vtxo := range allVtxos {
				if !vtxo.Spent && !vtxo.Swept && !vtxo.Unrolled {
					spendableVtxos = append(spendableVtxos, vtxo)
				}
			}
			allVtxos = spendableVtxos
		}
		if spentOnly {
			spentVtxos := make([]domain.Vtxo, 0, len(allVtxos))
			for _, vtxo := range allVtxos {
				if vtxo.Spent || vtxo.Swept || vtxo.Unrolled {
					spentVtxos = append(spentVtxos, vtxo)
				}
			}
			allVtxos = spentVtxos
		}
		if recoverableOnly {
			recoverableVtxos := make([]domain.Vtxo, 0, len(allVtxos))
			for _, vtxo := range allVtxos {
				if !vtxo.RequiresForfeit() && !vtxo.Spent && !vtxo.Unrolled {
					recoverableVtxos = append(recoverableVtxos, vtxo)
				}
			}
			allVtxos = recoverableVtxos
		}
	}

	vtxos, pageResp := paginate(allVtxos, page, maxPageSizeSpendableVtxos)
	return &GetVtxosResp{
		Vtxos: vtxos,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetVtxosByOutpoint(
	ctx context.Context, outpoints []Outpoint, page *Page,
) (*GetVtxosResp, error) {
	allVtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, outpoints)
	if err != nil {
		return nil, err
	}

	vtxos, pageResp := paginate(allVtxos, page, maxPageSizeSpendableVtxos)
	return &GetVtxosResp{
		Vtxos: vtxos,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetVtxoChain(
	ctx context.Context, authToken string, outpoint Outpoint, page *Page,
) (*VtxoChainResp, error) {
	switch i.txExposure {
	case exposurePublic:
		// Nothing to do
	case exposureWithheld:
		// Auth token is optional, validate it only if provided
		if authToken != "" {
			hash, err := i.validateAuthToken(authToken)
			if err != nil {
				return nil, err
			}

			outpoints, _, ok := i.tokenCache.getOutpoints(hash)
			if !ok {
				return nil, fmt.Errorf("auth token not found")
			}
			if _, ok := outpoints[outpoint.String()]; !ok {
				return nil, fmt.Errorf("auth token is not for outpoint %s", outpoint)
			}
		}
	case exposurePrivate:
		// Auth token is mandatory, always validate it
		hash, err := i.validateAuthToken(authToken)
		if err != nil {
			return nil, err
		}

		outpoints, _, ok := i.tokenCache.getOutpoints(hash)
		if !ok {
			return nil, fmt.Errorf("auth token not found")
		}
		if _, ok := outpoints[outpoint.String()]; !ok {
			return nil, fmt.Errorf("auth token is not for outpoint %s", outpoint)
		}
	}
	resp, _, err := i.getVtxoChain(ctx, outpoint, page)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (i *indexerService) GetVtxoChainByIntent(
	ctx context.Context, intent Intent, page *Page,
) (*VtxoChainResp, error) {
	outpoints, err := i.extractOutpointsFromIntent(intent)
	if err != nil {
		return nil, err
	}
	if len(outpoints) > 1 {
		return nil, fmt.Errorf("only one outpoint expected in intent proof")
	}
	outpoint := outpoints[0]

	switch i.txExposure {
	case exposurePublic:
		resp, _, err := i.getVtxoChain(ctx, outpoint, page)
		return resp, err
	case exposureWithheld, exposurePrivate:
		if err := i.validateIntent(ctx, intent); err != nil {
			return nil, err
		}
	}

	resp, allOutpoints, err := i.getVtxoChain(ctx, outpoint, page)
	if err != nil {
		return nil, err
	}

	token, err := i.createAuthToken(allOutpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth token: %w", err)
	}
	resp.AuthToken = token
	return resp, nil
}

func (i *indexerService) GetVirtualTxs(
	ctx context.Context, authToken string, txids []string, page *Page,
) (*VirtualTxsResp, error) {
	var valid bool
	switch i.txExposure {
	case exposurePublic:
		valid = true
		// Nothing to do
	case exposureWithheld:
		// Auth token is optional, and if it's invalid fallback to stripping the signer sigs
		if authToken != "" {
			hash, err := i.validateAuthToken(authToken)
			if err != nil {
				return nil, err
			}

			txidWhitelist, ok := i.tokenCache.getTxids(hash)
			if !ok {
				break
			}
			valid = true
			for _, txid := range txids {
				if _, ok := txidWhitelist[txid]; !ok {
					valid = false
					break
				}
			}
		}
	case exposurePrivate:
		// Auth token is mandatory, always validate it
		hash, err := i.validateAuthToken(authToken)
		if err != nil {
			return nil, err
		}

		txidWhitelist, ok := i.tokenCache.getTxids(hash)
		if !ok {
			return nil, fmt.Errorf("auth token not found")
		}
		for _, txid := range txids {
			if _, ok := txidWhitelist[txid]; !ok {
				return nil, fmt.Errorf("auth token is not for txid %s", txid)
			}
		}
		valid = true
	}

	resp, err := i.getVirtualTxs(ctx, txids, page, "")
	if err != nil {
		return nil, err
	}
	if !valid {
		if err := i.stripSignerSignatures(resp.Txs); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (i *indexerService) GetVirtualTxsByIntent(
	ctx context.Context, intent Intent, page *Page,
) (*VirtualTxsResp, error) {
	outpoints, err := i.extractOutpointsFromIntent(intent)
	if err != nil {
		return nil, err
	}
	txids := make([]string, 0, len(outpoints))
	for _, outpoint := range outpoints {
		txids = append(txids, outpoint.Txid)
	}

	switch i.txExposure {
	case exposurePublic:
		return i.getVirtualTxs(ctx, txids, page, "")
	case exposureWithheld, exposurePrivate:
		if err := i.validateIntent(ctx, intent); err != nil {
			return nil, err
		}
	}

	token, err := i.createAuthToken(outpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth token: %w", err)
	}

	return i.getVirtualTxs(ctx, txids, page, token)
}

func (i *indexerService) GetBatchSweepTxs(
	ctx context.Context, batchOutpoint Outpoint,
) ([]string, error) {
	sweepTxs, err := i.repoManager.Rounds().GetSweepTxs(ctx, batchOutpoint.Txid)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(sweepTxs))
	for txid := range sweepTxs {
		txids = append(txids, txid)
	}

	return txids, nil
}

func (i *indexerService) getVtxoChain(
	ctx context.Context, vtxoKey Outpoint, page *Page,
) (*VtxoChainResp, []Outpoint, error) {
	chain, allOutpoints, err := i.buildVtxoChain(ctx, vtxoKey)
	if err != nil {
		return nil, nil, err
	}

	txChain, pageResp := paginate(chain, page, maxPageSizeVtxoChain)
	return &VtxoChainResp{
		Chain: txChain,
		Page:  pageResp,
	}, allOutpoints, nil
}

// buildVtxoChain builds the full chain of transactions for a given vtxo outpoint.
func (i *indexerService) buildVtxoChain(
	ctx context.Context, outpoint Outpoint,
) ([]ChainTx, []Outpoint, error) {
	chain := make([]ChainTx, 0)
	nextVtxos := []domain.Outpoint{outpoint}
	visited := make(map[string]bool)
	allOutpoints := make([]Outpoint, 0)

	for len(nextVtxos) > 0 {
		vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, nextVtxos)
		if err != nil {
			return nil, nil, err
		}
		if len(vtxos) == 0 {
			return nil, nil, fmt.Errorf("vtxo not found for outpoint: %v", nextVtxos)
		}

		newNextVtxos := make([]domain.Outpoint, 0)
		for _, vtxo := range vtxos {
			key := vtxo.Outpoint.String()
			if visited[key] {
				continue
			}
			allOutpoints = append(allOutpoints, vtxo.Outpoint)
			visited[key] = true

			// if the vtxo is preconfirmed, it means it has been created by an offchain tx
			// we need to add the virtual tx + the associated checkpoints txs
			// also, we have to populate the newNextVtxos with the checkpoints inputs
			// in order to continue the chain in the next iteration
			if vtxo.Preconfirmed {
				offchainTx, err := i.repoManager.OffchainTxs().GetOffchainTx(ctx, vtxo.Txid)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to retrieve offchain tx: %s", err)
				}

				chainTx := ChainTx{
					Txid:      vtxo.Txid,
					ExpiresAt: vtxo.ExpiresAt,
					Type:      IndexerChainedTxTypeArk,
				}

				checkpointTxs := make([]ChainTx, 0, len(offchainTx.CheckpointTxs))
				for _, b64 := range offchainTx.CheckpointTxs {
					ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
					if err != nil {
						return nil, nil, fmt.Errorf("failed to deserialize checkpoint tx: %s", err)
					}

					txid := ptx.UnsignedTx.TxID()
					checkpointTxs = append(checkpointTxs, ChainTx{
						Txid:      txid,
						ExpiresAt: vtxo.ExpiresAt,
						Type:      IndexerChainedTxTypeCheckpoint,
						Spends:    []string{ptx.UnsignedTx.TxIn[0].PreviousOutPoint.String()},
					})

					chainTx.Spends = append(chainTx.Spends, txid)

					// populate newNextVtxos with checkpoints inputs
					for _, in := range ptx.UnsignedTx.TxIn {
						if !visited[in.PreviousOutPoint.String()] {
							newNextVtxos = append(newNextVtxos, domain.Outpoint{
								Txid: in.PreviousOutPoint.Hash.String(),
								VOut: in.PreviousOutPoint.Index,
							})
						}
					}
				}

				chain = append(chain, chainTx)
				chain = append(chain, checkpointTxs...)
				continue
			}

			// if the vtxo is not preconfirmed, it means it's a leaf of a batch tree
			// add the branch until the commitment tx
			flatVtxoTree, err := i.repoManager.Rounds().GetRoundVtxoTree(ctx, vtxo.RootCommitmentTxid)
			if err != nil {
				return nil, nil, err
			}

			vtxoTree, err := tree.NewTxTree(flatVtxoTree)
			if err != nil {
				return nil, nil, err
			}
			branch, err := vtxoTree.SubTree([]string{vtxo.Txid})
			if err != nil {
				return nil, nil, err
			}

			fromRootToVtxo := make([]string, 0)
			if err := branch.Apply(func(tx *tree.TxTree) (bool, error) {
				fromRootToVtxo = append(fromRootToVtxo, tx.Root.UnsignedTx.TxID())
				return true, nil
			}); err != nil {
				return nil, nil, err
			}

			// reverse fromRootToVtxo
			fromVtxoToRoot := make([]ChainTx, 0, len(fromRootToVtxo))
			for i := len(fromRootToVtxo) - 1; i >= 0; i-- {
				fromVtxoToRoot = append(fromVtxoToRoot, ChainTx{
					Txid:      fromRootToVtxo[i],
					ExpiresAt: vtxo.ExpiresAt,
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
			chain = append(chain, ChainTx{
				Txid:      vtxo.RootCommitmentTxid,
				ExpiresAt: vtxo.ExpiresAt,
				Type:      IndexerChainedTxTypeCommitment,
			})

			for _, txid := range fromRootToVtxo {
				allOutpoints = append(allOutpoints, Outpoint{
					Txid: txid,
					VOut: 0,
				})
			}
		}

		nextVtxos = newNextVtxos
	}

	return chain, allOutpoints, nil
}

func (i *indexerService) getVirtualTxs(
	ctx context.Context, txids []string, page *Page, authToken string,
) (*VirtualTxsResp, error) {
	txs, err := i.repoManager.Rounds().GetTxsWithTxids(ctx, txids)
	if err != nil {
		return nil, err
	}
	virtualTxs, resp := paginate(txs, page, maxPageSizeVirtualTxs)
	return &VirtualTxsResp{
		Txs:       virtualTxs,
		Page:      resp,
		AuthToken: authToken,
	}, nil
}

func (i *indexerService) stripSignerSignatures(virtualTxs []string) error {
	signerPubkey := schnorr.SerializePubKey(i.signerPubkey)

	for idx := range virtualTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(virtualTxs[idx]), true)
		if err != nil {
			return fmt.Errorf("failed to deserialize virtual tx: %s", err)
		}

		// Remove arkd taproot script spend signatures from each input
		for j := range ptx.Inputs {
			// If this is a tree tx, strip the musig signature
			if len(ptx.Inputs[j].TaprootKeySpendSig) > 0 {
				ptx.Inputs[j].TaprootKeySpendSig = nil
				continue
			}

			newSigs := make([]*psbt.TaprootScriptSpendSig, 0)
			for _, sig := range ptx.Inputs[j].TaprootScriptSpendSig {
				if !bytes.Equal(sig.XOnlyPubKey, signerPubkey) {
					newSigs = append(newSigs, sig)
				}
			}
			ptx.Inputs[j].TaprootScriptSpendSig = newSigs
		}

		var b bytes.Buffer
		if err := ptx.Serialize(&b); err != nil {
			return fmt.Errorf("failed to serialize virtual tx: %s", err)
		}
		virtualTxs[idx] = base64.StdEncoding.EncodeToString(b.Bytes())
	}
	return nil
}

// Similar flow in DeleteIntentsByProof inside internal/core/application/service.go
func (i *indexerService) validateIntent(ctx context.Context, intentToValidate Intent) error {
	if intentToValidate.Proof == "" {
		return fmt.Errorf("missing intent tx")
	}

	// Message content is not validated here. Ownership is proved by the PSBT
	// structure (inputs must reference real VTXOs with matching scripts/values).
	// validate proof
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(intentToValidate.Proof), true)
	if err != nil {
		return fmt.Errorf("failed to parse intent tx: %s", err)
	}
	if len(ptx.Inputs) <= 1 {
		return fmt.Errorf("not enough inputs in intent tx, expected at least 2")
	}

	outpoints := intent.Proof{Packet: *ptx}.GetOutpoints()

	boardingTxs := make(map[string]wire.MsgTx)
	for idx, outpoint := range outpoints {
		txInIndex := idx + 1
		txIn := ptx.Inputs[txInIndex]

		if len(txIn.TaprootLeafScript) == 0 {
			return fmt.Errorf("missing taproot leaf script on intent tx input %d", txInIndex)
		}
		if txIn.WitnessUtxo == nil {
			return fmt.Errorf("missing witness utxo on intent tx input %d", txInIndex)
		}

		vtxoOutpoint := domain.Outpoint{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		vtxosResult, err := i.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxoOutpoint})
		if err != nil || len(vtxosResult) == 0 {
			if _, ok := boardingTxs[vtxoOutpoint.Txid]; !ok {
				txhex, err := i.wallet.GetTransaction(ctx, vtxoOutpoint.Txid)
				if err != nil {
					return fmt.Errorf(
						"failed to get boarding tx %s for intent tx input %d: %s",
						vtxoOutpoint.Txid, txInIndex, err,
					)
				}
				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return fmt.Errorf(
						"failed to deserialize boarding tx %s for intent tx input %d: %s",
						vtxoOutpoint.Txid, txInIndex, err,
					)
				}

				boardingTxs[vtxoOutpoint.Txid] = tx
			}

			tx := boardingTxs[vtxoOutpoint.Txid]
			if int(vtxoOutpoint.VOut) >= len(tx.TxOut) {
				return fmt.Errorf(
					"malformed intent tx input %d: vout %d exceed num of tx outputs %d",
					txInIndex, vtxoOutpoint.VOut, len(tx.TxOut),
				)
			}
			prevout := tx.TxOut[vtxoOutpoint.VOut]

			if !bytes.Equal(prevout.PkScript, txIn.WitnessUtxo.PkScript) {
				return fmt.Errorf(
					"malformed intent tx input %d: got prevout script %x, expected %x",
					txInIndex, prevout.PkScript, txIn.WitnessUtxo.PkScript,
				)
			}

			if prevout.Value != int64(txIn.WitnessUtxo.Value) {
				return fmt.Errorf(
					"malformed intent tx input %d: got prevout value %d, expected %d",
					txInIndex, prevout.Value, txIn.WitnessUtxo.Value,
				)
			}

			continue
		}

		vtxo := vtxosResult[0]

		if txIn.WitnessUtxo.Value != int64(vtxo.Amount) {
			return fmt.Errorf(
				"malformed intent tx input %d: got prevout value %d, expected %d",
				txInIndex, txIn.WitnessUtxo.Value, vtxo.Amount,
			)
		}

		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return fmt.Errorf(
				"failed to decode vtxo script for intent tx input %d: %w", txInIndex, err,
			)
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return fmt.Errorf(
				"failed to parse vtxo xOnly key for intent tx input %d: %w", txInIndex, err,
			)
		}

		pkScript, err := script.P2TRScript(pubkey)
		if err != nil {
			return fmt.Errorf(
				"failed to compute P2TR script from vtxo script for intent tx input %d: %w",
				txInIndex, err,
			)
		}

		if !bytes.Equal(pkScript, txIn.WitnessUtxo.PkScript) {
			return fmt.Errorf(
				"malformed intent tx input %d: got witness utxo script %x, expected %x",
				txInIndex, txIn.WitnessUtxo.PkScript, pkScript,
			)
		}
	}

	return intent.Verify(
		intentToValidate.Proof, intentToValidate.Message, []*btcec.PublicKey{i.signerPubkey},
	)
}

// extractOutpointFromIntent parses the intent proof and returns all input outpoints
// (excluding the toSpend, ie. the very first one).
func (i *indexerService) extractOutpointsFromIntent(intentToParse Intent) ([]Outpoint, error) {
	if intentToParse.Proof == "" {
		return nil, fmt.Errorf("missing intent proof tx")
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(intentToParse.Proof), true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intent proof tx: %s", err)
	}

	outs := intent.Proof{Packet: *ptx}.GetOutpoints()
	if len(outs) == 0 {
		return nil, fmt.Errorf("no outpoints found in intent proof tx")
	}

	outpoints := make([]Outpoint, 0, len(outs))
	for _, out := range outs {
		outpoints = append(outpoints, Outpoint{
			Txid: out.Hash.String(),
			VOut: out.Index,
		})
	}
	return outpoints, nil
}

// createAuthToken creates a signed auth token for accessing virtual txs.
// Format: base64(hash(order(outpoints))(32)|timestamp(8)|signature(64))
func (i *indexerService) createAuthToken(outpoints []Outpoint) (string, error) {
	now := time.Now()

	hash, err := hashOutpoints(outpoints)
	if err != nil {
		return "", fmt.Errorf("failed to hash outpoints: %s", err)
	}
	hashStr := hex.EncodeToString(hash)

	_, expiry, tokenExists := i.tokenCache.getOutpoints(hashStr)
	if tokenExists {
		// If token already exists, reuse the original timestamp to generate the same token
		now = expiry.Add(-i.tokenCache.invalidationDuration)
	}

	msg := make([]byte, 32+8)
	copy(msg[0:32], hash)
	binary.BigEndian.PutUint64(msg[32:40], uint64(now.Unix()))

	// Sign the message
	msgHash := chainhash.HashB(msg)
	sig, err := schnorr.Sign(i.authPrvkey, msgHash)
	if err != nil {
		return "", fmt.Errorf("failed to sign auth token: %w", err)
	}
	sigBytes := sig.Serialize()

	// Combine message + signature and encode as base64
	token := make([]byte, len(msg)+len(sigBytes))
	copy(token[0:len(msg)], msg)
	copy(token[len(msg):], sigBytes)

	// Even if tokenCache.add is no-op if hash already exists,
	// we explicitly prevent invoking it as best practice
	if !tokenExists {
		i.tokenCache.add(hashStr, outpoints, now)
	}

	return base64.StdEncoding.EncodeToString(token), nil
}

// validateAuthToken validates a signed auth token.
// Returns the outpoints hash encoded in the token and true if the signature is valid and
// the token has not expired.
func (i *indexerService) validateAuthToken(authToken string) (string, error) {
	if authToken == "" {
		return "", fmt.Errorf("missing auth")
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		return "", fmt.Errorf("invalid auth token format, must be base64")
	}

	// Token format: msg (40 bytes: hash 32 + timestamp 8) + schnorr signature (64 bytes)
	if len(tokenBytes) != 40+64 {
		return "", fmt.Errorf("invalid auth token length")
	}

	msg := tokenBytes[0:40]
	sigBytes := tokenBytes[40:]

	// Extract timestamp and check expiry
	tsSec := binary.BigEndian.Uint64(msg[32:40])
	tokenTime := time.Unix(int64(tsSec), 0)
	if time.Since(tokenTime) > i.authTokenTTL {
		return "", fmt.Errorf("auth token expired")
	}

	// Verify schnorr signature
	msgHash := chainhash.HashB(msg)
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse auth token signature: %w", err)
	}

	if !sig.Verify(msgHash, i.authPrvkey.PubKey()) {
		return "", fmt.Errorf("signature verification failed")
	}

	return hex.EncodeToString(msg[:32]), nil
}

// extractTokenHash decodes an auth token and returns the outpoints hash
// without checking expiry. Signature is still verified.
func (i *indexerService) extractTokenHash(authToken string) (string, error) {
	if i.authPrvkey == nil {
		return "", fmt.Errorf(
			"%w: token filter not available in public exposure mode",
			ErrInvalidInput,
		)
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		return "", fmt.Errorf("%w: invalid auth token format, must be base64", ErrInvalidInput)
	}
	if len(tokenBytes) != 40+64 {
		return "", fmt.Errorf("%w: invalid auth token length", ErrInvalidInput)
	}

	return hex.EncodeToString(tokenBytes[:32]), nil
}

func (i *indexerService) resolveTokenFilter(
	token, hash string,
) (string, error) {
	if token != "" {
		return i.extractTokenHash(token)
	}
	return hash, nil
}

// normalizeOutpoint validates and normalizes an outpoint string (txid:vout).
// Returns empty string if input is empty.
func normalizeOutpoint(outpoint string) (string, error) {
	if outpoint == "" {
		return "", nil
	}
	var op Outpoint
	if err := op.FromString(outpoint); err != nil {
		return "", fmt.Errorf("%w: invalid outpoint filter: %w", ErrInvalidInput, err)
	}
	return op.String(), nil
}

func (i *indexerService) ListTokens(
	_ context.Context, token, hash, outpoint, txid string,
) ([]TokenEntry, error) {
	h, err := i.resolveTokenFilter(token, hash)
	if err != nil {
		return nil, err
	}
	op, err := normalizeOutpoint(outpoint)
	if err != nil {
		return nil, err
	}
	return i.tokenCache.list(h, op, txid), nil
}

func (i *indexerService) RevokeTokens(
	_ context.Context, token, hash, outpoint, txid string,
) (int, error) {
	h, err := i.resolveTokenFilter(token, hash)
	if err != nil {
		return 0, err
	}
	op, err := normalizeOutpoint(outpoint)
	if err != nil {
		return 0, err
	}
	if h == "" && op == "" && txid == "" {
		return 0, fmt.Errorf("%w: at least one filter is required", ErrInvalidInput)
	}
	return i.tokenCache.revoke(h, op, txid), nil
}

// hashOutpoints clones the given outpoints, sorts them lexicographically by txid and vout,
// and returns the sha256 hash of the concatenation of their txid and vout.
func hashOutpoints(outpoints []Outpoint) ([]byte, error) {
	outs := slices.Clone(outpoints)
	sort.SliceStable(outs, func(i, j int) bool {
		if outs[i].Txid != outs[j].Txid {
			return outs[i].Txid < outs[j].Txid
		}
		return outs[i].VOut < outs[j].VOut
	})

	var buf bytes.Buffer
	for _, out := range outs {
		// Decode txid from hex
		txidBytes, err := hex.DecodeString(out.Txid)
		if err != nil {
			return nil, fmt.Errorf("failed to decode outpoint txid %s: %w", out.Txid, err)
		}

		// Write txid bytes
		buf.Write(txidBytes)

		// Write vout as big endian
		if err := binary.Write(&buf, binary.BigEndian, out.VOut); err != nil {
			return nil, fmt.Errorf("failed to encode outpoint vout %d: %w", out.VOut, err)
		}
	}

	// Hash the concatenated bytes
	hash := sha256.Sum256(buf.Bytes())

	return hash[:], nil
}

func paginate[T any](items []T, params *Page, maxSize int32) ([]T, PageResp) {
	if params == nil {
		params = &Page{PageSize: maxSize, PageNum: 1}
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
