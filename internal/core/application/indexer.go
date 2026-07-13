package application

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	log "github.com/sirupsen/logrus"
)

const (
	// These constants are meant to be used only by page-number (legacy) pagination.
	maxPageSizeVtxoTree       = 300
	maxPageSizeForfeitTxs     = 500
	maxPageSizeSpendableVtxos = 100
	maxPageSizeVtxoChain      = 100
	maxPageSizeVirtualTxs     = 100

	// maxVtxoChainWalkSize is the cursor pagination page size (fixed, not client-customizable)
	// and the upper bound for legacy page-number pagination:
	// GetVtxoChain rejects page-number requests on chains longer than this to force clients onto
	// the cursor API.
	maxVtxoChainWalkSize = 50_000

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
		ctx context.Context, authToken string, vtxoKey Outpoint, page *Page, pageToken string,
	) (*VtxoChainResp, error)
	GetVtxoChainByIntent(ctx context.Context, intent Intent) (*VtxoChainResp, error)
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
	repoManager   ports.RepoManager
	wallet        ports.WalletService
	authPrvkey    *btcec.PrivateKey // key used to sign auth tokens
	cursorHMACKey []byte            // HMAC key for signing pagination cursors
	signerPubkey  *btcec.PublicKey  // server's signing key, used for stripping signatures from txs
	// deprecated signer pubkeys still accepted for old vtxos after a key rotation
	deprecatedSignerPubkeys []ports.DeprecatedSignerPubkey
	txExposure              exposure
	authTokenTTL            time.Duration
	tokenCache              *tokenCache
}

func NewIndexerService(
	repoManager ports.RepoManager,
	wallet ports.WalletService,
	privkey *btcec.PrivateKey,
	signerPubkey *btcec.PublicKey,
	deprecatedSignerPubkeys []ports.DeprecatedSignerPubkey,
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

	// Derive HMAC key for pagination cursors from the auth private key.
	// This prevents clients from forging cursors with arbitrary outpoints.
	var cursorKey []byte
	if privkey != nil {
		h := sha256.Sum256(append(privkey.Serialize(), []byte("cursor-hmac")...))
		cursorKey = h[:]
	}

	svc := &indexerService{
		repoManager:   repoManager,
		wallet:        wallet,
		authPrvkey:    privkey,
		cursorHMACKey: cursorKey,
		txExposure:    exposure(txExposure),
		authTokenTTL:  ttl,
		tokenCache:    newTokenCache(ttl),
	}

	if signerPubkey != nil {
		svc.signerPubkey = signerPubkey
	}
	svc.deprecatedSignerPubkeys = deprecatedSignerPubkeys
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
	ctx context.Context, authToken string, outpoint Outpoint, page *Page, pageToken string,
) (*VtxoChainResp, error) {
	switch i.txExposure {
	case exposurePublic:
		// Nothing to do
	case exposureWithheld:
		// Auth token is optional, validate it only if provided
		if authToken != "" {
			if err := i.validateChainAuth(authToken, outpoint); err != nil {
				return nil, err
			}
		}
	case exposurePrivate:
		// Auth token is mandatory, always validate it
		if err := i.validateChainAuth(authToken, outpoint); err != nil {
			return nil, err
		}
	}

	// Cursor pagination: a page_token resumes from a saved offset; with no page and no token
	// we start a fresh cursor session at offset 0. The cursor page size is fixed at
	// maxVtxoChainWalkSize and is not client-customizable — only the chain prefix up to
	// offset+pageSize is loaded, then sliced.
	if len(pageToken) > 0 || page == nil {
		offset := 0
		if len(pageToken) > 0 {
			var err error
			offset, err = i.decodeChainCursor(pageToken, outpoint)
			if err != nil {
				// page_token is client-supplied input. Surface it as invalid input
				// so the handler maps it to InvalidArgument rather than Internal.
				return nil, fmt.Errorf("%w: invalid page_token: %w", ErrInvalidInput, err)
			}
		}
		chain, _, truncated, err := i.walkVtxoChain(
			ctx, []domain.Outpoint{outpoint}, offset+maxVtxoChainWalkSize,
		)
		if err != nil {
			return nil, err
		}
		return i.chainCursorPage(chain, offset, maxVtxoChainWalkSize, truncated, outpoint), nil
	}

	// Legacy page-number pagination: build the full chain (capped at maxVtxoChainWalkSize,
	// erroring on longer chains to force clients onto the cursor API), then slice by page number
	// with page metadata.
	chain, _, truncated, err := i.walkVtxoChain(
		ctx, []domain.Outpoint{outpoint}, maxVtxoChainWalkSize+1,
	)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf(
			"chain exceeds maximum size of %d for page-number pagination; "+
				"use cursor pagination (page_token) instead", maxVtxoChainWalkSize,
		)
	}
	txChain, pageResp := paginate(chain, page, maxPageSizeVtxoChain)
	return &VtxoChainResp{Chain: txChain, Page: pageResp}, nil
}

// GetVtxoChainByIntent is the cursor-pagination entry point: it walks the full chain to mint an
// auth token that authorizes every outpoint the client will page through, and returns the first
// cursor page (fixed size maxVtxoChainWalkSize) plus a next page token when the chain is longer.
// It does not support page-number (legacy) pagination.
func (i *indexerService) GetVtxoChainByIntent(
	ctx context.Context, intent Intent,
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
		// math.MaxInt32 limit => the walk never truncates, so the whole chain is
		// loaded and moreBeyondChain is false. chainCursorPage still emits a next
		// page token when the chain exceeds one page (offset+pageSize < len).
		chain, _, _, err := i.walkVtxoChain(ctx, []domain.Outpoint{outpoint}, math.MaxInt32)
		if err != nil {
			return nil, err
		}
		return i.chainCursorPage(chain, 0, maxVtxoChainWalkSize, false, outpoint), nil
	case exposureWithheld, exposurePrivate:
		if err := i.validateIntent(ctx, intent); err != nil {
			return nil, err
		}
	}

	// The full chain must be walked (math.MaxInt32 limit, so it never truncates)
	// so the auth token authorizes every outpoint (and every ark/checkpoint/tree
	// txid) the client can later fetch.
	chain, allOutpoints, _, err := i.walkVtxoChain(ctx, []domain.Outpoint{outpoint}, math.MaxInt32)
	if err != nil {
		return nil, err
	}

	token, err := i.createAuthToken(allOutpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth token: %w", err)
	}

	// moreBeyondChain is false: the entire chain is loaded above, so a next page
	// token (for chains longer than one page) is derived from the slice length.
	resp := i.chainCursorPage(chain, 0, maxVtxoChainWalkSize, false, outpoint)
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

// walkVtxoChain walks the VTXO chain upward from the given start outpoints,
// collecting chain transactions and all outpoints seen, in a deterministic
// order. It stops once it has collected at least limit chain txs and reports
// truncated=true in that case (more of the chain remains beyond what was
// returned); callers slice the page they need out of the returned chain.
func (i *indexerService) walkVtxoChain(
	ctx context.Context, frontier []domain.Outpoint, limit int,
) ([]ChainTx, []Outpoint, bool, error) {
	chain := make([]ChainTx, 0)
	nextVtxos := frontier
	visited := make(map[string]bool)
	offchainTxCache := make(map[string]*domain.OffchainTx)
	allOutpoints := make([]Outpoint, 0)

	// Lazy cache for VTXOs loaded during this page.
	vtxoCache := make(map[string]domain.Vtxo)
	loadedMarkers := make(map[string]bool)

	// Eagerly preload VTXOs and offchain txs by walking the marker DAG upward.
	// Failures in the marker-driven preload are treated as optimization misses:
	// the per-hop walk loop below falls back to Vtxos().GetVtxos + ensureVtxosCached,
	// so we log marker-repo errors here and continue instead of aborting.
	if i.repoManager.Markers() != nil {
		startVtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, nextVtxos)
		if err != nil {
			return nil, nil, false, err
		}
		if err := i.preloadByMarkers(ctx, startVtxos, vtxoCache, offchainTxCache); err != nil {
			log.WithError(err).Warnf(
				"marker-driven preload failed for frontier of %d outpoints; "+
					"falling back to per-hop walk", len(nextVtxos),
			)
		}
	}

	for len(nextVtxos) > 0 {
		if err := i.ensureVtxosCached(ctx, nextVtxos, vtxoCache, loadedMarkers); err != nil {
			return nil, nil, false, err
		}

		vtxos := make([]domain.Vtxo, 0, len(nextVtxos))
		for _, op := range nextVtxos {
			if v, ok := vtxoCache[op.String()]; ok {
				vtxos = append(vtxos, v)
			}
		}
		if len(vtxos) == 0 {
			return nil, nil, false, fmt.Errorf("vtxo not found for outpoint: %v", nextVtxos)
		}

		missingOffchainTxids := make(map[string]struct{})
		for _, vtxo := range vtxos {
			if !vtxo.Preconfirmed {
				continue
			}
			if _, ok := offchainTxCache[vtxo.Txid]; ok {
				continue
			}
			missingOffchainTxids[vtxo.Txid] = struct{}{}
		}

		if len(missingOffchainTxids) > 0 {
			txids := make([]string, 0, len(missingOffchainTxids))
			for txid := range missingOffchainTxids {
				txids = append(txids, txid)
			}

			offchainTxs, err := i.repoManager.OffchainTxs().GetOffchainTxsByTxids(ctx, txids)
			if err != nil {
				return nil, nil, false, fmt.Errorf("failed to retrieve offchain txs: %s", err)
			}

			for _, tx := range offchainTxs {
				offchainTxCache[tx.ArkTxid] = tx
			}
		}

		newNextVtxos := make([]domain.Outpoint, 0)
		for _, vtxo := range vtxos {
			key := vtxo.Outpoint.String()
			if visited[key] {
				continue
			}

			// Stop once we have collected at least limit txs. The chain built so
			// far is a deterministic prefix; the caller slices its page out of it
			// and knows more of the chain remains (truncated=true).
			if len(chain) >= limit {
				return chain, allOutpoints, true, nil
			}

			allOutpoints = append(allOutpoints, vtxo.Outpoint)
			visited[key] = true

			// if the vtxo is preconfirmed, it means it has been created by an offchain tx
			// we need to add the virtual tx + the associated checkpoints txs
			// also, we have to populate the newNextVtxos with the checkpoints inputs
			// in order to continue the chain in the next iteration
			if vtxo.Preconfirmed {
				offchainTx, ok := offchainTxCache[vtxo.Txid]
				if !ok {
					var err error
					offchainTx, err = i.repoManager.OffchainTxs().GetOffchainTx(ctx, vtxo.Txid)
					if err != nil {
						return nil, nil, false, fmt.Errorf("failed to retrieve offchain tx: %s", err)
					}
					offchainTxCache[vtxo.Txid] = offchainTx
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
						return nil, nil, false, fmt.Errorf(
							"failed to deserialize checkpoint tx: %s",
							err,
						)
					}

					txid := ptx.UnsignedTx.TxID()
					checkpointTxs = append(checkpointTxs, ChainTx{
						Txid:      txid,
						ExpiresAt: vtxo.ExpiresAt,
						Type:      IndexerChainedTxTypeCheckpoint,
						Spends:    []string{ptx.UnsignedTx.TxIn[0].PreviousOutPoint.String()},
					})

					allOutpoints = append(allOutpoints, Outpoint{Txid: txid, VOut: 0})
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
			flatVtxoTree, err := i.GetVtxoTree(ctx, Outpoint{
				Txid: vtxo.RootCommitmentTxid, VOut: 0,
			}, nil)
			if err != nil {
				return nil, nil, false, err
			}

			vtxoTree, err := tree.NewTxTree(flatVtxoTree.Txs)
			if err != nil {
				return nil, nil, false, err
			}
			branch, err := vtxoTree.SubTree([]string{vtxo.Txid})
			if err != nil {
				return nil, nil, false, err
			}

			fromRootToVtxo := make([]string, 0)
			if err := branch.Apply(func(tx *tree.TxTree) (bool, error) {
				fromRootToVtxo = append(fromRootToVtxo, tx.Root.UnsignedTx.TxID())
				return true, nil
			}); err != nil {
				return nil, nil, false, err
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

	return chain, allOutpoints, false, nil
}

// preloadByMarkers bulk-fetches VTXOs and their offchain txs by walking the
// marker DAG upward from the markers of startVtxos. This reduces DB round-trips
// from O(chain_length) to O(chain_length / MarkerInterval) for both layers.
func (i *indexerService) preloadByMarkers(
	ctx context.Context,
	startVtxos []domain.Vtxo,
	vtxoCache map[string]domain.Vtxo,
	offchainTxCache map[string]*domain.OffchainTx,
) error {
	markerRepo := i.repoManager.Markers()
	offchainTxRepo := i.repoManager.OffchainTxs()

	// Seed the traversal with the markers of the start VTXOs, caching the
	// VTXOs themselves along the way. markerIds accumulates every marker
	// discovered during the traversal below.
	markerIds := make([]string, 0)
	for _, v := range startVtxos {
		vtxoCache[v.Outpoint.String()] = v
		markerIds = append(markerIds, v.MarkerIDs...)
	}

	// Legacy VTXOs may carry no markers, leaving nothing to walk or bulk-fetch.
	if len(markerIds) == 0 {
		return nil
	}

	// BFS up the marker DAG: currentMarkerIds holds the frontier of the
	// current level, one bulk DB fetch per level.
	currentMarkerIds := make([]string, len(markerIds))
	copy(currentMarkerIds, markerIds)

	visited := make(map[string]bool)
	for len(currentMarkerIds) > 0 {
		// Get marker objects to find parent markers.
		markers, err := markerRepo.GetMarkersByIds(ctx, currentMarkerIds)
		if err != nil {
			return err
		}

		for _, id := range currentMarkerIds {
			visited[id] = true
		}

		// Expand the frontier to the not-yet-visited parents. Markers may
		// share parents, so the visited set guards against re-fetching and
		// against cycles.
		nextMarkers := make([]string, 0)
		for _, m := range markers {
			for _, pid := range m.ParentMarkerIDs {
				if !visited[pid] {
					nextMarkers = append(nextMarkers, pid)
					markerIds = append(markerIds, pid)
				}
			}
		}
		currentMarkerIds = nextMarkers
	}

	// Bulk-fetch all VTXOs tagged with these markers.
	vtxos, err := markerRepo.GetVtxoChainByMarkers(ctx, markerIds)
	if err != nil {
		return err
	}
	for _, v := range vtxos {
		if _, ok := vtxoCache[v.Outpoint.String()]; !ok {
			vtxoCache[v.Outpoint.String()] = v
		}
	}

	// Piggyback: bulk-fetch the offchain txs for the preconfirmed VTXOs
	// in this window, so the walk loop never has to hit the DB per-hop.
	missingTxids := make([]string, 0, len(vtxos))
	seen := make(map[string]bool, len(vtxos))
	for _, v := range vtxos {
		if !v.Preconfirmed {
			continue
		}
		if seen[v.Txid] {
			continue
		}
		seen[v.Txid] = true
		if _, ok := offchainTxCache[v.Txid]; ok {
			continue
		}
		missingTxids = append(missingTxids, v.Txid)
	}
	// offchainTxRepo may be nil in test helpers that do not wire up the
	// offchain-tx repo. Skip the piggyback in that case — the walk loop
	// will fall back to its own in-loop bulk fetch for any cache misses.
	if len(missingTxids) > 0 && offchainTxRepo != nil {
		offchainTxs, err := offchainTxRepo.GetOffchainTxsByTxids(ctx, missingTxids)
		if err != nil {
			return err
		}
		for _, tx := range offchainTxs {
			offchainTxCache[tx.ArkTxid] = tx
		}
	}

	return nil
}

// ensureVtxosCached loads the given outpoints into the cache if not already present.
// For each fetched VTXO, it also loads its marker window into the cache to prefetch
// nearby VTXOs that will likely be needed in subsequent iterations.
func (i *indexerService) ensureVtxosCached(
	ctx context.Context,
	outpoints []domain.Outpoint,
	cache map[string]domain.Vtxo,
	loadedMarkers map[string]bool,
) error {
	// Collect cache misses.
	missingOutpoints := make([]domain.Outpoint, 0)
	for _, op := range outpoints {
		if _, ok := cache[op.String()]; !ok {
			missingOutpoints = append(missingOutpoints, op)
		}
	}
	if len(missingOutpoints) == 0 {
		return nil
	}

	// Fetch misses from DB.
	dbVtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, missingOutpoints)
	if err != nil {
		return err
	}
	for _, v := range dbVtxos {
		cache[v.Outpoint.String()] = v
	}

	// For each fetched VTXO, load its marker window(s) into cache.
	if i.repoManager.Markers() == nil {
		return nil
	}
	for _, v := range dbVtxos {
		for _, markerID := range v.MarkerIDs {
			if loadedMarkers[markerID] {
				continue
			}
			loadedMarkers[markerID] = true

			windowVtxos, err := i.repoManager.Markers().GetVtxosByMarker(ctx, markerID)
			if err != nil {
				log.WithError(err).
					Warnf("failed to load marker window %s, falling back to per-VTXO lookups", markerID)
				continue
			}
			for _, wv := range windowVtxos {
				if _, ok := cache[wv.Outpoint.String()]; !ok {
					cache[wv.Outpoint.String()] = wv
				}
			}
		}
	}

	return nil
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
	signerPubkeys := make([][]byte, 0)
	for _, pk := range i.allSignerPubkeys() {
		signerPubkeys = append(signerPubkeys, schnorr.SerializePubKey(pk))
	}

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
				isSignerSig := false
				for _, pk := range signerPubkeys {
					if bytes.Equal(sig.XOnlyPubKey, pk) {
						isSignerSig = true
						break
					}
				}
				if !isSignerSig {
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
		intentToValidate.Proof, intentToValidate.Message, i.allSignerPubkeys(),
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

// validateChainAuth validates the auth token for GetVtxoChain: it verifies the
// signature and the embedded-timestamp expiry and confirms the token authorizes
// vtxoKey.
func (i *indexerService) validateChainAuth(authToken string, vtxoKey Outpoint) error {
	if i.authPrvkey == nil {
		return fmt.Errorf("auth not configured")
	}

	hash, err := i.validateAuthToken(authToken)
	if err != nil {
		return err
	}

	outpoints, _, ok := i.tokenCache.getOutpoints(hash)
	if !ok {
		return fmt.Errorf("auth token not found")
	}
	if _, ok := outpoints[vtxoKey.String()]; !ok {
		return fmt.Errorf("auth token is not for outpoint %s", vtxoKey)
	}
	return nil
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

func (i *indexerService) allSignerPubkeys() []*btcec.PublicKey {
	pubkeys := make([]*btcec.PublicKey, 0, len(i.deprecatedSignerPubkeys)+1)
	pubkeys = append(pubkeys, i.signerPubkey)
	for _, deprecated := range i.deprecatedSignerPubkeys {
		pubkeys = append(pubkeys, deprecated.PubKey)
	}
	return pubkeys
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

// chainCursorPage slices a page of pageSize starting at offset out of chain and
// emits the next offset cursor (bound to vtxoKey) when more of the chain
// remains. chain is a deterministic prefix of the full chain, so each page is a
// disjoint slice — no tx is emitted twice across pages. moreBeyondChain is set
// when chain was truncated by the walk limit, so a next page exists even though
// the slice reached the end of what was loaded.
func (i *indexerService) chainCursorPage(
	chain []ChainTx, offset, pageSize int, moreBeyondChain bool, vtxoKey Outpoint,
) *VtxoChainResp {
	if offset < 0 {
		offset = 0
	}
	if pageSize <= 0 {
		pageSize = int(maxPageSizeVtxoChain)
	}

	total := len(chain)
	if offset >= total {
		return &VtxoChainResp{Chain: []ChainTx{}}
	}

	end := offset + pageSize
	if end > total {
		end = total
	}

	hasMore := moreBeyondChain || end < total
	var nextToken string
	if hasMore {
		nextToken = i.encodeChainCursor(end, vtxoKey)
	}

	return &VtxoChainResp{
		Chain:         chain[offset:end],
		NextPageToken: nextToken,
	}
}

// encodeChainCursor encodes a chain offset into an HMAC-signed opaque page token
// bound to vtxoKey. The HMAC prevents clients from forging cursors or replaying
// a cursor issued for one outpoint while authenticating for another (which would
// bypass auth validation in exposurePrivate/withheld modes).
func (i *indexerService) encodeChainCursor(offset int, vtxoKey Outpoint) string {
	cur := vtxoChainCursor{Outpoint: vtxoKey.String(), Offset: offset}
	payload, err := json.Marshal(cur)
	if err != nil {
		// Unreachable for a fixed {string, int} struct, but avoid emitting a
		// malformed cursor: returning "" just signals "no next page".
		return ""
	}

	if len(i.cursorHMACKey) > 0 {
		mac := hmac.New(sha256.New, i.cursorHMACKey)
		mac.Write(payload)
		payload = append(payload, mac.Sum(nil)...)
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

// decodeChainCursor decodes and verifies an HMAC-signed page token, returning
// the resume offset. It rejects a cursor issued for a different outpoint so a
// page token cannot be replayed against another chain in withheld/private mode.
func (i *indexerService) decodeChainCursor(token string, vtxoKey Outpoint) (int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("invalid base64: %w", err)
	}

	payload := raw
	if len(i.cursorHMACKey) > 0 {
		if len(raw) < sha256.Size {
			return 0, fmt.Errorf("invalid cursor: too short")
		}
		payload = raw[:len(raw)-sha256.Size]
		sig := raw[len(raw)-sha256.Size:]

		mac := hmac.New(sha256.New, i.cursorHMACKey)
		mac.Write(payload)
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return 0, fmt.Errorf("invalid cursor: signature mismatch")
		}
	}

	var cur vtxoChainCursor
	if err := json.Unmarshal(payload, &cur); err != nil {
		return 0, fmt.Errorf("invalid JSON: %w", err)
	}
	if cur.Outpoint != vtxoKey.String() {
		return 0, fmt.Errorf("cursor does not match outpoint")
	}
	if cur.Offset < 0 {
		return 0, fmt.Errorf("invalid cursor offset")
	}
	return cur.Offset, nil
}
