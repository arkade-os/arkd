package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

const (
	maxPageSizeVtxoTree       = 300
	maxPageSizeForfeitTxs     = 500
	maxPageSizeSpendableVtxos = 100
	maxPageSizeVtxoChain      = 100
	maxPageSizeVirtualTxs     = 100

	defaultAuthTokenTTL = 5 * time.Minute
)

type TxExposure string

const (
	TxExposurePublic   TxExposure = "public"
	TxExposureWithheld TxExposure = "withheld"
	TxExposurePrivate  TxExposure = "private"
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
		pubkeys []string, spendableOnly, spendOnly, recoverableOnly, pendingOnly bool, after, before int64, page *Page,
	) (*GetVtxosResp, error)
	GetVtxosByOutpoint(
		ctx context.Context, outpoints []Outpoint, page *Page,
	) (*GetVtxosResp, error)
	GetVtxoChain(
		ctx context.Context,
		intent Intent,
		page *Page,
	) (*VtxoChainResp, error)
	GetVtxoChainByOutpoint(
		ctx context.Context,
		vtxoKey Outpoint,
		page *Page,
	) (*VtxoChainResp, error)
	GetVirtualTxs(
		ctx context.Context,
		authToken string,
		txids []string,
		page *Page,
	) (*VirtualTxsResp, error)
	GetVirtualTxsByIds(
		ctx context.Context,
		txids []string,
		page *Page,
	) (*VirtualTxsResp, error)
	GetBatchSweepTxs(ctx context.Context, batchOutpoint Outpoint) ([]string, error)
	GetAsset(ctx context.Context, assetID string) ([]Asset, error)
}

type indexerService struct {
	repoManager  ports.RepoManager
	wallet       ports.WalletService
	privkey      *btcec.PrivateKey
	signerPubkey []byte
	txExposure   string
	authTokenTTL time.Duration
}

func NewIndexerService(
	repoManager ports.RepoManager,
	wallet ports.WalletService,
	privkey *btcec.PrivateKey,
	txExposure string,
	authTokenExpirySec int64,
) (IndexerService, error) {
	// validate txExposure
	switch TxExposure(txExposure) {
	case TxExposurePublic, TxExposureWithheld, TxExposurePrivate:
	default:
		return nil, fmt.Errorf("invalid tx exposure value: %q", txExposure)
	}

	ttl := defaultAuthTokenTTL
	if authTokenExpirySec > 0 {
		ttl = time.Duration(authTokenExpirySec) * time.Second
	}

	svc := &indexerService{
		repoManager:  repoManager,
		wallet:       wallet,
		privkey:      privkey,
		txExposure:   txExposure,
		authTokenTTL: ttl,
	}
	if privkey != nil {
		svc.signerPubkey = schnorr.SerializePubKey(privkey.PubKey())
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
				if !vtxo.RequiresForfeit() && !vtxo.Spent {
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
	ctx context.Context, intentForProof Intent, page *Page,
) (*VtxoChainResp, error) {
	vtxoKey, err := i.extractOutpointFromIntent(intentForProof)
	if err != nil {
		return nil, err
	}

	authToken := ""

	switch TxExposure(i.txExposure) {
	case TxExposureWithheld:
		// validate the intent proof/message to allow access to the full chain
		if err = i.validateIntentProof(ctx, vtxoKey, intentForProof); err != nil {
			// withheld: swallow error, proceed without auth token
			break
		}
		authToken, err = i.createAuthToken(vtxoKey)
		if err != nil {
			return nil, err
		}
	case TxExposurePrivate:
		// validate the intent proof/message to allow access to the full chain
		if err = i.validateIntentProof(ctx, vtxoKey, intentForProof); err != nil {
			return nil, err
		}
		authToken, err = i.createAuthToken(vtxoKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid exposure value: %s", i.txExposure)
	}

	resp, err := i.getVtxoChain(ctx, vtxoKey, page)
	if err != nil {
		return nil, err
	}
	resp.AuthToken = authToken
	return resp, nil
}

func (i *indexerService) GetVtxoChainByOutpoint(
	ctx context.Context, vtxoKey Outpoint, page *Page,
) (*VtxoChainResp, error) {
	return i.getVtxoChain(ctx, vtxoKey, page)
}

func (i *indexerService) getVtxoChain(
	ctx context.Context, vtxoKey Outpoint, page *Page,
) (*VtxoChainResp, error) {
	chain, err := i.buildVtxoChain(ctx, vtxoKey)
	if err != nil {
		return nil, err
	}

	txChain, pageResp := paginate(chain, page, maxPageSizeVtxoChain)
	return &VtxoChainResp{
		Chain: txChain,
		Page:  pageResp,
	}, nil
}

// extractOutpointFromIntent parses the intent proof and returns the first vtxo outpoint.
func (i *indexerService) extractOutpointFromIntent(
	intentForProof Intent,
) (Outpoint, error) {
	if intentForProof.Proof == "" {
		return Outpoint{}, fmt.Errorf("intent proof is required")
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(intentForProof.Proof), true)
	if err != nil {
		return Outpoint{}, fmt.Errorf("failed to parse proof tx: %s", err)
	}
	if ptx == nil {
		return Outpoint{}, fmt.Errorf("proof PSBT is nil")
	}
	proof := intent.Proof{Packet: *ptx}
	outpoints := proof.GetOutpoints()
	if len(outpoints) == 0 {
		return Outpoint{}, fmt.Errorf("no outpoints found in intent proof")
	}
	return Outpoint{
		Txid: outpoints[0].Hash.String(),
		VOut: outpoints[0].Index,
	}, nil
}

// buildVtxoChain builds the full chain of transactions for a given vtxo outpoint.
func (i *indexerService) buildVtxoChain(ctx context.Context, outpoint Outpoint) ([]ChainTx, error) {
	chain := make([]ChainTx, 0)
	nextVtxos := []domain.Outpoint{outpoint}
	visited := make(map[string]bool)

	for len(nextVtxos) > 0 {
		vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, nextVtxos)
		if err != nil {
			return nil, err
		}
		if len(vtxos) == 0 {
			return nil, fmt.Errorf("vtxo not found for outpoint: %v", nextVtxos)
		}

		newNextVtxos := make([]domain.Outpoint, 0)
		for _, vtxo := range vtxos {
			key := vtxo.Outpoint.String()
			if visited[key] {
				continue
			}
			visited[key] = true

			// if the vtxo is preconfirmed, it means it has been created by an offchain tx
			// we need to add the virtual tx + the associated checkpoints txs
			// also, we have to populate the newNextVtxos with the checkpoints inputs
			// in order to continue the chain in the next iteration
			if vtxo.Preconfirmed {
				offchainTx, err := i.repoManager.OffchainTxs().GetOffchainTx(ctx, vtxo.Txid)
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve offchain tx: %s", err)
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
						return nil, fmt.Errorf("failed to deserialize checkpoint tx: %s", err)
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
			flatVtxoTree, err := i.GetVtxoTree(ctx, Outpoint{
				Txid: vtxo.RootCommitmentTxid, VOut: 0,
			}, nil)
			if err != nil {
				return nil, err
			}

			vtxoTree, err := tree.NewTxTree(flatVtxoTree.Txs)
			if err != nil {
				return nil, err
			}
			branch, err := vtxoTree.SubTree([]string{vtxo.Txid})
			if err != nil {
				return nil, err
			}

			fromRootToVtxo := make([]string, 0)
			if err := branch.Apply(func(tx *tree.TxTree) (bool, error) {
				fromRootToVtxo = append(fromRootToVtxo, tx.Root.UnsignedTx.TxID())
				return true, nil
			}); err != nil {
				return nil, err
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
		}

		nextVtxos = newNextVtxos
	}

	return chain, nil
}

// validateTxidsAgainstChain checks that all requested txids belong to the vtxo chain
// rooted at the given outpoint.
func (i *indexerService) validateTxidsAgainstChain(
	ctx context.Context, outpoint Outpoint, txids []string,
) error {
	chain, err := i.buildVtxoChain(ctx, outpoint)
	if err != nil {
		return fmt.Errorf("failed to build vtxo chain for outpoint binding: %w", err)
	}

	chainTxids := make(map[string]struct{}, len(chain))
	for _, tx := range chain {
		chainTxids[tx.Txid] = struct{}{}
	}

	for _, txid := range txids {
		if _, ok := chainTxids[txid]; !ok {
			return fmt.Errorf("txid %s is not part of the authenticated vtxo chain", txid)
		}
	}

	return nil
}

// similar flow in DeleteIntentsByProof inside internal/core/application/service.go
func (i *indexerService) validateIntentProof(
	ctx context.Context,
	vtxoKey Outpoint,
	intentForProof Intent,
) error {
	if intentForProof.Proof == "" || intentForProof.Message == "" {
		return fmt.Errorf("intent proof and message are required for private exposure")
	}
	// validate proof
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(intentForProof.Proof), true)
	if err != nil {
		return fmt.Errorf("failed to parse proof tx: %s", err)
	}
	if ptx == nil {
		return fmt.Errorf("proof PSBT is nil")
	}
	if len(ptx.Inputs) <= 1 {
		return errors.INVALID_PSBT_INPUT.New("not enough inputs in proof PSBT")
	}
	proof := intent.Proof{
		Packet: *ptx,
	}
	outpoints := proof.GetOutpoints()
	proofTxid := proof.UnsignedTx.TxID()
	boardingTxs := make(map[string]wire.MsgTx)
	for idx, outpoint := range outpoints {
		if idx+1 >= len(proof.Inputs) {
			return errors.INVALID_PSBT_INPUT.New(
				"outpoint index %d exceeds proof inputs count",
				idx,
			)
		}
		psbtInput := proof.Inputs[idx+1]

		if len(psbtInput.TaprootLeafScript) == 0 {
			return errors.INVALID_PSBT_INPUT.New("missing taproot leaf script on input %d", idx+1).
				WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
		}
		if psbtInput.WitnessUtxo == nil {
			return errors.INVALID_PSBT_INPUT.New("missing witness utxo on input %d", idx+1).
				WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
		}

		vtxoOutpoint := domain.Outpoint{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		vtxosResult, err := i.repoManager.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxoOutpoint})
		if err != nil || len(vtxosResult) == 0 {
			if _, ok := boardingTxs[vtxoOutpoint.Txid]; !ok {
				txhex, err := i.wallet.GetTransaction(ctx, outpoint.Hash.String())
				if err != nil {
					return errors.TX_NOT_FOUND.New(
						"failed to get boarding input tx %s: %s", vtxoOutpoint.Txid, err,
					).WithMetadata(errors.TxNotFoundMetadata{Txid: vtxoOutpoint.Txid})
				}
				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return errors.INVALID_PSBT_INPUT.New(
						"failed to deserialize boarding tx %s: %s", vtxoOutpoint.Txid, err,
					).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
				}

				boardingTxs[vtxoOutpoint.Txid] = tx
			}

			tx := boardingTxs[vtxoOutpoint.Txid]
			if int(vtxoOutpoint.VOut) >= len(tx.TxOut) {
				return errors.INVALID_PSBT_INPUT.New(
					"invalid vout index %d for tx %s (tx has %d outputs)",
					vtxoOutpoint.VOut, vtxoOutpoint.Txid, len(tx.TxOut),
				).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
			}
			prevout := tx.TxOut[vtxoOutpoint.VOut]

			if !bytes.Equal(prevout.PkScript, psbtInput.WitnessUtxo.PkScript) {
				return errors.INVALID_PSBT_INPUT.New(
					"pkscript mismatch: got %x expected %x",
					prevout.PkScript,
					psbtInput.WitnessUtxo.PkScript,
				).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
			}

			if prevout.Value != int64(psbtInput.WitnessUtxo.Value) {
				return errors.INVALID_PSBT_INPUT.New(
					"invalid witness utxo value: got %d expected %d",
					prevout.Value,
					psbtInput.WitnessUtxo.Value,
				).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
			}

			continue
		}

		vtxo := vtxosResult[0]

		if psbtInput.WitnessUtxo.Value != int64(vtxo.Amount) {
			return errors.INVALID_PSBT_INPUT.New(
				"invalid witness utxo value: got %d expected %d",
				psbtInput.WitnessUtxo.Value,
				vtxo.Amount,
			).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
		}

		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return errors.INTERNAL_ERROR.New("failed to decode vtxo pubkey: %w", err).
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return errors.INTERNAL_ERROR.New("failed to parse vtxo pubkey: %w", err).
				WithMetadata(map[string]any{
					"vtxo_pubkey": vtxo.PubKey,
				})
		}

		pkScript, err := script.P2TRScript(pubkey)
		if err != nil {
			return errors.INTERNAL_ERROR.New(
				"failed to compute P2TR script from vtxo pubkey: %w", err,
			).WithMetadata(map[string]any{
				"vtxo_pubkey": vtxo.PubKey,
			})
		}

		if !bytes.Equal(pkScript, psbtInput.WitnessUtxo.PkScript) {
			return errors.INVALID_PSBT_INPUT.New(
				"invalid witness utxo script: got %x expected %x",
				psbtInput.WitnessUtxo.PkScript,
				pkScript,
			).WithMetadata(errors.InputMetadata{Txid: proofTxid, InputIndex: idx + 1})
		}
	}

	signedProof, err := i.signTransactionTapscript(intentForProof.Proof)
	if err != nil {
		return errors.INTERNAL_ERROR.New("failed to sign proof: %w", err).
			WithMetadata(map[string]any{
				"proof": proof.UnsignedTx.TxID(),
			})
	}
	if err := intent.Verify(signedProof, intentForProof.Message); err != nil {
		log.
			WithField("signedProof", signedProof).
			WithField("encodedMessage", intentForProof.Message).
			Tracef("failed to verify intent proof: %s", err)
		return errors.INVALID_INTENT_PROOF.New("invalid intent proof: %w", err).
			WithMetadata(errors.InvalidIntentProofMetadata{
				Proof:   signedProof,
				Message: intentForProof.Message,
			})
	}
	return nil
}

func (i *indexerService) GetVirtualTxs(
	ctx context.Context, authToken string, txids []string, page *Page,
) (*VirtualTxsResp, error) {
	switch TxExposure(i.txExposure) {
	case TxExposureWithheld:
		isValid := false
		var err error
		// optional auth token can be passed, if it was lets check if valid
		if authToken != "" {
			var tokenOutpoint Outpoint
			tokenOutpoint, isValid, err = i.validateAuthToken(authToken)
			if err != nil {
				return nil, err
			}
			if isValid {
				if err := i.validateTxidsAgainstChain(ctx, tokenOutpoint, txids); err != nil {
					return nil, err
				}
			}
		}

		resp, err := i.getVirtualTxs(ctx, txids, page)
		if err != nil {
			return nil, err
		}

		// if no auth token or invalid auth token, remove from each PSBT the signature of arkd
		// so user cannot construct the full broadcastable txn
		if !isValid {
			if err := i.stripArkdSignatures(resp.Txs); err != nil {
				return nil, err
			}
		}
		return resp, nil
	case TxExposurePrivate:
		if authToken == "" {
			return nil, fmt.Errorf("auth token is required for private exposure")
		}
		// require valid auth token to proceed
		tokenOutpoint, isValid, err := i.validateAuthToken(authToken)
		if err != nil {
			return nil, err
		}
		if !isValid {
			return nil, fmt.Errorf("invalid auth token for private exposure")
		}
		if err := i.validateTxidsAgainstChain(ctx, tokenOutpoint, txids); err != nil {
			return nil, err
		}
		return i.getVirtualTxs(ctx, txids, page)
	default:
		return nil, fmt.Errorf("invalid exposure value: %s", i.txExposure)
	}
}

func (i *indexerService) GetVirtualTxsByIds(
	ctx context.Context, txids []string, page *Page,
) (*VirtualTxsResp, error) {
	return i.getVirtualTxs(ctx, txids, page)
}

func (i *indexerService) getVirtualTxs(
	ctx context.Context, txids []string, page *Page,
) (*VirtualTxsResp, error) {
	txs, err := i.repoManager.Rounds().GetTxsWithTxids(ctx, txids)
	if err != nil {
		return nil, err
	}
	virtualTxs, reps := paginate(txs, page, maxPageSizeVirtualTxs)
	return &VirtualTxsResp{
		Txs:  virtualTxs,
		Page: reps,
	}, nil
}

func (i *indexerService) stripArkdSignatures(virtualTxs []string) error {
	for idx := range virtualTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(virtualTxs[idx]), true)
		if err != nil {
			return fmt.Errorf("failed to deserialize virtual tx: %s", err)
		}

		// remove arkd taproot script spend signatures from each input
		for j := range ptx.Inputs {
			newSigs := make([]*psbt.TaprootScriptSpendSig, 0)
			for _, sig := range ptx.Inputs[j].TaprootScriptSpendSig {
				if !bytes.Equal(sig.XOnlyPubKey, i.signerPubkey) {
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

func (i *indexerService) GetBatchSweepTxs(
	ctx context.Context, batchOutpoint Outpoint,
) ([]string, error) {
	round, err := i.repoManager.Rounds().GetRoundWithCommitmentTxid(ctx, batchOutpoint.Txid)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(round.SweepTxs))
	for txid := range round.SweepTxs {
		txids = append(txids, txid)
	}

	return txids, nil
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

// createAuthToken creates a signed auth token for accessing virtual txs.
// Format: base64(outpoint_txid(32)|outpoint_vout(4)|timestamp(8)|signature(64))
func (i *indexerService) createAuthToken(outpoint Outpoint) (string, error) {
	return i.createAuthTokenWithTimestamp(outpoint, time.Now())
}

func (i *indexerService) createAuthTokenWithTimestamp(
	outpoint Outpoint, ts time.Time,
) (string, error) {
	// Build message: txid (32 bytes) + vout (4 bytes) + timestamp (8 bytes)
	txidBytes, err := hex.DecodeString(outpoint.Txid)
	if err != nil {
		return "", fmt.Errorf("failed to decode txid: %w", err)
	}

	msg := make([]byte, 32+4+8)
	copy(msg[0:32], txidBytes)
	binary.BigEndian.PutUint32(msg[32:36], outpoint.VOut)
	binary.BigEndian.PutUint64(msg[36:44], uint64(ts.Unix()))

	// Sign the message
	msgHash := chainhash.HashB(msg)
	sig, err := schnorr.Sign(i.privkey, msgHash)
	if err != nil {
		return "", fmt.Errorf("failed to sign auth token: %w", err)
	}
	sigBytes := sig.Serialize()

	// Combine message + signature and encode as base64
	token := make([]byte, len(msg)+len(sigBytes))
	copy(token[0:len(msg)], msg)
	copy(token[len(msg):], sigBytes)

	return base64.StdEncoding.EncodeToString(token), nil
}

// validateAuthToken validates a signed auth token.
// Returns the outpoint encoded in the token and true if the signature is valid and the token has not expired.
func (i *indexerService) validateAuthToken(authToken string) (Outpoint, bool, error) {
	if authToken == "" {
		return Outpoint{}, false, nil
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		return Outpoint{}, false, nil // Invalid base64, treat as invalid token
	}

	// Token format: msg (44 bytes: txid 32 + vout 4 + timestamp 8) + schnorr signature (64 bytes)
	if len(tokenBytes) != 44+64 {
		return Outpoint{}, false, nil
	}

	msg := tokenBytes[0:44]
	sigBytes := tokenBytes[44:]

	// Extract timestamp and check expiry
	tsSec := binary.BigEndian.Uint64(msg[36:44])
	tokenTime := time.Unix(int64(tsSec), 0)
	if time.Since(tokenTime) > i.authTokenTTL {
		return Outpoint{}, false, nil
	}

	// Verify schnorr signature
	msgHash := chainhash.HashB(msg)
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return Outpoint{}, false, fmt.Errorf("failed to parse signature: %w", err)
	}

	pubkey, err := schnorr.ParsePubKey(i.signerPubkey)
	if err != nil {
		return Outpoint{}, false, fmt.Errorf("failed to parse signer pubkey: %w", err)
	}

	if !sig.Verify(msgHash, pubkey) {
		return Outpoint{}, false, nil
	}

	// Extract outpoint from token
	outpoint := Outpoint{
		Txid: hex.EncodeToString(msg[0:32]),
		VOut: binary.BigEndian.Uint32(msg[32:36]),
	}

	return outpoint, true, nil
}

// signTransactionTapscript signs all tapscript inputs of a PSBT using the indexer's private key.
func (i *indexerService) signTransactionTapscript(partialTx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(partialTx), true)
	if err != nil {
		return "", err
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for inputIndex, input := range ptx.Inputs {
		prevOutpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if input.WitnessUtxo != nil {
			prevouts[prevOutpoint] = input.WitnessUtxo
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	for inputIndex, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			continue
		}
		if !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
			continue
		}
		if len(input.TaprootLeafScript) == 0 {
			continue
		}

		// Use the first leaf script — PSBT inputs in this context always have
		// a single tapscript leaf (the VTXO covenant script).
		tapLeaf := txscript.NewBaseTapLeaf(input.TaprootLeafScript[0].Script)

		signature, err := txscript.RawTxInTapscriptSignature(
			ptx.UnsignedTx, txSigHashes, inputIndex, input.WitnessUtxo.Value,
			input.WitnessUtxo.PkScript, tapLeaf, input.SighashType, i.privkey,
		)
		if err != nil {
			return "", err
		}

		leafHash := tapLeaf.TapHash()

		ptx.Inputs[inputIndex].TaprootScriptSpendSig = append(
			ptx.Inputs[inputIndex].TaprootScriptSpendSig,
			&psbt.TaprootScriptSpendSig{
				Signature:   signature[:64],
				XOnlyPubKey: schnorr.SerializePubKey(i.privkey.PubKey()),
				LeafHash:    leafHash[:],
				SigHash:     input.SighashType,
			},
		)
	}

	return ptx.B64Encode()
}
