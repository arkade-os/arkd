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

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

const (
	maxPageSizeVtxoTree       = 300
	maxPageSizeForfeitTxs     = 500
	maxPageSizeSpendableVtxos = 100
	maxPageSizeVtxoChain      = 100
	maxPageSizeVirtualTxs     = 100
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
		vtxoKey Outpoint,
		intent Intent,
		page *Page,
	) (*VtxoChainResp, error)
	GetVirtualTxs(
		ctx context.Context,
		authToken string,
		txids []string,
		page *Page,
	) (*VirtualTxsResp, error)
	GetBatchSweepTxs(ctx context.Context, batchOutpoint Outpoint) ([]string, error)
}

type indexerService struct {
	repoManager  ports.RepoManager
	signer       ports.SignerService
	wallet       ports.WalletService
	signerPubkey []byte
	txExposure   string
}

func NewIndexerService(
	repoManager ports.RepoManager,
	signer ports.SignerService,
	wallet ports.WalletService,
	txExposure string,
) (IndexerService, error) {
	pubkey, err := signer.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get signer pubkey: %w", err)
	}
	return &indexerService{
		repoManager:  repoManager,
		signer:       signer,
		wallet:       wallet,
		signerPubkey: pubkey.SerializeCompressed(),
		txExposure:   txExposure,
	}, nil
}

func (i *indexerService) GetCommitmentTxInfo(
	ctx context.Context, txid string,
) (*CommitmentTxInfo, error) {
	roundStats, err := i.repoManager.Rounds().GetRoundStats(ctx, txid)
	if err != nil {
		return nil, err
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
	ctx context.Context, vtxoKey Outpoint, intentForProof Intent, page *Page,
) (*VtxoChainResp, error) {
	chain := make([]ChainTx, 0)
	nextVtxos := []domain.Outpoint{vtxoKey}
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

	authToken := ""
	var err error

	switch TxExposure(i.txExposure) {
	case TxExposurePublic: // no need to do anything
	case TxExposureWithheld, TxExposurePrivate:
		// validate the intent proof/message to allow access to the full chain
		err = i.ValidateIntentWithProof(ctx, vtxoKey, intentForProof)
		if err == nil {
			authToken, err = i.createAuthToken(ctx, vtxoKey)
			if err != nil {
				return nil, err
			}
		}
		// if intent failed validation, we just dont supply an auth token

	default:
		return nil, fmt.Errorf("invalid exposure value: %s", i.txExposure)
	}

	txChain, pageResp := paginate(chain, page, maxPageSizeVtxoChain)
	return &VtxoChainResp{
		Chain:     txChain,
		Page:      pageResp,
		AuthToken: authToken,
	}, nil
}

func (i *indexerService) ValidateIntentWithProof(
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

	signedProof, err := i.signer.SignTransactionTapscript(ctx, intentForProof.Proof, nil)
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
	txs, err := i.repoManager.Rounds().GetTxsWithTxids(ctx, txids)
	if err != nil {
		return nil, err
	}

	virtualTxs, reps := paginate(txs, page, maxPageSizeVirtualTxs)

	// turn into TxExposure enum
	switch TxExposure(i.txExposure) {
	case TxExposurePublic:
		// no need to validate auth
	case TxExposureWithheld:
		isValid := false
		// optional auth token can be passed, if it was lets check if valid
		if authToken != "" {
			isValid, err = i.validateAuthToken(authToken)
			if err != nil {
				return nil, err
			}
		}
		// if no auth token or invalid auth token, remove from each PSBT the signature of arkd
		// so user cannot construct the full broadcastable txn
		if !isValid {
			for idx := range virtualTxs {
				ptx, err := psbt.NewFromRawBytes(strings.NewReader(virtualTxs[idx]), true)
				if err != nil {
					return nil, fmt.Errorf("failed to deserialize virtual tx: %s", err)
				}

				// remove arkd signature from each input
				for j := range ptx.Inputs {
					newSigs := make([]*psbt.PartialSig, 0)
					for _, sig := range ptx.Inputs[j].PartialSigs {
						// if the signature is not from arkd, keep it, otherwise remove it
						if !bytes.Equal(sig.PubKey, i.signerPubkey) {
							newSigs = append(newSigs, sig)
						}
					}
					ptx.Inputs[j].PartialSigs = newSigs
				}

				var b strings.Builder
				if err := ptx.Serialize(&b); err != nil {
					return nil, fmt.Errorf("failed to serialize virtual tx: %s", err)
				}
				virtualTxs[idx] = b.String()
			}
		}
	case TxExposurePrivate:
		if authToken == "" {
			return nil, fmt.Errorf("auth token is required for private exposure")
		}
		// require valid auth token to proceed
		isValid, err := i.validateAuthToken(authToken)
		if err != nil {
			return nil, err
		}
		if !isValid {
			return nil, fmt.Errorf("invalid auth token for private exposure")
		}
	default:
		return nil, fmt.Errorf("invalid exposure value: %s", i.txExposure)
	}

	return &VirtualTxsResp{
		Txs:  virtualTxs,
		Page: reps,
	}, nil
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
// Format: base64(outpoint_txid|outpoint_vout|signature)
func (i *indexerService) createAuthToken(ctx context.Context, outpoint Outpoint) (string, error) {
	// Build message: txid (32 bytes) + vout (4 bytes)
	txidBytes, err := hex.DecodeString(outpoint.Txid)
	if err != nil {
		return "", fmt.Errorf("failed to decode txid: %w", err)
	}

	msg := make([]byte, 32+4)
	copy(msg[0:32], txidBytes)
	binary.BigEndian.PutUint32(msg[32:36], outpoint.VOut)

	// Sign the message
	sig, err := i.signer.SignMessage(ctx, msg)
	if err != nil {
		return "", fmt.Errorf("failed to sign auth token: %w", err)
	}

	// Combine message + signature and encode as base64
	token := make([]byte, len(msg)+len(sig))
	copy(token[0:len(msg)], msg)
	copy(token[len(msg):], sig)

	return base64.StdEncoding.EncodeToString(token), nil
}

// validateAuthToken validates a signed auth token.
// Returns true if the signature is valid.
func (i *indexerService) validateAuthToken(authToken string) (bool, error) {
	if authToken == "" {
		return false, nil
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		return false, nil // Invalid base64, treat as invalid token
	}

	// Token format: msg (36 bytes) + schnorr signature (64 bytes)
	if len(tokenBytes) != 36+64 {
		return false, nil
	}

	msg := tokenBytes[0:36]
	sigBytes := tokenBytes[36:]

	// Verify schnorr signature
	msgHash := chainhash.HashB(msg)
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse signature: %w", err)
	}

	pubkey, err := schnorr.ParsePubKey(i.signerPubkey)
	if err != nil {
		return false, fmt.Errorf("failed to parse signer pubkey: %w", err)
	}

	return sig.Verify(msgHash, pubkey), nil
}
