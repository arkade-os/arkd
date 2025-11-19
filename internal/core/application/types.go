package application

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/wire"
)

type Service interface {
	Start() errors.Error
	Stop()
	RegisterIntent(
		ctx context.Context, proof intent.Proof, message intent.RegisterMessage,
	) (string, errors.Error)
	ConfirmRegistration(ctx context.Context, intentId string) errors.Error
	SubmitForfeitTxs(ctx context.Context, forfeitTxs []string) errors.Error
	SignCommitmentTx(ctx context.Context, commitmentTx string) errors.Error
	GetEventsChannel(ctx context.Context) <-chan []domain.Event
	GetInfo(ctx context.Context) (*ServiceInfo, errors.Error)
	SubmitOffchainTx(
		ctx context.Context, checkpointTxs []string, signedArkTx string,
	) (signedCheckpoints []string, finalArkTx string, arkTxid string, err errors.Error)
	FinalizeOffchainTx(ctx context.Context, txid string, finalCheckpoints []string) errors.Error
	// Tree signing methods
	RegisterCosignerNonces(
		ctx context.Context, roundId, pubkey string, nonces tree.TreeNonces,
	) errors.Error
	RegisterCosignerSignatures(
		ctx context.Context, roundId, pubkey string, signatures tree.TreePartialSigs,
	) errors.Error
	GetTxEventsChannel(ctx context.Context) <-chan TransactionEvent
	DeleteIntentsByProof(
		ctx context.Context,
		proof intent.Proof,
		message intent.DeleteMessage,
	) errors.Error

	// TODO: remove when detaching the indexer svc.
	GetIndexerTxChannel(ctx context.Context) <-chan TransactionEvent
}

type ServiceInfo struct {
	SignerPubKey         string
	ForfeitPubKey        string
	UnilateralExitDelay  int64
	BoardingExitDelay    int64
	SessionDuration      int64
	Network              string
	Dust                 uint64
	ForfeitAddress       string
	NextScheduledSession *NextScheduledSession
	UtxoMinAmount        int64
	UtxoMaxAmount        int64
	VtxoMinAmount        int64
	VtxoMaxAmount        int64
	CheckpointTapscript  string
	Fees                 FeeInfo
}

type NextScheduledSession struct {
	StartTime time.Time
	EndTime   time.Time
	Period    time.Duration
	Duration  time.Duration
	Fees      FeeInfo
}

type WalletStatus struct {
	IsInitialized bool
	IsUnlocked    bool
	IsSynced      bool
}

type FeeInfo struct {
	IntentFees IntentFeeInfo
	TxFeeRate  float64
}

type IntentFeeInfo struct {
	OffchainInput  string
	OffchainOutput string
	OnchainInput   uint64
	OnchainOutput  uint64
}

const (
	CommitmentTxType TransactionEventType = "commitment_tx"
	ArkTxType        TransactionEventType = "ark_tx"
	SweepTxType      TransactionEventType = "sweep_tx"
)

type TransactionEventType string

type TxData struct {
	Tx   string
	Txid string
}

type TransactionEvent struct {
	TxData
	Type           TransactionEventType
	SpentVtxos     []domain.Vtxo
	SpendableVtxos []domain.Vtxo
	SweptVtxos     []domain.Outpoint
	CheckpointTxs  map[string]TxData
}

type VtxoChainResp struct {
	Chain []ChainTx
	Page  PageResp
}

type VOut int

type CommitmentTxInfo struct {
	StartedAt         int64
	EndAt             int64
	Batches           map[VOut]Batch
	TotalInputAmount  uint64
	TotalInputVtxos   int32
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
}

type Batch struct {
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
	ExpiresAt         int64
	Swept             bool
}

type TreeTxResp struct {
	Txs  []TreeTx
	Page PageResp
}

type VtxoTreeLeavesResp struct {
	Leaves []domain.Vtxo
	Page   PageResp
}

type TreeTx = tree.TxTreeNode

type ForfeitTxsResp struct {
	Txs  []string
	Page PageResp
}

type GetVtxosResp struct {
	Vtxos []domain.Vtxo
	Page  PageResp
}

type VirtualTxsResp struct {
	Txs  []string
	Page PageResp
}

type Outpoint = domain.Outpoint

type TxType int

const (
	TxUnspecified TxType = iota
	TxReceived
	TxSent
)

type Page struct {
	PageSize int32
	PageNum  int32
}

type PageResp struct {
	Current int32
	Next    int32
	Total   int32
}

type ChainTxType string

const (
	IndexerChainedTxTypeUnspecified ChainTxType = "unspecified"
	IndexerChainedTxTypeCommitment  ChainTxType = "commitment"
	IndexerChainedTxTypeArk         ChainTxType = "ark"
	IndexerChainedTxTypeTree        ChainTxType = "tree"
	IndexerChainedTxTypeCheckpoint  ChainTxType = "checkpoint"
)

type ChainTx struct {
	Txid      string
	ExpiresAt int64
	Type      ChainTxType
	Spends    []string
}

type boardingIntentInput struct {
	ports.Input
	locktime         *arklib.RelativeLocktime
	locktimeDisabled bool
	witnessUtxo      *wire.TxOut
}
