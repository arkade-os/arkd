package client

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

const (
	GrpcClient = "grpc"
	RestClient = "rest"
)

var (
	ErrConnectionClosedByServer = fmt.Errorf("connection closed by server")
)

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	RegisterIntent(ctx context.Context, signature, message string) (string, error)
	DeleteIntent(ctx context.Context, signature, message string) error
	ConfirmRegistration(ctx context.Context, intentID string) error
	SubmitTreeNonces(ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces) error
	SubmitTreeSignatures(ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs) error
	SubmitSignedForfeitTxs(ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string) error
	GetEventStream(ctx context.Context, topics []string) (<-chan BatchEventChannel, func(), error)
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (
		arkTxid, finalArkTx string, signedCheckpointTxs []string, err error,
	)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	GetTransactionsStream(ctx context.Context) (<-chan TransactionEvent, func(), error)
	Close()
}

type Info struct {
	Version                 string
	PubKey                  string
	VtxoTreeExpiry          int64
	UnilateralExitDelay     int64
	BoardingExitDelay       int64
	RoundInterval           int64
	Network                 string
	Dust                    uint64
	ForfeitAddress          string
	MarketHourStartTime     int64
	MarketHourEndTime       int64
	MarketHourPeriod        int64
	MarketHourRoundInterval int64
	UtxoMinAmount           int64
	UtxoMaxAmount           int64
	VtxoMinAmount           int64
	VtxoMaxAmount           int64
}

type BatchEventChannel struct {
	Event any
	Err   error
}

type Input struct {
	types.Outpoint
	Tapscripts []string
}

type TapscriptsVtxo struct {
	types.Vtxo
	Tapscripts []string
}

type BatchFinalizationEvent struct {
	Id string
	Tx string
}

type BatchFinalizedEvent struct {
	Id   string
	Txid string
}

type BatchFailedEvent struct {
	Id     string
	Reason string
}

type TreeSigningStartedEvent struct {
	Id                   string
	UnsignedCommitmentTx string
	CosignersPubkeys     []string
}

type TreeNoncesAggregatedEvent struct {
	Id     string
	Nonces tree.TreeNonces
}

type TreeTxEvent struct {
	Id           string
	Topic        []string
	BatchIndex   int32
	TxGraphChunk tree.TxGraphChunk
}

type TreeSignatureEvent struct {
	Id         string
	Topic      []string
	BatchIndex int32
	Txid       string
	Signature  string
}

type BatchStartedEvent struct {
	Id              string
	HashedIntentIds []string
	BatchExpiry     int64
}

type TransactionEvent struct {
	CommitmentTx *TxNotification
	ArkTx        *TxNotification
	Err          error
}

type TxData struct {
	Txid string
	Tx   string
}

type TxNotification struct {
	TxData
	SpentVtxos     []types.Vtxo
	SpendableVtxos []types.Vtxo
	CheckpointTxs  map[types.Outpoint]TxData
}
