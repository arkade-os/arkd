package client

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

const (
	GrpcClient = "grpc"
	RestClient = "rest"
)

var (
	ErrConnectionClosedByServer = fmt.Errorf("connection closed by server")
)

type AcceptedOffchainTx struct {
	Txid                string
	FinalArkTx          string
	SignedCheckpointTxs []string
}

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	RegisterIntent(ctx context.Context, proof, message string) (string, error)
	DeleteIntent(ctx context.Context, proof, message string) error
	ConfirmRegistration(ctx context.Context, intentID string) error
	SubmitTreeNonces(
		ctx context.Context,
		batchId, cosignerPubkey string,
		nonces tree.TreeNonces,
	) error
	SubmitTreeSignatures(
		ctx context.Context,
		batchId, cosignerPubkey string,
		signatures tree.TreePartialSigs,
	) error
	SubmitSignedForfeitTxs(
		ctx context.Context,
		signedForfeitTxs []string,
		signedCommitmentTx string,
	) error
	GetEventStream(ctx context.Context, topics []string) (<-chan BatchEventChannel, func(), error)
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (
		// TODO SubmitTx should return AcceptedOffchainTx struct
		arkTxid, finalArkTx string, signedCheckpointTxs []string, err error,
	)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	GetPendingTx(ctx context.Context, proof, message string) ([]AcceptedOffchainTx, error)
	GetTransactionsStream(ctx context.Context) (<-chan TransactionEvent, func(), error)
	Close()
}

type Info struct {
	Version                   string
	SignerPubKey              string
	ForfeitPubKey             string
	UnilateralExitDelay       int64
	BoardingExitDelay         int64
	SessionDuration           int64
	Network                   string
	Dust                      uint64
	ForfeitAddress            string
	ScheduledSessionStartTime int64
	ScheduledSessionEndTime   int64
	ScheduledSessionPeriod    int64
	ScheduledSessionDuration  int64
	ScheduledSessionFees      types.FeeInfo
	UtxoMinAmount             int64
	UtxoMaxAmount             int64
	VtxoMinAmount             int64
	VtxoMaxAmount             int64
	CheckpointTapscript       string
	Fees                      types.FeeInfo
	DeprecatedSignerPubKeys   []DeprecatedSigner
	ServiceStatus             map[string]string
	Digest                    string
}

type DeprecatedSigner struct {
	PubKey     string
	CutoffDate int64
}

type BatchEventChannel struct {
	Event any
	Err   error
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

type TreeNoncesEvent struct {
	Id     string
	Topic  []string
	Txid   string
	Nonces map[string]*tree.Musig2Nonce
}

type TreeTxEvent struct {
	Id         string
	Topic      []string
	BatchIndex int32
	Node       tree.TxTreeNode
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
