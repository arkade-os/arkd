package clientlib

import (
	"context"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

const (
	GrpcClient = "grpc"
)

var (
	ErrConnectionClosedByServer = fmt.Errorf("connection closed by server")
)

type AcceptedOffchainTx struct {
	Txid                string
	FinalArkTx          string
	SignedCheckpointTxs []string
}

type Client interface {
	GetInfo(ctx context.Context) (*Info, error)
	RegisterIntent(ctx context.Context, proof, message string) (string, error)
	DeleteIntent(ctx context.Context, proof, message string) error
	EstimateIntentFee(ctx context.Context, proof, message string) (int64, error)
	ConfirmRegistration(ctx context.Context, intentID string) error
	SubmitTreeNonces(
		ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces,
	) error
	SubmitTreeSignatures(
		ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs,
	) error
	SubmitSignedForfeitTxs(
		ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
	) error
	GetEventStream(ctx context.Context, topics []string) (<-chan BatchEventChannel, func(), error)
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (
		// TODO SubmitTx should return AcceptedOffchainTx struct
		arkTxid, finalArkTx string, signedCheckpointTxs []string, err error,
	)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	GetPendingTx(ctx context.Context, proof, message string) ([]AcceptedOffchainTx, error)
	GetTransactionsStream(ctx context.Context) (<-chan TransactionEvent, func(), error)
	ModifyStreamTopics(
		ctx context.Context, addTopics, removeTopics []string,
	) (addedTopics, removedTopics, allTopics []string, err error)
	OverwriteStreamTopics(
		ctx context.Context, topics []string,
	) (addedTopics, removedTopics, allTopics []string, err error)
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
	ScheduledSessionFees      FeeInfo
	UtxoMinAmount             int64
	UtxoMaxAmount             int64
	VtxoMinAmount             int64
	VtxoMaxAmount             int64
	CheckpointTapscript       string
	MaxTxWeight               int64
	MaxOpReturnOutputs        int64
	Fees                      FeeInfo
	DeprecatedSignerPubKeys   []DeprecatedSignerInfo
	ServiceStatus             map[string]string
	Digest                    string
}

func (i Info) ServerParams(serverUrl, explorerUrl string) (*ServerParams, error) {
	network := NetworkFromString(i.Network)

	signerPubkey, err := EcPubkeyFromHex(i.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signer pubkey: %s", err)
	}

	forfeitPubkey, err := EcPubkeyFromHex(i.ForfeitPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse forfeit pubkey: %s", err)
	}

	unilateralExitDelayType := arklib.LocktimeTypeBlock
	if i.UnilateralExitDelay >= 512 {
		unilateralExitDelayType = arklib.LocktimeTypeSecond
	}

	boardingExitDelayType := arklib.LocktimeTypeBlock
	if i.BoardingExitDelay >= 512 {
		boardingExitDelayType = arklib.LocktimeTypeSecond
	}

	deprecatedSigners := make([]DeprecatedSigner, 0, len(i.DeprecatedSignerPubKeys))
	for _, signer := range i.DeprecatedSignerPubKeys {
		pubkey, err := EcPubkeyFromHex(signer.PubKey)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to parse deprecated signer pubkey %s: %s", signer.PubKey, err,
			)
		}
		var cutoffDate time.Time
		if signer.CutoffDate > 0 {
			cutoffDate = time.Unix(signer.CutoffDate, 0)
		}
		deprecatedSigners = append(deprecatedSigners, DeprecatedSigner{
			PubKey:     pubkey,
			CutoffDate: cutoffDate,
		})
	}

	return &ServerParams{
		ServerUrl:       serverUrl,
		SignerPubKey:    signerPubkey,
		ForfeitPubKey:   forfeitPubkey,
		Network:         network,
		SessionDuration: i.SessionDuration,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type: unilateralExitDelayType, Value: uint32(i.UnilateralExitDelay),
		},
		Dust: i.Dust,
		BoardingExitDelay: arklib.RelativeLocktime{
			Type: boardingExitDelayType, Value: uint32(i.BoardingExitDelay),
		},
		ExplorerURL:         explorerUrl,
		ForfeitAddress:      i.ForfeitAddress,
		UtxoMinAmount:       i.UtxoMinAmount,
		UtxoMaxAmount:       i.UtxoMaxAmount,
		VtxoMinAmount:       i.VtxoMinAmount,
		VtxoMaxAmount:       i.VtxoMaxAmount,
		CheckpointTapscript: i.CheckpointTapscript,
		Fees:                i.Fees,
		DeprecatedSigners:   deprecatedSigners,
		Digest:              i.Digest,
	}, nil
}

type DeprecatedSignerInfo struct {
	PubKey     string
	CutoffDate int64
}

type BatchEventChannel struct {
	Event      any
	Connection *StreamConnectionEvent
	Err        error
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

type StreamStartedEvent struct {
	Id string
}

type BatchStartedEvent struct {
	Id              string
	HashedIntentIds []string
	BatchExpiry     int64
}

type TransactionEvent struct {
	CommitmentTx *TxNotification
	ArkTx        *TxNotification
	SweepTx      *TxNotification
	Connection   *StreamConnectionEvent
	Err          error
}

type TxData struct {
	Txid string
	Tx   string
}

type TxNotification struct {
	TxData
	SpentVtxos     []Vtxo
	SpendableVtxos []Vtxo
	CheckpointTxs  map[Outpoint]TxData
	SweptVtxos     []Outpoint
}
