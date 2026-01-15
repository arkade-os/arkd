package ports

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

type LiveStore interface {
	Intents() IntentStore
	ForfeitTxs() ForfeitTxsStore
	OffchainTxs() OffChainTxStore
	CurrentRound() CurrentRoundStore
	ConfirmationSessions() ConfirmationSessionsStore
	TreeSigingSessions() TreeSigningSessionsStore
	BoardingInputs() BoardingInputsStore
}

type IntentStore interface {
	Len(ctx context.Context) (int64, error)
	Push(
		ctx context.Context, intent domain.Intent, boardingInputs []BoardingInput, cosignersPublicKeys []string,
	) error
	Pop(ctx context.Context, num int64) ([]TimedIntent, error)
	GetSelectedIntents(ctx context.Context) ([]TimedIntent, error)
	// TODO uncomment when we have a way to register outputs outside of intent proof
	// Update(intent domain.Intent, cosignersPublicKeys []string) error
	Delete(ctx context.Context, ids []string) error
	DeleteAll(ctx context.Context) error
	DeleteVtxos(ctx context.Context) error
	ViewAll(ctx context.Context, ids []string) ([]TimedIntent, error)
	IncludesAny(ctx context.Context, outpoints []domain.Outpoint) (bool, string)
}

type ForfeitTxsStore interface {
	Init(ctx context.Context, connectors tree.FlatTxTree, intents []domain.Intent) error
	Sign(ctx context.Context, txs []string) error
	Reset(ctx context.Context) error
	Pop(ctx context.Context) ([]string, error)
	AllSigned(ctx context.Context) (bool, error)
	GetUnsignedInputs(ctx context.Context) ([]domain.Outpoint, error)
	Len(ctx context.Context) (int, error)
	GetConnectorsIndexes(ctx context.Context) (map[string]domain.Outpoint, error)
}

type OffChainTxStore interface {
	Add(ctx context.Context, offchainTx domain.OffchainTx) error
	Remove(ctx context.Context, arkTxid string) error
	Get(ctx context.Context, arkTxid string) (*domain.OffchainTx, error)
	Includes(ctx context.Context, outpoint domain.Outpoint) (bool, error)
	GetTxidByOutpoint(ctx context.Context, outpoint domain.Outpoint) (string, error)
}

type CurrentRoundStore interface {
	Upsert(ctx context.Context, fn func(m *domain.Round) *domain.Round) error
	Get(ctx context.Context) (*domain.Round, error)
}

type ConfirmationSessionsStore interface {
	Init(ctx context.Context, intentIDsHashes [][32]byte) error
	Confirm(ctx context.Context, intentId string) error
	Get(ctx context.Context) (*ConfirmationSessions, error)
	Reset(ctx context.Context) error
	Initialized(ctx context.Context) bool
	SessionCompleted() <-chan struct{}
}

type TreeSigningSessionsStore interface {
	New(ctx context.Context, roundId string, uniqueSignersPubKeys map[string]struct{}) error
	Get(ctx context.Context, roundId string) (*MusigSigningSession, error)
	Delete(ctx context.Context, roundId string) error
	AddNonces(ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces) error
	AddSignatures(
		ctx context.Context, roundId, pubkey string, nonces tree.TreePartialSigs,
	) error
	NoncesCollected(roundId string) <-chan struct{}
	SignaturesCollected(roundId string) <-chan struct{}
}

type BoardingInputsStore interface {
	Set(ctx context.Context, numOfInputs int) error
	Get(ctx context.Context) (int, error)
	AddSignatures(
		ctx context.Context, batchId string, inputSigs map[uint32]SignedBoardingInput,
	) error
	GetSignatures(ctx context.Context, batchId string) (map[uint32]SignedBoardingInput, error)
	DeleteSignatures(ctx context.Context, batchId string) error
}

type TimedIntent struct {
	domain.Intent
	BoardingInputs      []BoardingInput
	Timestamp           time.Time
	CosignersPublicKeys []string
}

func (t TimedIntent) HashID() [32]byte {
	return sha256.Sum256([]byte(t.Id))
}

// MusigSigningSession holds the state of ephemeral nonces and signatures in order to coordinate the signing of the tree
type MusigSigningSession struct {
	NbCosigners int
	Cosigners   map[string]struct{}
	Nonces      map[string]tree.TreeNonces

	Signatures map[string]tree.TreePartialSigs
}

type ConfirmationSessions struct {
	IntentsHashes       map[[32]byte]bool // hash --> confirmed
	NumIntents          int
	NumConfirmedIntents int
}
