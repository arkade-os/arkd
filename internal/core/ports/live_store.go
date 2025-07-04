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
	Len() int64
	Push(intent domain.Intent, boardingInputs []BoardingInput, cosignersPublicKeys []string) error
	Pop(num int64) []TimedIntent
	Update(intent domain.Intent, cosignersPublicKeys []string) error
	Delete(ids []string) error
	DeleteAll() error
	DeleteVtxos()
	ViewAll(ids []string) ([]TimedIntent, error)
	View(id string) (*domain.Intent, bool)
	IncludesAny(outpoints []domain.Outpoint) (bool, string)
}

type ForfeitTxsStore interface {
	Init(connectors tree.FlatTxTree, intents []domain.Intent) error
	Sign(txs []string) error
	Reset()
	Pop() ([]string, error)
	AllSigned() bool
	Len() int
	GetConnectorsIndexes() map[string]domain.Outpoint
}

type OffChainTxStore interface {
	Add(offchainTx domain.OffchainTx)
	Remove(arkTxid string)
	Get(arkTxid string) (domain.OffchainTx, bool)
	Includes(outpoint domain.Outpoint) bool
}

type CurrentRoundStore interface {
	Upsert(fn func(m *domain.Round) *domain.Round) error
	Get() *domain.Round
	Fail(err error) []domain.Event
}

type ConfirmationSessionsStore interface {
	Init(intentIDsHashes [][32]byte)
	Confirm(intentId string) error
	Get() *ConfirmationSessions
	Reset()
	Initialized() bool
	SessionCompleted() <-chan struct{}
}

type TreeSigningSessionsStore interface {
	New(roundId string, uniqueSignersPubKeys map[string]struct{}) *MusigSigningSession
	Get(roundId string) (*MusigSigningSession, bool)
	Delete(roundId string)
	AddNonces(ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces) error
	AddSignatures(
		ctx context.Context, roundId, pubkey string, nonces tree.TreePartialSigs,
	) error
	NoncesCollected(roundId string) <-chan struct{}
	SignaturesCollected(roundId string) <-chan struct{}
}

type BoardingInputsStore interface {
	Set(numOfInputs int)
	Get() int
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
