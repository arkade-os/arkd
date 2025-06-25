package ports

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
)

type LiveStore interface {
	TxRequests() TxRequestsStore
	ForfeitTxs() ForfeitTxsStore
	OffchainTxs() OffChainTxStore
	CurrentRound() CurrentRoundStore
	ConfirmationSessions() ConfirmationSessionsStore
	TreeSigingSessions() TreeSigningSessionsStore
	BoardingInputs() BoardingInputsStore
}

type TxRequestsStore interface {
	Len() int64
	Push(request domain.TxRequest, boardingInputs []BoardingInput, cosignersPublicKeys []string) error
	Pop(num int64) []TimedTxRequest
	Update(request domain.TxRequest, cosignersPublicKeys []string) error
	Delete(ids []string) error
	DeleteAll() error
	DeleteVtxos()
	ViewAll(ids []string) ([]TimedTxRequest, error)
	View(id string) (*domain.TxRequest, bool)
	IncludesAny(outpoints []domain.Outpoint) (bool, string)
}

type ForfeitTxsStore interface {
	Init(connectors []tree.TxGraphChunk, requests []domain.TxRequest) error
	Sign(txs []string) error
	Reset()
	Pop() ([]string, error)
	AllSigned() bool
	Len() int
	GetConnectorsIndexes() map[string]domain.Outpoint
}

type OffChainTxStore interface {
	Add(offchainTx domain.OffchainTx)
	Remove(virtualTxid string)
	Get(virtualTxid string) (domain.OffchainTx, bool)
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
	AddSignatures(ctx context.Context, roundId string, pubkey string, nonces tree.TreePartialSigs) error
	NoncesCollected(roundId string) <-chan struct{}
	SignaturesCollected(roundId string) <-chan struct{}
}

type BoardingInputsStore interface {
	Set(numOfInputs int)
	Get() int
}

type TimedTxRequest struct {
	domain.TxRequest
	BoardingInputs      []BoardingInput
	Timestamp           time.Time
	CosignersPublicKeys []string
}

func (t TimedTxRequest) HashID() [32]byte {
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
