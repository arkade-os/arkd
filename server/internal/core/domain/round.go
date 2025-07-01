package domain

import (
	"fmt"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/google/uuid"
)

const (
	RoundUndefinedStage RoundStage = iota
	RoundRegistrationStage
	RoundFinalizationStage
)

type RoundStage int

func (s RoundStage) String() string {
	switch s {
	case RoundRegistrationStage:
		return "REGISTRATION_STAGE"
	case RoundFinalizationStage:
		return "FINALIZATION_STAGE"
	default:
		return "UNDEFINED_STAGE"
	}
}

type Stage struct {
	Code   int
	Ended  bool
	Failed bool
}

type ForfeitTx struct {
	Txid string
	Tx   string
}

type Round struct {
	Id                 string
	StartingTimestamp  int64
	EndingTimestamp    int64
	Stage              Stage
	TxRequests         map[string]TxRequest
	Txid               string
	CommitmentTx       string
	ForfeitTxs         []ForfeitTx
	VtxoTree           []tree.TxGraphChunk
	Connectors         []tree.TxGraphChunk
	ConnectorAddress   string
	Version            uint
	Swept              bool // true if all the vtxos are vtxo.Swept or vtxo.Redeemed
	VtxoTreeExpiration int64
	SweepTxs           map[string]string
	Changes            []Event
}

func NewRound() *Round {
	return &Round{
		Id:         uuid.New().String(),
		TxRequests: make(map[string]TxRequest),
		Changes:    make([]Event, 0),
	}
}

func NewRoundFromEvents(events []Event) *Round {
	r := &Round{}

	for _, event := range events {
		r.on(event, true)
	}

	r.Changes = append([]Event{}, events...)

	return r
}

func (r *Round) Events() []Event {
	return r.Changes
}

func (r *Round) StartRegistration() ([]Event, error) {
	empty := Stage{}
	if r.Stage != empty {
		return nil, fmt.Errorf("not in a valid stage to start tx requests registration")
	}

	event := RoundStarted{
		RoundEvent: RoundEvent{
			Id:   r.Id,
			Type: EventTypeRoundStarted,
		},
		Timestamp: time.Now().Unix(),
	}
	r.raise(event)

	return []Event{event}, nil
}

func (r *Round) RegisterTxRequests(txRequests []TxRequest) ([]Event, error) {
	if r.Stage.Code != int(RoundRegistrationStage) || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to register tx requests")
	}
	if len(txRequests) <= 0 {
		return nil, fmt.Errorf("missing tx requests to register")
	}
	for _, request := range txRequests {
		if err := request.validate(false); err != nil {
			return nil, err
		}
	}

	event := TxRequestsRegistered{
		RoundEvent: RoundEvent{
			Id:   r.Id,
			Type: EventTypeTxRequestsRegistered,
		},
		TxRequests: txRequests,
	}
	r.raise(event)

	return []Event{event}, nil
}

func (r *Round) StartFinalization(
	connectorAddress string,
	connectors []tree.TxGraphChunk,
	vtxoTree []tree.TxGraphChunk,
	txid string,
	roundTx string,
	vtxoTreeExpiration int64,
) ([]Event, error) {
	if len(roundTx) <= 0 {
		return nil, fmt.Errorf("missing unsigned round tx")
	}
	if vtxoTreeExpiration <= 0 {
		return nil, fmt.Errorf("missing vtxo tree expiration")
	}
	if r.Stage.Code != int(RoundRegistrationStage) || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to start finalization")
	}
	if len(r.TxRequests) <= 0 {
		return nil, fmt.Errorf("no tx requests registered")
	}
	if txid == "" {
		return nil, fmt.Errorf("missing txid")
	}

	event := RoundFinalizationStarted{
		RoundEvent: RoundEvent{
			Id:   r.Id,
			Type: EventTypeRoundFinalizationStarted,
		},
		VtxoTree:           vtxoTree,
		Connectors:         connectors,
		ConnectorAddress:   connectorAddress,
		Txid:               txid,
		RoundTx:            roundTx,
		VtxoTreeExpiration: vtxoTreeExpiration,
	}
	r.raise(event)

	return []Event{event}, nil
}

func (r *Round) EndFinalization(forfeitTxs []ForfeitTx, finalCommitmentTx string) ([]Event, error) {
	if len(forfeitTxs) <= 0 {
		for _, request := range r.TxRequests {
			for _, in := range request.Inputs {
				// The list of signed forfeit txs is required only if there is at least
				// one input that is not either a note or swept..
				if in.RequiresForfeit() {
					return nil, fmt.Errorf("missing list of signed forfeit txs")
				}
			}
		}
	}
	if r.Stage.Code != int(RoundFinalizationStage) || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to end finalization")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("round already finalized")
	}
	if forfeitTxs == nil {
		forfeitTxs = make([]ForfeitTx, 0)
	}

	event := RoundFinalized{
		RoundEvent: RoundEvent{
			Id:   r.Id,
			Type: EventTypeRoundFinalized,
		},
		ForfeitTxs:        forfeitTxs,
		FinalCommitmentTx: finalCommitmentTx,
		Timestamp:         time.Now().Unix(),
	}
	r.raise(event)

	return []Event{event}, nil
}

func (r *Round) Sweep(vtxos []Outpoint, txid, tx string) ([]Event, error) {
	if !r.IsEnded() {
		return nil, fmt.Errorf("not in a valid stage to sweep")
	}
	if r.Swept {
		return nil, nil
	}

	sweptVtxosCount := countSweptVtxos(r.Changes)
	leavesCount := len(tree.TxGraphChunkList(r.VtxoTree).Leaves())
	fullySwept := len(vtxos)+sweptVtxosCount == leavesCount

	event := BatchSwept{
		RoundEvent: RoundEvent{
			Id:   r.Id,
			Type: EventTypeBatchSwept,
		},
		Vtxos:      vtxos,
		Txid:       txid,
		Tx:         tx,
		FullySwept: fullySwept,
	}

	r.raise(event)

	return []Event{event}, nil
}

func (r *Round) Fail(err error) []Event {
	if r.Stage.Failed {
		return nil
	}
	event := RoundFailed{
		RoundEvent: RoundEvent{
			Id:   r.Id,
			Type: EventTypeRoundFailed,
		},
		Err:       err.Error(),
		Timestamp: time.Now().Unix(),
	}
	r.raise(event)

	return []Event{event}
}

func (r *Round) IsStarted() bool {
	empty := Stage{}
	return !r.IsFailed() && !r.IsEnded() && r.Stage != empty
}

func (r *Round) IsEnded() bool {
	return !r.IsFailed() && r.Stage.Code == int(RoundFinalizationStage) && r.Stage.Ended
}

func (r *Round) IsFailed() bool {
	return r.Stage.Failed
}

func (r *Round) ExpiryTimestamp() int64 {
	if r.IsEnded() {
		return time.Unix(r.EndingTimestamp, 0).Add(time.Second * time.Duration(r.VtxoTreeExpiration)).Unix()
	}
	return -1
}

func (r *Round) on(event Event, replayed bool) {
	switch e := event.(type) {
	case RoundStarted:
		r.Stage.Code = int(RoundRegistrationStage)
		r.Id = e.Id
		r.StartingTimestamp = e.Timestamp
	case RoundFinalizationStarted:
		r.Stage.Code = int(RoundFinalizationStage)
		r.VtxoTree = e.VtxoTree
		r.Connectors = e.Connectors
		r.ConnectorAddress = e.ConnectorAddress
		r.Txid = e.Txid
		r.CommitmentTx = e.RoundTx
		r.VtxoTreeExpiration = e.VtxoTreeExpiration
	case RoundFinalized:
		r.Stage.Ended = true
		r.ForfeitTxs = append([]ForfeitTx{}, e.ForfeitTxs...)
		r.EndingTimestamp = e.Timestamp
		r.CommitmentTx = e.FinalCommitmentTx
	case RoundFailed:
		r.Stage.Failed = true
		r.EndingTimestamp = e.Timestamp
	case TxRequestsRegistered:
		if r.TxRequests == nil {
			r.TxRequests = make(map[string]TxRequest)
		}
		for _, p := range e.TxRequests {
			r.TxRequests[p.Id] = p
		}
	case BatchSwept:
		if r.SweepTxs == nil {
			r.SweepTxs = make(map[string]string)
		}
		r.Swept = e.FullySwept
		r.SweepTxs[e.Txid] = e.Tx
	default:
		return
	}

	if replayed {
		r.Version++
	}
}

func (r *Round) raise(event Event) {
	if r.Changes == nil {
		r.Changes = make([]Event, 0)
	}
	r.Changes = append(r.Changes, event)
	r.on(event, false)
}

func countSweptVtxos(events []Event) int {
	count := 0
	for _, event := range events {
		if e, ok := event.(BatchSwept); ok {
			count += len(e.Vtxos)
		}
	}
	return count
}
