package domain

import (
	"fmt"
	"time"
)

const (
	OnchainTxUndefinedStage OnchainTxStage = iota
	OnchainTxBroadcastedStage
	OnchainTxConfirmedStage
)

type OnchainTxStage int

func (s OnchainTxStage) String() string {
	switch s {
	case OnchainTxBroadcastedStage:
		return "ONCHAIN_TX_BROADCASTED_STAGE"
	case OnchainTxConfirmedStage:
		return "ONCHAIN_TX_CONFIRMED_STAGE"
	default:
		return "ONCHAIN_TX_UNDEFINED_STAGE"
	}
}

type OnchainTx struct {
	Stage             Stage
	BroadcastedAt     int64
	ConfirmedAtTime   int64
	ConfirmedAtHeight uint64
	Txid              string
	Tx                string
	SignedInputs      map[string]struct{}
	Version           uint
	changes           []Event
}

func NewOnchainTx() *OnchainTx {
	return &OnchainTx{
		changes: make([]Event, 0),
	}
}

func NewOnchainTxFromEvents(events []Event) *OnchainTx {
	s := &OnchainTx{}

	for _, event := range events {
		s.on(event, true)
	}

	s.changes = append([]Event{}, events...)

	return s
}

func (s *OnchainTx) Broadcast(txid, tx string, signedInputs []Outpoint) (Event, error) {
	if s.Stage.Code != int(OnchainTxUndefinedStage) {
		return nil, fmt.Errorf("not in a valid stage to sign and broadcast an onchain tx")
	}
	if txid == "" {
		return nil, fmt.Errorf("missing onchain txid")
	}
	if tx == "" {
		return nil, fmt.Errorf("missing onchain tx")
	}
	if len(signedInputs) <= 0 {
		return nil, fmt.Errorf("missing signed inputs")
	}

	indexedInputs := make(map[string]struct{})
	for _, input := range signedInputs {
		indexedInputs[input.String()] = struct{}{}
	}
	event := OnchainTxBroadcasted{
		OnchainTxEvent: OnchainTxEvent{
			Id:   txid,
			Type: EventTypeOnchainTxBroadcasted,
		},
		Tx:           tx,
		SignedInputs: indexedInputs,
		Timestamp:    time.Now().Unix(),
	}
	s.raise(event)
	return event, nil
}

func (s *OnchainTx) Confirm(confirmedAtTime int64, confirmedAtHeight uint64) (Event, error) {
	if s.Stage.Code != int(OnchainTxBroadcastedStage) {
		return nil, fmt.Errorf("not in a valid stage to confirm an onchain tx")
	}
	if confirmedAtTime <= 0 {
		return nil, fmt.Errorf("missing confirmation time")
	}
	if confirmedAtHeight == 0 {
		return nil, fmt.Errorf("missing confirmation height")
	}

	event := OnchainTxConfirmed{
		OnchainTxEvent: OnchainTxEvent{
			Id:   s.Txid,
			Type: EventTypeOnchainTxConfirmed,
		},
		ConfirmedAtTime:   confirmedAtTime,
		ConfirmedAtHeight: confirmedAtHeight,
	}
	s.raise(event)
	return event, nil
}

func (s *OnchainTx) Events() []Event {
	return s.changes
}

func (s *OnchainTx) IsBroadcasted() bool {
	return s.Stage.Code == int(OnchainTxBroadcastedStage) && s.Txid != ""
}

func (s *OnchainTx) IsConfirmed() bool {
	return s.Stage.Code == int(OnchainTxConfirmedStage) && s.Stage.Ended &&
		s.ConfirmedAtTime > 0 && s.ConfirmedAtHeight > 0
}

func (s *OnchainTx) on(event Event, replayed bool) {
	switch e := event.(type) {
	case OnchainTxBroadcasted:
		if s.Stage.Code != int(OnchainTxUndefinedStage) {
			return
		}
		s.Stage.Failed = false
		s.Stage.Code = int(OnchainTxBroadcastedStage)
		s.Txid = e.Id
		s.Tx = e.Tx
		// Copied, the event is kept in the history and must not be aliased.
		s.SignedInputs = make(map[string]struct{}, len(e.SignedInputs))
		for input := range e.SignedInputs {
			s.SignedInputs[input] = struct{}{}
		}
		s.BroadcastedAt = e.Timestamp
	case OnchainTxConfirmed:
		if s.Stage.Code != int(OnchainTxBroadcastedStage) {
			return
		}
		s.Stage.Code = int(OnchainTxConfirmedStage)
		s.Stage.Ended = true
		s.ConfirmedAtTime = e.ConfirmedAtTime
		s.ConfirmedAtHeight = e.ConfirmedAtHeight
	}

	if replayed {
		s.Version++
	}
}

func (s *OnchainTx) raise(event Event) {
	if s.changes == nil {
		s.changes = make([]Event, 0)
	}
	s.changes = append(s.changes, event)
	s.on(event, false)
}
