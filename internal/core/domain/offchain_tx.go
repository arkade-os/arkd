package domain

import (
	"fmt"
	"time"
)

const (
	OffchainTxUndefinedStage OffchainTxStage = iota
	OffchainTxRequestedStage
	OffchainTxAcceptedStage
	OffchainTxFinalizedStage
)

type OffchainTxStage int

func (s OffchainTxStage) String() string {
	switch s {
	case OffchainTxRequestedStage:
		return "OFFCHAIN_TX_REQUESTED_STAGE"
	case OffchainTxAcceptedStage:
		return "OFFCHAIN_TX_ACCEPTED_STAGE"
	case OffchainTxFinalizedStage:
		return "OFFCHAIN_TX_FINALIZED_STAGE"
	default:
		return "OFFCHAIN_TX_UNDEFINED_STAGE"
	}
}

type Tx struct {
	Txid string
	Str  string
}

type OffchainTx struct {
	Stage              Stage
	StartingTimestamp  int64
	EndingTimestamp    int64
	ArkTxid            string
	ArkTx              string
	CheckpointTxs      map[string]string
	CommitmentTxids    map[string]string
	RootCommitmentTxId string
	ExpiryTimestamp    int64
	FailReason         string
	Version            uint
	changes            []Event
}

func NewOffchainTx() *OffchainTx {
	return &OffchainTx{
		changes: make([]Event, 0),
	}
}

func NewOffchainTxFromEvents(events []Event) *OffchainTx {
	s := &OffchainTx{}

	for _, event := range events {
		s.on(event, true)
	}

	s.changes = append([]Event{}, events...)

	return s
}

func (s *OffchainTx) Request(
	arkTxid, arkTx string, unsignedCheckpointTxs map[string]string,
) (Event, error) {
	if s.IsFailed() || s.Stage.Code != int(OffchainTxUndefinedStage) {
		return nil, fmt.Errorf("not in a valid stage to request offchain tx")
	}
	if arkTxid == "" {
		return nil, fmt.Errorf("missing ark txid")
	}
	if arkTx == "" {
		return nil, fmt.Errorf("missing ark tx")
	}
	if len(unsignedCheckpointTxs) == 0 {
		return nil, fmt.Errorf("missing unsigned checkpoint txs")
	}

	event := OffchainTxRequested{
		OffchainTxEvent: OffchainTxEvent{
			Id:   arkTxid,
			Type: EventTypeOffchainTxRequested,
		},
		ArkTx:                 arkTx,
		UnsignedCheckpointTxs: unsignedCheckpointTxs,
		StartingTimestamp:     time.Now().Unix(),
	}
	s.raise(event)
	return event, nil
}

func (s *OffchainTx) Accept(
	finalArkTx string, signedCheckpointTxs map[string]string,
	commitmentTxsByCheckpointTxid map[string]string, rootCommitmentTx string, expiryTimestamp int64,
) (Event, error) {
	if finalArkTx == "" {
		return nil, fmt.Errorf("missing final ark tx")
	}
	if len(signedCheckpointTxs) == 0 {
		return nil, fmt.Errorf("missing signed checkpoint txs")
	}
	if len(signedCheckpointTxs) != len(s.CheckpointTxs) {
		return nil, fmt.Errorf(
			"invalid number of signed checkpoint txs, expected %d, got %d",
			len(s.CheckpointTxs), len(signedCheckpointTxs),
		)
	}
	if len(commitmentTxsByCheckpointTxid) == 0 {
		return nil, fmt.Errorf("missing commitment txids")
	}
	if rootCommitmentTx == "" {
		return nil, fmt.Errorf("missing root commitment txid")
	}
	if !s.IsRequested() {
		return nil, fmt.Errorf("not in a valid stage to accept offchain tx")
	}
	if expiryTimestamp <= 0 {
		return nil, fmt.Errorf("missing expiry timestamp")
	}
	event := OffchainTxAccepted{
		OffchainTxEvent: OffchainTxEvent{
			Id:   s.ArkTxid,
			Type: EventTypeOffchainTxAccepted,
		},
		FinalArkTx:          finalArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
		CommitmentTxids:     commitmentTxsByCheckpointTxid,
		RootCommitmentTxid:  rootCommitmentTx,
		ExpiryTimestamp:     expiryTimestamp,
	}
	s.raise(event)
	return event, nil
}

func (s *OffchainTx) Finalize(finalCheckpointTxs map[string]string) (Event, error) {
	if len(finalCheckpointTxs) == 0 {
		return nil, fmt.Errorf("missing final checkpoint txs")
	}
	if len(finalCheckpointTxs) != len(s.CheckpointTxs) {
		return nil, fmt.Errorf(
			"invalid number of final checkpoint txs, expected %d, got %d",
			len(s.CheckpointTxs), len(finalCheckpointTxs),
		)
	}
	if !s.IsAccepted() {
		return nil, fmt.Errorf("not in a valid stage to finalize offchain tx")
	}

	event := OffchainTxFinalized{
		OffchainTxEvent: OffchainTxEvent{
			Id:   s.ArkTxid,
			Type: EventTypeOffchainTxFinalized,
		},
		FinalCheckpointTxs: finalCheckpointTxs,
		Timestamp:          time.Now().Unix(),
	}
	s.raise(event)
	return event, nil
}

func (s *OffchainTx) Fail(err error) Event {
	event := OffchainTxFailed{
		OffchainTxEvent: OffchainTxEvent{
			Id:   s.ArkTxid,
			Type: EventTypeOffchainTxFailed,
		},
		Reason:    err.Error(),
		Timestamp: time.Now().Unix(),
	}
	s.raise(event)
	return event
}

func (s *OffchainTx) Events() []Event {
	return s.changes
}

func (s *OffchainTx) IsRequested() bool {
	return !s.IsFailed() && s.Stage.Code == int(OffchainTxRequestedStage)
}

func (s *OffchainTx) IsAccepted() bool {
	return !s.IsFailed() && s.Stage.Code == int(OffchainTxAcceptedStage)
}

func (s *OffchainTx) IsFinalized() bool {
	return !s.IsFailed() && s.Stage.Code == int(OffchainTxFinalizedStage)
}

func (s *OffchainTx) IsFailed() bool {
	return s.Stage.Failed
}

func (s *OffchainTx) CommitmentTxidsList() []string {
	indexedList := make(map[string]struct{})
	for _, txid := range s.CommitmentTxids {
		indexedList[txid] = struct{}{}
	}
	list := make([]string, 0, len(indexedList))
	for txid := range indexedList {
		list = append(list, txid)
	}
	return list
}

func (s *OffchainTx) on(event Event, replayed bool) {
	switch e := event.(type) {
	case OffchainTxRequested:
		s.Stage.Code = int(OffchainTxRequestedStage)
		s.ArkTxid = e.Id
		s.ArkTx = e.ArkTx
		s.CheckpointTxs = e.UnsignedCheckpointTxs
		s.StartingTimestamp = e.StartingTimestamp
	case OffchainTxAccepted:
		s.Stage.Code = int(OffchainTxAcceptedStage)
		s.ArkTx = e.FinalArkTx
		s.CheckpointTxs = e.SignedCheckpointTxs
		s.CommitmentTxids = e.CommitmentTxids
		s.RootCommitmentTxId = e.RootCommitmentTxid
		s.ExpiryTimestamp = e.ExpiryTimestamp
	case OffchainTxFinalized:
		s.Stage.Code = int(OffchainTxFinalizedStage)
		s.CheckpointTxs = e.FinalCheckpointTxs
		s.EndingTimestamp = e.Timestamp
	case OffchainTxFailed:
		s.Stage.Failed = true
		s.FailReason = e.Reason
		s.EndingTimestamp = e.Timestamp
	}

	if replayed {
		s.Version++
	}
}

func (s *OffchainTx) raise(event Event) {
	if s.changes == nil {
		s.changes = make([]Event, 0)
	}
	s.changes = append(s.changes, event)
	s.on(event, false)
}
