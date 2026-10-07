package domain

const OnchainTxTopic = "onchain_tx"

type OnchainTxEvent struct {
	Id   string
	Type EventType
}

func (s OnchainTxEvent) GetTopic() string   { return OnchainTxTopic }
func (s OnchainTxEvent) GetType() EventType { return s.Type }

type OnchainTxBroadcasted struct {
	OnchainTxEvent
	Tx           string
	SignedInputs map[string]struct{}
	Timestamp    int64
}

type OnchainTxConfirmed struct {
	OnchainTxEvent
	ConfirmedAtTime   int64
	ConfirmedAtHeight uint64
}
