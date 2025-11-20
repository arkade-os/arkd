package ports

import (
	"context"
)

const (
	BatchFinalized Topic = "Batch Finalized"
	ArkTx          Topic = "Ark Tx"
)

type Topic string

type BatchFinalizedAlert struct {
	Id                                 string
	CommitmentTxid                     string
	Duration                           string
	LiquidityProviderInputAmount       uint64
	LiqudityProviderConfirmedBalance   uint64
	LiqudityProviderUnconfirmedBalance uint64
	LiquidityCost                      string
	LiquidityProvided                  uint64
	BoardingInputCount                 int
	BoardingInputAmount                uint64
	IntentsCount                       int
	LeafCount                          int
	LeafAmount                         uint64
	ConnectorsCount                    int
	ConnectorsAmount                   uint64
	ExitCount                          int
	ExitAmount                         uint64
	ForfeitCount                       int
	ForfeitAmount                      uint64
	OnchainFees                        uint64
	CollectedFees                      uint64
}

type Alerts interface {
	Publish(ctx context.Context, topic Topic, message any) error
}
