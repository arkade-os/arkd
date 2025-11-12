package ports

import "context"

const (
	BatchFinalized Topic = "Batch Finalized"
	ArkTx          Topic = "Ark Tx"
)

type Topic string

type Alerts interface {
	Publish(ctx context.Context, topic Topic, message interface{}) error
}
