package domain

import "context"

type IntentFees struct {
	OnchainInputFee   string
	OffchainInputFee  string
	OnchainOutputFee  string
	OffchainOutputFee string
}

type FeeRepository interface {
	GetIntentFees(ctx context.Context) (*IntentFees, error)
	UpdateIntentFees(ctx context.Context, fees IntentFees) error
	ClearIntentFees(ctx context.Context) error
	Close()
}
