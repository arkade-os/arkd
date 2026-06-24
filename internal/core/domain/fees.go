package domain

import (
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
)

type BatchFees struct {
	OnchainInputFee   string
	OffchainInputFee  string
	OnchainOutputFee  string
	OffchainOutputFee string
}

type BatchFeesUpdate struct {
	OnchainInputFee   *string
	OffchainInputFee  *string
	OnchainOutputFee  *string
	OffchainOutputFee *string
}

func NewBatchFees(
	onchainInputFee, offchainInputFee, onchainOutputFee, offchainOutputFee string,
) (*BatchFees, error) {
	fees := &BatchFees{
		OnchainInputFee:   onchainInputFee,
		OffchainInputFee:  offchainInputFee,
		OnchainOutputFee:  onchainOutputFee,
		OffchainOutputFee: offchainOutputFee,
	}
	if err := fees.Validate(); err != nil {
		return nil, err
	}
	return fees, nil
}

func (f *BatchFees) Update(u BatchFeesUpdate) error {
	// Apply the update to a copy so that, if validation fails, the fees are
	// left untouched.
	updated := *f

	if u.OnchainInputFee != nil {
		updated.OnchainInputFee = *u.OnchainInputFee
	}
	if u.OffchainInputFee != nil {
		updated.OffchainInputFee = *u.OffchainInputFee
	}
	if u.OnchainOutputFee != nil {
		updated.OnchainOutputFee = *u.OnchainOutputFee
	}
	if u.OffchainOutputFee != nil {
		updated.OffchainOutputFee = *u.OffchainOutputFee
	}
	if err := updated.Validate(); err != nil {
		return err
	}

	// Validation passed: commit the changes.
	*f = updated
	return nil
}

func (f *BatchFees) Validate() error {
	_, err := arkfee.New(arkfee.Config{
		IntentOffchainInputProgram:  f.OffchainInputFee,
		IntentOnchainInputProgram:   f.OnchainInputFee,
		IntentOffchainOutputProgram: f.OffchainOutputFee,
		IntentOnchainOutputProgram:  f.OnchainOutputFee,
	})
	return err
}
