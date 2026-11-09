package domain

import "fmt"

// VtxoFilter narrows a vtxo query. The Only flags are mutually exclusive.
type VtxoFilter struct {
	Pubkeys         []string
	AssetIDs        []string
	After           int64
	Before          int64
	SpendableOnly   bool
	SpentOnly       bool
	RecoverableOnly bool
	RenewableOnly   bool
	PendingOnly     bool
}

func NewVtxoFilter(
	spendableOnly, spentOnly, recoverableOnly, pendingOnly, renewableOnly bool,
	after, before int64,
) (VtxoFilter, error) {
	if err := validateTimeRange(after, before); err != nil {
		return VtxoFilter{}, err
	}
	options := []bool{spendableOnly, spentOnly, recoverableOnly, pendingOnly, renewableOnly}
	count := 0
	for _, v := range options {
		if v {
			count++
		}
	}
	if count > 1 {
		return VtxoFilter{}, fmt.Errorf(
			"spendable, spent, recoverable, pending and renewable filters are mutually exclusive",
		)
	}

	return VtxoFilter{
		After:           after,
		Before:          before,
		SpendableOnly:   spendableOnly,
		SpentOnly:       spentOnly,
		RecoverableOnly: recoverableOnly,
		RenewableOnly:   renewableOnly,
		PendingOnly:     pendingOnly,
	}, nil
}

// validateTimeRange validates time range values. A zero value means unbounded and is allowed.
func validateTimeRange(after, before int64) error {
	if after < 0 || before < 0 {
		return fmt.Errorf("after and before must be greater than or equal to 0")
	}
	if before > 0 && after > 0 && before <= after {
		return fmt.Errorf("before must be greater than after")
	}
	return nil
}
