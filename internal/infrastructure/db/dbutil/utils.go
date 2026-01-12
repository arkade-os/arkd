package dbutil

import "fmt"

// Validates time range values. A zero value means unbounded and is allowed.
func ValidateTimeRange(after, before int64) error {
	if after < 0 || before < 0 {
		return fmt.Errorf("after and before must be greater than or equal to 0")
	}
	if before > 0 && after > 0 && before <= after {
		return fmt.Errorf("before must be greater than after")
	}
	return nil
}
