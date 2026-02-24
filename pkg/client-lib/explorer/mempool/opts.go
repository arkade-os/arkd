package mempool_explorer

import "time"

// Option is a functional option for configuring the Explorer service.
type Option func(*explorerSvc)

// WithPollInterval sets the polling interval for address tracking when WebSocket is unavailable.
// Default: 10 seconds.
func WithPollInterval(interval time.Duration) Option {
	return func(svc *explorerSvc) {
		svc.pollInterval = interval
	}
}

// WithTracker enables or disables address tracking.
// When disabled, the explorer only provides REST API functionality without WebSocket connections.
// Default: tracking is disabled.
func WithTracker(withTracker bool) Option {
	return func(svc *explorerSvc) {
		if !withTracker {
			svc.noTracking = true
		}
	}
}
