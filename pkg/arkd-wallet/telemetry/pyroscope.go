package telemetry

import (
	"context"
	"runtime"

	"github.com/grafana/pyroscope-go"
	log "github.com/sirupsen/logrus"
)

const arkdWallet = "arkd-wallet"

// InitPyroscope initializes the Pyroscope profiler for continuous profiling.
// It returns a shutdown function that should be called on application exit.
// If pyroscopeServerURL is empty, this function does nothing and returns a no-op shutdown function.
func InitPyroscope(ctx context.Context, pyroscopeServerURL string) (func(), error) {
	if pyroscopeServerURL == "" {
		return func() {}, nil
	}

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: arkdWallet,
		ServerAddress:   pyroscopeServerURL,
		Logger:          pyroscope.StandardLogger,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileInuseSpace,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileMutexCount,
			pyroscope.ProfileMutexDuration,
			pyroscope.ProfileBlockCount,
			pyroscope.ProfileBlockDuration,
		},
	})
	if err != nil {
		log.WithError(err).Warnf("failed to start pyroscope profiler, continuing without profiling")
		return func() {}, nil
	}

	log.WithFields(log.Fields{
		"server":  pyroscopeServerURL,
		"service": arkdWallet,
	}).Info("pyroscope profiler started successfully")

	shutdown := func() {
		if profiler != nil {
			if err := profiler.Stop(); err != nil {
				log.WithError(err).Warn("error stopping pyroscope profiler")
			} else {
				log.Info("pyroscope profiler stopped")
			}
		}
	}

	// Log profiling overhead estimate
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.WithFields(log.Fields{
		"alloc_mb":      m.Alloc / 1024 / 1024,
		"profile_types": 10,
	}).Debug("pyroscope profiler initialized")

	return shutdown, nil
}
