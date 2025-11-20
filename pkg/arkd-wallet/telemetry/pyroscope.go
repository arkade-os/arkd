package telemetry

import (
	"fmt"

	"github.com/grafana/pyroscope-go"
	log "github.com/sirupsen/logrus"
)

const arkdWallet = "arkd-wallet"

// InitPyroscope initializes the Pyroscope profiler for continuous profiling.
// It returns a shutdown function that should be called on application exit.
// If pyroscopeServerURL is empty, this function does nothing and returns a no-op shutdown function.
func InitPyroscope(pyroscopeServerURL string) (func() error, error) {
	if pyroscopeServerURL == "" {
		return nil, nil
	}

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: arkdWallet,
		ServerAddress:   pyroscopeServerURL,
		Logger:          nil,
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
		return nil, fmt.Errorf("failed to start pyroscope profiler: %s", err)
	}

	log.WithFields(log.Fields{
		"server":  pyroscopeServerURL,
		"service": arkdWallet,
	}).Info("pyroscope profiler started successfully")

	shutdown := func() error {
		if profiler != nil {
			return profiler.Stop()
		}
		return nil
	}

	return shutdown, nil
}
