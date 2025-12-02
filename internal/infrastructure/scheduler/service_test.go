package scheduler_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	blockscheduler "github.com/arkade-os/arkd/internal/infrastructure/scheduler/block"
	timescheduler "github.com/arkade-os/arkd/internal/infrastructure/scheduler/gocron"
	"github.com/stretchr/testify/require"
)

type service struct {
	name      string
	scheduler ports.SchedulerService
}

func TestScheduleTask(t *testing.T) {
	t.Parallel()

	svcs := servicesToTest(t)

	for _, svc := range svcs {
		t.Run(svc.name, func(t *testing.T) {
			handlerFuncCalled := false
			handlerFunc := func() {
				handlerFuncCalled = true
			}

			err := svc.scheduler.ScheduleTaskOnce(svc.scheduler.AddNow(2), handlerFunc)
			require.NoError(t, err)

			time.Sleep(3 * time.Second)

			require.True(t, handlerFuncCalled)
		})
	}
}

func servicesToTest(t *testing.T) []service {
	// mock esplora server for block tip endpoint
	var blockHeight int64 = 99
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocks/tip/height" {
			w.WriteHeader(http.StatusOK)
			height := atomic.AddInt64(&blockHeight, 1)
			// nolint:errcheck
			fmt.Fprintf(w, "%d", height)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(func() {
		mockServer.Close()
	})

	blockService, err := blockscheduler.NewScheduler(
		mockServer.URL,
		blockscheduler.WithTickerInterval(time.Second*1),
	)
	if err != nil {
		t.Fatalf("failed to create block scheduler: %v", err)
	}

	svcs := []service{
		{name: "gocron", scheduler: timescheduler.NewScheduler()},
		{name: "block", scheduler: blockService},
	}

	for _, svc := range svcs {
		svc.scheduler.Start()
		t.Cleanup(func() { svc.scheduler.Stop() })
	}

	return svcs
}
