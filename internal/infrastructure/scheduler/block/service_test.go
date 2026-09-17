package blockscheduler

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStop(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("100"))
	}))
	t.Cleanup(mock.Close)

	t.Run("waits for running task", func(t *testing.T) {
		svc, err := NewScheduler(mock.URL, WithTickerInterval(20*time.Millisecond))
		require.NoError(t, err)

		entered, release := make(chan struct{}), make(chan struct{})
		releaseTask := sync.OnceFunc(func() { close(release) })
		t.Cleanup(releaseTask)
		require.NoError(t, svc.ScheduleTaskOnce(1, func() {
			close(entered)
			<-release
		}))
		svc.Start()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("scheduled task did not start")
		}

		stopped := make(chan struct{})
		go func() {
			svc.Stop()
			close(stopped)
		}()
		select {
		case <-stopped:
			t.Fatal("Stop returned while a task was still running")
		case <-time.After(100 * time.Millisecond):
		}

		releaseTask()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("Stop did not return after the task finished")
		}
	})

	t.Run("gives up on blocked task", func(t *testing.T) {
		scheduler, err := NewScheduler(mock.URL, WithTickerInterval(20*time.Millisecond))
		require.NoError(t, err)
		svc := scheduler.(*service)
		svc.tasksTimeout = 100 * time.Millisecond

		entered, release := make(chan struct{}), make(chan struct{})
		t.Cleanup(func() { close(release) })
		require.NoError(t, svc.ScheduleTaskOnce(1, func() {
			close(entered)
			<-release
		}))
		svc.Start()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("scheduled task did not start")
		}

		stopped := make(chan time.Duration, 1)
		go func() {
			start := time.Now()
			svc.Stop()
			stopped <- time.Since(start)
		}()
		select {
		case elapsed := <-stopped:
			require.GreaterOrEqual(t, elapsed, svc.tasksTimeout,
				"Stop gave up before the grace period expired")
		case <-time.After(5 * time.Second):
			t.Fatal("Stop did not give up after the grace period expired")
		}
	})
}
