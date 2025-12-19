package blockscheduler

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

const tipHeightEndpoint = "/blocks/tip/height"

type Option func(*service)

func WithTickerInterval(interval time.Duration) Option {
	return func(s *service) {
		s.tickerInterval = interval
	}
}

type service struct {
	tipURL         string
	lock           sync.Locker
	taskes         map[int64][]func()
	stopCh         chan struct{}
	tickerInterval time.Duration
}

func NewScheduler(esploraURL string, opts ...Option) (ports.SchedulerService, error) {
	if len(esploraURL) == 0 {
		return nil, fmt.Errorf("esplora URL is required")
	}

	tipURL, err := url.JoinPath(esploraURL, tipHeightEndpoint)
	if err != nil {
		return nil, err
	}

	svc := &service{
		tipURL,
		&sync.Mutex{},
		make(map[int64][]func()),
		make(chan struct{}),
		time.Second * 10,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

func (s *service) Start() {
	go func() {
		ticker := time.NewTicker(s.tickerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				taskes, err := s.popTaskes()
				if err != nil {
					log.Errorf("error fetching tasks: %s", err)
					continue
				}

				log.Debugf("fetched %d tasks", len(taskes))
				for _, task := range taskes {
					go task()
				}
			}
		}
	}()
}

func (s *service) Stop() {
	s.stopCh <- struct{}{}
	close(s.stopCh)
}

func (s *service) Unit() ports.TimeUnit {
	return ports.BlockHeight
}

func (s *service) AfterNow(expiry int64) bool {
	tip, err := s.fetchTipHeight()
	if err != nil {
		return false
	}

	return expiry > tip
}

func (s *service) ScheduleTaskOnce(at int64, task func()) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.taskes[at]; !ok {
		s.taskes[at] = make([]func(), 0)
	}

	s.taskes[at] = append(s.taskes[at], task)

	return nil
}

func (s *service) popTaskes() ([]func(), error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	tip, err := s.fetchTipHeight()
	if err != nil {
		return nil, err
	}

	taskes := make([]func(), 0)

	for height, tasks := range s.taskes {
		if height > tip {
			continue
		}

		taskes = append(taskes, tasks...)
		delete(s.taskes, height)
	}

	return taskes, nil
}

func (s *service) fetchTipHeight() (int64, error) {
	resp, err := http.Get(s.tipURL)
	if err != nil {
		return 0, err
	}

	// nolint:all
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tip int64
	if _, err := fmt.Fscanf(resp.Body, "%d", &tip); err != nil {
		return 0, err
	}

	log.Debugf("fetching tip height from %s, got %d", s.tipURL, tip)

	return tip, nil
}
