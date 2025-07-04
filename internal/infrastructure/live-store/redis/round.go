package redislivestore

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	currentRoundKey   = "currentRoundStore:round"
	boardingInputsKey = "boardingInputsStore:numOfInputs"
)

type currentRoundStore struct {
	rdb          *redis.Client
	numOfRetries int
}

type boardingInputsStore struct {
	rdb *redis.Client
}

func NewCurrentRoundStore(rdb *redis.Client, numOfRetries int) ports.CurrentRoundStore {
	return &currentRoundStore{rdb: rdb, numOfRetries: numOfRetries}
}

func (s *currentRoundStore) Upsert(fn func(m *domain.Round) *domain.Round) error {
	ctx := context.Background()
	for attempt := 0; attempt < s.numOfRetries; attempt++ {
		if err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			updated := fn(s.Get())
			val, err := json.Marshal(updated)
			if err != nil {
				return err
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, currentRoundKey, val, 0)
				return nil
			})

			return err
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *currentRoundStore) Get() *domain.Round {
	data, err := s.rdb.Get(context.Background(), currentRoundKey).Bytes()
	if err != nil {
		return nil
	}

	type roundAlias domain.Round
	var temp struct {
		roundAlias
		Changes []json.RawMessage `json:"Changes"` // use the exported field name
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		log.Warnf("failed to unmarshal round: %s", err)
		return nil
	}

	var events []domain.Event
	for _, raw := range temp.Changes {
		var probe map[string]interface{}
		if err := json.Unmarshal(raw, &probe); err != nil {
			log.Warnf("failed to unmarshal event: %s", err)
			return nil
		}

		var evt domain.Event
		rawType, ok := probe["Type"]
		if !ok {
			log.Warnf("failed to unmarshal event: missing type")
			return nil
		}
		var eventType domain.EventType
		switch v := rawType.(type) {
		case float64:
			eventType = domain.EventType(int(v))
		case string:
			atoi, err := strconv.Atoi(v)
			if err != nil {
				log.Warnf("failed to unmarshal event: %s", err)
				return nil
			}
			eventType = domain.EventType(atoi)
		default:
			log.Warnf("failed to unmarshal event: unknown type")
			return nil
		}
		switch eventType {
		case domain.EventTypeRoundStarted:
			var e domain.RoundStarted
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeRoundFinalizationStarted:
			var e domain.RoundFinalizationStarted
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeRoundFinalized:
			var e domain.RoundFinalized
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeRoundFailed:
			var e domain.RoundFailed
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeIntentsRegistered:
			var e domain.IntentsRegistered
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		default:
			continue
		}
		events = append(events, evt)
	}

	round := domain.Round(temp.roundAlias)
	round.Changes = events

	return &round
}

func (s *currentRoundStore) Fail(err error) []domain.Event {
	var events []domain.Event
	if err := s.Upsert(func(m *domain.Round) *domain.Round {
		m.Fail(err)
		return m
	}); err != nil {
		log.Warnf("fail: failed to upsert round: %s", err)
		return nil
	}

	round := s.Get()
	if round == nil {
		return nil
	}
	events = append(events, round.Events()...)

	return events
}

func NewBoardingInputsStore(rdb *redis.Client) ports.BoardingInputsStore {
	return &boardingInputsStore{rdb: rdb}
}

func (b *boardingInputsStore) Set(numOfInputs int) {
	ctx := context.Background()
	b.rdb.Set(ctx, boardingInputsKey, numOfInputs, 0)
}

func (b *boardingInputsStore) Get() int {
	ctx := context.Background()
	num, err := b.rdb.Get(ctx, boardingInputsKey).Int()
	if err != nil {
		return 0
	}
	return num
}
