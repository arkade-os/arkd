package redislivestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

const (
	currentRoundKey      = "currentRoundStore:round"
	boardingInputsKey    = "boardingInputsStore:numOfInputs"
	boardingInputSigsKey = "boardingInputsStore:signatures"
)

type currentRoundStore struct {
	rdb          *redis.Client
	numOfRetries int
	retryDelay   time.Duration
}

func NewCurrentRoundStore(rdb *redis.Client, numOfRetries int) ports.CurrentRoundStore {
	return &currentRoundStore{
		rdb:          rdb,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

func (s *currentRoundStore) Upsert(
	ctx context.Context, fn func(m *domain.Round) *domain.Round,
) error {
	round, err := s.Get(ctx)
	if err != nil {
		return err
	}
	if round == nil {
		round = &domain.Round{}
	}
	updated := fn(round)
	val, err := json.Marshal(updated)
	if err != nil {
		return err
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, currentRoundKey, val, 0)
				return nil
			})

			return err
		}); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to update round after max number of retries: %v", err)
}

func (s *currentRoundStore) Get(ctx context.Context) (*domain.Round, error) {
	data, err := s.rdb.Get(ctx, currentRoundKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get current round: %v", err)
	}

	type roundAlias domain.Round
	var temp struct {
		roundAlias
		Changes []json.RawMessage `json:"Changes"` // use the exported field name
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, fmt.Errorf("malformed round in storage (out=%s): %s", string(data), err)
	}

	var events []domain.Event
	for _, raw := range temp.Changes {
		var probe map[string]interface{}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf(
				"malformed round event in storage (out=%s): %s",
				string(raw),
				err,
			)
		}

		var evt domain.Event
		rawType, ok := probe["Type"]
		if !ok {
			return nil, fmt.Errorf("malformed round event in storage: missing type")
		}
		var eventType domain.EventType
		switch v := rawType.(type) {
		case float64:
			eventType = domain.EventType(int(v))
		case string:
			atoi, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf(
					"malformed round event in storage - failed to parse type (value=%s): %s",
					v, err,
				)
			}
			eventType = domain.EventType(atoi)
		default:
			return nil, fmt.Errorf("malformed round event in storage: unknown type %T", v)
		}

		switch eventType {
		case domain.EventTypeRoundStarted:
			var e domain.RoundStarted
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf(
					"failed to unmarshal round started event (event=%s): %s", string(raw), err,
				)
			}
			evt = e
		case domain.EventTypeRoundFinalizationStarted:
			var e domain.RoundFinalizationStarted
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf(
					"failed to unmarshal round finalization started event (event=%s): %s",
					string(raw), err,
				)
			}
			evt = e
		case domain.EventTypeRoundFinalized:
			var e domain.RoundFinalized
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf(
					"failed to unmarshal round finalized event (event=%s): %s", string(raw), err,
				)
			}
			evt = e
		case domain.EventTypeRoundFailed:
			var e domain.RoundFailed
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf(
					"failed to unmarshal round failed event (event=%s): %s", string(raw), err,
				)
			}
			evt = e
		case domain.EventTypeIntentsRegistered:
			var e domain.IntentsRegistered
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf(
					"failed to unmarshal round intents registered event (event=%s): %s",
					string(raw), err,
				)
			}
			evt = e
		default:
			continue
		}
		events = append(events, evt)
	}

	round := domain.Round(temp.roundAlias)
	round.Changes = events

	return &round, nil
}
