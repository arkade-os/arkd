package redislivestore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	intentStoreIdsKey           = "intent:ids"
	intentStoreVtxosKey         = "intent:vtxos"
	intentStoreVtxosToRemoveKey = "intent:vtxosToRemove"
	selectedIntentsKey          = "intent:selected"
)

type intentStore struct {
	rdb          *redis.Client
	intents      *KVStore[ports.TimedIntent]
	numOfRetries int
	retryDelay   time.Duration
}

func NewIntentStore(rdb *redis.Client, numOfRetries int) ports.IntentStore {
	return &intentStore{
		rdb:          rdb,
		intents:      NewRedisKVStore[ports.TimedIntent](rdb, "intent:"),
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

func (s *intentStore) Len(ctx context.Context) (int64, error) {
	ids, err := s.rdb.SMembers(ctx, intentStoreIdsKey).Result()
	if err != nil {
		return -1, fmt.Errorf("failed to get intent ids: %v", err)
	}

	intents, err := s.intents.GetMulti(ctx, ids)
	if err != nil {
		return -1, fmt.Errorf("failed to get intents: %v", err)
	}

	count := int64(0)
	for _, tx := range intents {
		if tx != nil && len(tx.Receivers) > 0 {
			count++
		}
	}
	return count, nil
}

func (s *intentStore) Push(
	ctx context.Context, intent domain.Intent,
	boardingInputs []ports.BoardingInput, cosignerPubkeys []string,
) error {
	var err error
	for range s.numOfRetries {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			exists, err := s.rdb.SIsMember(ctx, intentStoreIdsKey, intent.Id).Result()
			if err != nil {
				return fmt.Errorf("failed to check existence of intent: %v", err)
			}
			if exists {
				return fmt.Errorf("duplicated intent %s", intent.Id)
			}
			// Check input duplicates directly in Redis set
			for _, input := range intent.Inputs {
				if input.IsNote() {
					continue
				}
				key := input.Outpoint.String()
				exists, err := s.rdb.SIsMember(ctx, intentStoreVtxosKey, key).Result()
				if err != nil {
					return fmt.Errorf(
						"failed to check existence of intent input %s: %v", input.Outpoint, err,
					)
				}
				if exists {
					return fmt.Errorf(
						"duplicated input, %s already registered by another intent", key,
					)
				}
			}

			for _, boardingInput := range boardingInputs {
				key := boardingInput.String()
				exists, err := s.rdb.SIsMember(ctx, intentStoreVtxosKey, key).Result()
				if err != nil {
					return fmt.Errorf(
						"failed to check existence of boarding input %s: %v", key, err,
					)
				}
				if exists {
					return fmt.Errorf(
						"duplicated input, %s already registered by another intent", key,
					)
				}
			}

			now := time.Now()
			timedIntent := &ports.TimedIntent{
				Intent:              intent,
				BoardingInputs:      boardingInputs,
				Timestamp:           now,
				CosignersPublicKeys: cosignerPubkeys,
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				if err := s.intents.SetPipe(ctx, pipe, intent.Id, timedIntent); err != nil {
					return err
				}

				pipe.SAdd(ctx, intentStoreIdsKey, intent.Id)
				for _, vtxo := range intent.Inputs {
					if vtxo.IsNote() {
						continue
					}
					pipe.SAdd(ctx, intentStoreVtxosKey, vtxo.Outpoint.String())
				}
				for _, boardingInput := range boardingInputs {
					pipe.SAdd(ctx, intentStoreVtxosKey, boardingInput.String())
				}

				return nil
			})

			return err
		}, intentStoreVtxosKey, intentStoreIdsKey) // WATCH dedup keys
		if err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to push intent after max number of retries: %v", err)
}

func (s *intentStore) Pop(ctx context.Context, num int64) ([]ports.TimedIntent, error) {
	watchKeys := []string{
		intentStoreIdsKey,
		intentStoreVtxosToRemoveKey,
		selectedIntentsKey,
	}

	var result []ports.TimedIntent
	var err error
	for range s.numOfRetries {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			// list all ids
			ids, err := tx.SMembers(ctx, intentStoreIdsKey).Result()
			if err != nil {
				return fmt.Errorf("failed to get intent ids: %v", err)
			}

			// fetch intents
			var intentsByTime []ports.TimedIntent
			for _, id := range ids {
				intent, err := s.intents.GetWith(ctx, tx, id)
				if err != nil {
					return fmt.Errorf("failed to get intent %s: %v", id, err)
				}
				if intent == nil {
					log.Warnf("got nil intent for id %s", id)
					continue
				}
				if len(intent.Receivers) > 0 {
					intentsByTime = append(intentsByTime, *intent)
				}
			}

			// sort by time
			sort.SliceStable(intentsByTime, func(i, j int) bool {
				return intentsByTime[i].Timestamp.Before(intentsByTime[j].Timestamp)
			})
			n := num
			if n < 0 || n > int64(len(intentsByTime)) {
				n = int64(len(intentsByTime))
			}
			selected := intentsByTime[:n]

			// list outpoints to remove
			var inputsToRemove []interface{}
			for _, intent := range selected {
				for _, vtxo := range intent.Inputs {
					inputsToRemove = append(inputsToRemove, vtxo.Outpoint.String())
				}
				for _, boardingInput := range intent.BoardingInputs {
					inputsToRemove = append(inputsToRemove, boardingInput.String())
				}
			}

			// delete intent, intent id and add outpoints to "vtxosToRemove" in the same transaction
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, selectedIntentsKey)
				for i := range selected {
					intent := selected[i]
					s.intents.DeletePipe(ctx, pipe, intent.Id)
					pipe.SRem(ctx, intentStoreIdsKey, intent.Id)
					if err := s.intents.ListPushPipe(
						ctx, pipe, selectedIntentsKey, &intent,
					); err != nil {
						return err
					}
				}

				if len(inputsToRemove) > 0 {
					pipe.SAdd(ctx, intentStoreVtxosToRemoveKey, inputsToRemove...)
				}
				return nil
			})
			if err != nil {
				return err
			}
			// safe copy to result
			result = slices.Clone(selected)
			return nil
		}, watchKeys...)
		if err == nil {
			return result, nil
		}
		// only retry on transient WATCH conflicts; propagate any other error.
		if !errors.Is(err, redis.TxFailedErr) {
			return nil, fmt.Errorf("failed to pop intents: %v", err)
		}
		time.Sleep(s.retryDelay)
	}
	return nil, fmt.Errorf("failed to pop intents after max number of retries: %v", err)
}

func (s *intentStore) GetSelectedIntents(ctx context.Context) ([]ports.TimedIntent, error) {
	result, err := s.intents.ListRange(ctx, selectedIntentsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get selected intents: %v", err)
	}
	return result, nil
}

func (s *intentStore) ViewAll(ctx context.Context, ids []string) ([]ports.TimedIntent, error) {
	var result []ports.TimedIntent
	if len(ids) > 0 {
		intents, err := s.intents.GetMulti(ctx, ids)
		if err != nil {
			return nil, fmt.Errorf("failed to get requested intents: %v", err)
		}
		for _, t := range intents {
			if t != nil {
				result = append(result, *t)
			}
		}
		return result, nil
	}

	allIDs, err := s.rdb.SMembers(ctx, intentStoreIdsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get all intent ids: %v", err)
	}

	txs, err := s.intents.GetMulti(ctx, allIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get all intents: %v", err)
	}

	for _, t := range txs {
		if t != nil {
			result = append(result, *t)
		}
	}
	return result, nil
}

func (s *intentStore) Update(
	ctx context.Context, intent domain.Intent, cosignerPubkeys []string,
) error {
	gotIntent, err := s.intents.Get(ctx, intent.Id)
	if err != nil {
		return fmt.Errorf("failed to get intent %s: %v", intent.Id, err)
	}
	if gotIntent == nil {
		return fmt.Errorf("intent %s not found", intent.Id)
	}

	// Sum of inputs = vtxos + boarding utxos + notes + recovered vtxos
	sumOfInputs := uint64(0)
	for _, input := range intent.Inputs {
		sumOfInputs += input.Amount
	}
	for _, boardingInput := range gotIntent.BoardingInputs {
		sumOfInputs += boardingInput.Amount
	}

	// Sum of outputs = receivers VTXOs
	sumOfOutputs := uint64(0)
	for _, receiver := range intent.Receivers {
		sumOfOutputs += receiver.Amount
	}

	if sumOfInputs != sumOfOutputs {
		return fmt.Errorf(
			"sum of inputs %d does not match sum of outputs %d", sumOfInputs, sumOfOutputs,
		)
	}

	gotIntent.Intent = intent
	if len(cosignerPubkeys) > 0 {
		gotIntent.CosignersPublicKeys = cosignerPubkeys
	}

	if err := s.intents.Set(ctx, intent.Id, gotIntent); err != nil {
		return fmt.Errorf("failed to update intent %s: %v", intent.Id, err)
	}
	return nil
}

func (s *intentStore) Delete(ctx context.Context, ids []string) error {
	watchKeys := []string{intentStoreIdsKey, intentStoreVtxosKey}
	for _, id := range ids {
		var err error
		for range s.numOfRetries {
			err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
				// get intent by id
				intent, err := s.intents.GetWith(ctx, tx, id)
				if err != nil {
					return fmt.Errorf("failed to get intent %s: %v", id, err)
				}
				if intent == nil {
					// ignore nil intent as defensive check to avoid dereference panic
					return nil
				}
				// delete intent id + outpoints in the same tx pipeline
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					for _, vtxo := range intent.Inputs {
						pipe.SRem(ctx, intentStoreVtxosKey, vtxo.Outpoint.String())
					}
					for _, boardingInput := range intent.BoardingInputs {
						pipe.SRem(ctx, intentStoreVtxosKey, boardingInput.String())
					}
					s.intents.DeletePipe(ctx, pipe, id)
					pipe.SRem(ctx, intentStoreIdsKey, id)
					return nil
				})
				return err
			}, watchKeys...)
			if err == nil {
				break
			}
			// only retry on transient WATCH conflicts; stop on terminal errors.
			if !errors.Is(err, redis.TxFailedErr) {
				break
			}
			time.Sleep(s.retryDelay)
		}
		if err != nil {
			return fmt.Errorf("failed to delete intent %s: %v", id, err)
		}
	}
	return nil
}

func (s *intentStore) DeleteAll(ctx context.Context) error {
	ids, err := s.rdb.SMembers(ctx, intentStoreIdsKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get all intent ids: %v", err)
	}
	for _, id := range ids {
		if err := s.intents.Delete(ctx, id); err != nil {
			log.Warnf("delete:failed to delete intent %s: %v", id, err)
		}
	}

	keys := []string{
		intentStoreIdsKey, intentStoreVtxosKey, intentStoreVtxosToRemoveKey, selectedIntentsKey,
	}
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, keys...)
				return nil
			})
			return err
		}, keys...); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to delete all intents after max number of retries: %v", err)
}

func (s *intentStore) DeleteVtxos(ctx context.Context) error {
	inputsToRemove, err := s.rdb.SMembers(ctx, intentStoreVtxosToRemoveKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get inputs to remove: %v", err)
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				if len(inputsToRemove) > 0 {
					members := make([]interface{}, len(inputsToRemove))
					for i, v := range inputsToRemove {
						members[i] = v
					}
					pipe.SRem(ctx, intentStoreVtxosKey, members...)
				}
				pipe.Del(ctx, intentStoreVtxosToRemoveKey)
				return nil
			})
			return err
		}, intentStoreVtxosKey, intentStoreVtxosToRemoveKey); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to delete vtxos after max number of retries: %v", err)
}

func (s *intentStore) IncludesAny(ctx context.Context, outpoints []domain.Outpoint) (bool, string) {
	for _, out := range outpoints {
		exists, err := s.rdb.SIsMember(ctx, intentStoreVtxosKey, out.String()).Result()
		if err == nil && exists {
			return true, out.String()
		} else if err != nil {
			log.Warnf("includesAny: failed to check vtxo %s: %v", out.String(), err)
		}
	}
	return false, ""
}
