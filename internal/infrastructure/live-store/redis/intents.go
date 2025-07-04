package redislivestore

import (
	"context"
	"fmt"
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
)

type intentStore struct {
	rdb     *redis.Client
	intents *KVStore[ports.TimedIntent]

	numOfRetries int
}

func NewIntentStore(rdb *redis.Client, numOfRetries int) ports.IntentStore {
	return &intentStore{
		rdb:          rdb,
		intents:      NewRedisKVStore[ports.TimedIntent](rdb, "intent:"),
		numOfRetries: numOfRetries,
	}
}

func (s *intentStore) Len() int64 {
	ctx := context.Background()
	ids, err := s.rdb.SMembers(ctx, intentStoreIdsKey).Result()
	if err != nil {
		return 0
	}

	intents, err := s.intents.GetMulti(ctx, ids)
	if err != nil {
		return 0
	}

	count := int64(0)
	for _, tx := range intents {
		if tx != nil && len(tx.Receivers) > 0 {
			count++
		}
	}

	return count
}

func (s *intentStore) Push(
	intent domain.Intent, boardingInputs []ports.BoardingInput, cosignerPubkeys []string,
) error {
	ctx := context.Background()
	var err error
	for attempt := 0; attempt < s.numOfRetries; attempt++ {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			exists, err := tx.SIsMember(ctx, intentStoreIdsKey, intent.Id).Result()
			if err != nil {
				return err
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
				exists, err := tx.SIsMember(ctx, intentStoreVtxosKey, key).Result()
				if err != nil {
					return err
				}
				if exists {
					return fmt.Errorf(
						"duplicated input, %s already registered by another intent", key,
					)
				}
			}

			// Check boarding inputs similarly if you store them

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

				return nil
			})

			return err
		}, intentStoreVtxosKey, intentStoreIdsKey) // WATCH both keys
		if err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

func (s *intentStore) Pop(num int64) []ports.TimedIntent {
	ctx := context.Background()
	ids, err := s.rdb.SMembers(ctx, intentStoreIdsKey).Result()
	if err != nil {
		return nil
	}

	var intentsByTime []ports.TimedIntent
	for _, id := range ids {
		intent, err := s.intents.Get(ctx, id)
		if err != nil || intent == nil {
			log.Debugf("pop: intent %s not found", id)
			continue
		}

		if len(intent.Receivers) > 0 {
			intentsByTime = append(intentsByTime, *intent)
		}
	}

	sort.SliceStable(intentsByTime, func(i, j int) bool {
		return intentsByTime[i].Timestamp.Before(intentsByTime[j].Timestamp)
	})
	if num < 0 || num > int64(len(intentsByTime)) {
		num = int64(len(intentsByTime))
	}

	result := make([]ports.TimedIntent, 0, num)
	var vtxosToRemove []string
	for _, intent := range intentsByTime[:num] {
		result = append(result, intent)
		for _, vtxo := range intent.Inputs {
			vtxosToRemove = append(vtxosToRemove, vtxo.Outpoint.String())
		}

		if err := s.intents.Delete(ctx, intent.Id); err != nil {
			log.Warnf("pop:failed to delete intent %s: %v", intent.Id, err)
		}

		s.rdb.SRem(ctx, intentStoreIdsKey, intent.Id)
	}

	if len(vtxosToRemove) > 0 {
		s.rdb.SAdd(ctx, intentStoreVtxosToRemoveKey, vtxosToRemove)
	}
	return result
}

func (s *intentStore) View(id string) (*domain.Intent, bool) {
	ctx := context.Background()
	intent, err := s.intents.Get(ctx, id)
	if err != nil || intent == nil {
		log.Debugf("view: intent %s not found", id)
		return nil, false
	}

	return &intent.Intent, true
}

func (s *intentStore) ViewAll(ids []string) ([]ports.TimedIntent, error) {
	ctx := context.Background()
	var result []ports.TimedIntent
	if len(ids) > 0 {
		intents, err := s.intents.GetMulti(ctx, ids)
		if err != nil {
			return nil, err
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
		return nil, err
	}

	txs, err := s.intents.GetMulti(ctx, allIDs)
	if err != nil {
		return nil, err
	}

	for _, t := range txs {
		if t != nil {
			result = append(result, *t)
		}
	}

	return result, nil
}

func (s *intentStore) Update(intent domain.Intent, cosignerPubkeys []string) error {
	ctx := context.Background()
	gotIntent, err := s.intents.Get(ctx, intent.Id)
	if err != nil || gotIntent == nil {
		return err
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

	return s.intents.Set(ctx, intent.Id, gotIntent)
}

func (s *intentStore) Delete(ids []string) error {
	ctx := context.Background()
	for _, id := range ids {
		intent, err := s.intents.Get(ctx, id)
		if err != nil || intent == nil {
			log.Debugf("delete: intent %s not found", id)
			continue
		}

		for _, vtxo := range intent.Inputs {
			s.rdb.SRem(ctx, intentStoreVtxosKey, vtxo.Outpoint.String())
		}

		if err := s.intents.Delete(ctx, id); err != nil {
			log.Warnf("delete:failed to delete intent %s: %v", id, err)
		}

		s.rdb.SRem(ctx, intentStoreIdsKey, id)
	}
	return nil
}

func (s *intentStore) DeleteAll() error {
	ctx := context.Background()
	ids, err := s.rdb.SMembers(ctx, intentStoreIdsKey).Result()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.intents.Delete(ctx, id); err != nil {
			log.Warnf("delete:failed to delete intent %s: %v", id, err)
		}
	}
	s.rdb.Del(ctx, intentStoreIdsKey)
	s.rdb.Del(ctx, intentStoreVtxosKey)
	s.rdb.Del(ctx, intentStoreVtxosToRemoveKey)
	return nil
}

func (s *intentStore) DeleteVtxos() {
	ctx := context.Background()
	vtxosToRemove, err := s.rdb.SMembers(ctx, intentStoreVtxosToRemoveKey).Result()
	if err != nil {
		return
	}

	if len(vtxosToRemove) > 0 {
		s.rdb.SRem(ctx, intentStoreVtxosKey, vtxosToRemove)
	}

	s.rdb.Del(ctx, intentStoreVtxosToRemoveKey)
}

func (s *intentStore) IncludesAny(outpoints []domain.Outpoint) (bool, string) {
	ctx := context.Background()
	for _, out := range outpoints {
		exists, err := s.rdb.SIsMember(ctx, intentStoreVtxosKey, out.String()).Result()
		if err == nil && exists {
			return true, out.String()
		} else if err != nil {
			log.Warnf("includesAny:failed to check vtxo %s: %v", out.String(), err)
		}
	}
	return false, ""
}
