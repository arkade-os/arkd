package redislivestore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

const utxoStoreOutpointsKey = "utxoStore:outpoints"

type utxoStore struct {
	rdb          *redis.Client
	numOfRetries int
	retryDelay   time.Duration
}

func NewUtxoStore(rdb *redis.Client, numOfRetries int) ports.CosignedUtxosStore {
	return &utxoStore{
		rdb:          rdb,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

// AddUtxos reserves the outpoints as a whole. The set is watched so the existence check and
// the insert are atomic: if any outpoint is already reserved none is added and
// ports.ErrUtxosAlreadyExist is returned.
func (s *utxoStore) AddUtxos(ctx context.Context, outpoints []domain.Outpoint) error {
	if len(outpoints) == 0 {
		return nil
	}
	members := outpointsToMembers(outpoints)

	var err error
	for range s.numOfRetries {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			exists, err := tx.SMIsMember(ctx, utxoStoreOutpointsKey, members...).Result()
			if err != nil {
				return fmt.Errorf("failed to check existence of %d utxos: %v", len(members), err)
			}
			for _, exist := range exists {
				if exist {
					return ports.ErrUtxosAlreadyExist
				}
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.SAdd(ctx, utxoStoreOutpointsKey, members...)
				return nil
			})
			return err
		}, utxoStoreOutpointsKey)
		if err == nil {
			return nil
		}
		// Another client changed the set between the check and the insert, check again.
		if errors.Is(err, redis.TxFailedErr) {
			time.Sleep(s.retryDelay)
			continue
		}
		return err
	}
	return fmt.Errorf("failed to add %d utxos after max number of retries: %v", len(members), err)
}

func (s *utxoStore) RemoveUtxos(ctx context.Context, outpoints []domain.Outpoint) error {
	if len(outpoints) == 0 {
		return nil
	}
	if err := s.rdb.SRem(
		ctx, utxoStoreOutpointsKey, outpointsToMembers(outpoints)...,
	).Err(); err != nil {
		return fmt.Errorf("failed to remove %d utxos: %v", len(outpoints), err)
	}
	return nil
}

func (s *utxoStore) IncludesAny(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	if len(outpoints) == 0 {
		return nil, nil
	}

	exists, err := s.rdb.SMIsMember(
		ctx, utxoStoreOutpointsKey, outpointsToMembers(outpoints)...,
	).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check existence of %d utxos: %v", len(outpoints), err)
	}
	if len(exists) != len(outpoints) {
		return nil, fmt.Errorf(
			"checked %d utxos but got %d answers", len(outpoints), len(exists),
		)
	}

	var included []domain.Outpoint
	for i, outpoint := range outpoints {
		if exists[i] {
			included = append(included, outpoint)
		}
	}
	return included, nil
}

func outpointsToMembers(outpoints []domain.Outpoint) []interface{} {
	members := make([]interface{}, 0, len(outpoints))
	for _, outpoint := range outpoints {
		members = append(members, outpoint.String())
	}
	return members
}
