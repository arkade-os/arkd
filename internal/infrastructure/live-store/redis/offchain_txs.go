package redislivestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/redis/go-redis/v9"
)

const (
	offChainTxsHashKey          = "offChainTxStore:txs"
	offChainInputsSetKey        = "offChainTxStore:inputs"
	offChainFinalizationLockKey = "offChainTxStore:finalization:"
)

type offChainTxStore struct {
	rdb          *redis.Client
	numOfRetries int
	retryDelay   time.Duration
}

func NewOffChainTxStore(
	rdb *redis.Client, numOfRetries int,
) ports.OffChainTxStore {
	return &offChainTxStore{
		rdb:          rdb,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

func (s *offChainTxStore) Add(ctx context.Context, offchainTx domain.OffchainTx) error {
	inputs := make([]string, 0)
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			inputs = append(inputs, in.PreviousOutPoint.String())
		}
	}
	val, err := json.Marshal(offchainTx)
	if err != nil {
		return fmt.Errorf("failed to marshal offchain tx %s: %v", offchainTx.ArkTxid, err)
	}

	members := make([]interface{}, len(inputs))
	for i, in := range inputs {
		members[i] = in
	}

	for range s.numOfRetries {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			// Reserve each input for a single in-flight tx: abort if any is already held. The
			// WATCH on the inputs set makes the check-and-add atomic: a concurrent Add that
			// reserves a shared input first invalidates this transaction, so the retry re-reads
			// and sees the input taken.
			if len(members) > 0 {
				included, err := tx.SMIsMember(ctx, offChainInputsSetKey, members...).Result()
				if err != nil {
					return err
				}
				for i, isIncluded := range included {
					if isIncluded {
						return fmt.Errorf(
							"input %s %w", inputs[i], ports.ErrOffchainTxInputAlreadySpent,
						)
					}
				}
			}

			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, offChainTxsHashKey, offchainTx.ArkTxid, val)
				if len(inputs) > 0 {
					pipe.SAdd(ctx, offChainInputsSetKey, inputs)
				}
				return nil
			})
			return err
		}, offChainTxsHashKey, offChainInputsSetKey)
		if err == nil {
			return nil
		}
		// A reserved input is a terminal conflict, not a transient WATCH failure: don't retry.
		if errors.Is(err, ports.ErrOffchainTxInputAlreadySpent) {
			return err
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf(
		"failed to add offchain tx %s after max number of retries: %v", offchainTx.ArkTxid, err,
	)
}

func (s *offChainTxStore) Remove(ctx context.Context, arkTxid string) error {
	txStr, err := s.rdb.HGet(ctx, offChainTxsHashKey, arkTxid).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("failed to get offchain tx %s: %v", arkTxid, err)
	}
	var offchainTx domain.OffchainTx
	if err := json.Unmarshal([]byte(txStr), &offchainTx); err != nil {
		return fmt.Errorf("malformed offchain tx in storage %s: %v", arkTxid, err)
	}
	inputs := make([]string, 0)
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			return fmt.Errorf(
				"malformed offchain checkpoint tx in storage %s (tx=%s): %v", arkTxid, tx, err,
			)
		}
		for _, in := range ptx.UnsignedTx.TxIn {
			inputs = append(inputs, in.PreviousOutPoint.String())
		}
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HDel(ctx, offChainTxsHashKey, arkTxid)
				if len(inputs) > 0 {
					pipe.SRem(ctx, offChainInputsSetKey, inputs)
				}
				return nil
			})
			return err
		}, offChainTxsHashKey, offChainInputsSetKey); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf(
		"failed to remove offchain tx %s after max number of retries: %v", arkTxid, err,
	)
}

func (s *offChainTxStore) Get(ctx context.Context, arkTxid string) (*domain.OffchainTx, error) {
	txStr, err := s.rdb.HGet(ctx, offChainTxsHashKey, arkTxid).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get offchain tx %s: %v", arkTxid, err)
	}
	var offchainTx domain.OffchainTx
	if err := json.Unmarshal([]byte(txStr), &offchainTx); err != nil {
		return nil, fmt.Errorf(
			"malformed offchain tx %s in storage (out=%s): %v", arkTxid, txStr, err,
		)
	}
	return &offchainTx, nil
}

func (s *offChainTxStore) IncludesAny(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	if len(outpoints) == 0 {
		return nil, nil
	}

	members := make([]interface{}, 0, len(outpoints))
	for _, outpoint := range outpoints {
		members = append(members, outpoint.String())
	}

	exists, err := s.rdb.SMIsMember(ctx, offChainInputsSetKey, members...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check existence of %d inputs: %v", len(outpoints), err)
	}
	if len(exists) != len(outpoints) {
		return nil, fmt.Errorf(
			"checked %d inputs but got %d answers", len(outpoints), len(exists),
		)
	}

	var included []domain.Outpoint
	for i, outpoint := range outpoints {
		if exists[i] {
			included = append(included, outpoint)
		}
	}
	if len(included) == 0 {
		return nil, nil
	}
	return included, nil
}

func (s *offChainTxStore) LockFinalization(
	ctx context.Context, arkTxid string, ttl time.Duration,
) error {
	if ttl <= 0 {
		return fmt.Errorf("finalization lock TTL must be positive")
	}
	key := offChainFinalizationLockKey + arkTxid
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("failed to lock finalization for offchain tx %s: %w", arkTxid, err)
		}
		// Expire abandoned locks so a crash cannot block finalization indefinitely.
		locked, err := s.rdb.SetNX(ctx, key, true, ttl).Result()
		if err != nil {
			return fmt.Errorf("failed to lock finalization for offchain tx %s: %w", arkTxid, err)
		}
		if locked {
			return nil
		}
		select {
		case <-ctx.Done():
			continue
		case <-time.After(s.retryDelay):
		}
	}
}

func (s *offChainTxStore) UnlockFinalization(ctx context.Context, arkTxid string) error {
	if err := s.rdb.Del(ctx, offChainFinalizationLockKey+arkTxid).Err(); err != nil {
		return fmt.Errorf("failed to unlock finalization for offchain tx %s: %w", arkTxid, err)
	}
	return nil
}
