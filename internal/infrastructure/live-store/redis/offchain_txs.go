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
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/redis/go-redis/v9"
)

const (
	offChainTxsHashKey   = "offChainTxStore:txs"
	offChainInputsSetKey = "offChainTxStore:inputs"
)

type offChainTxStore struct {
	rdb          *redis.Client
	numOfRetries int
	retryDelay   time.Duration
}

func NewOffChainTxStore(rdb *redis.Client, numOfRetries int) ports.OffChainTxStore {
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

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, offChainTxsHashKey, offchainTx.ArkTxid, val)
				if len(inputs) > 0 {
					pipe.SAdd(ctx, offChainInputsSetKey, inputs)
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

func (s *offChainTxStore) Includes(ctx context.Context, outpoint domain.Outpoint) (bool, error) {
	exists, err := s.rdb.SIsMember(ctx, offChainInputsSetKey, outpoint.String()).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence of input %s: %v", outpoint, err)
	}
	return exists, nil
}

func (s *offChainTxStore) GetTxidByOutpoint(ctx context.Context, outpoint domain.Outpoint) (string, error) {
	exists, err := s.rdb.SIsMember(ctx, offChainInputsSetKey, outpoint.String()).Result()
	if err != nil {
		return "", fmt.Errorf("failed to check existence of input %s: %v", outpoint, err)
	}
	if !exists {
		return "", nil
	}
	txsMap, err := s.rdb.HGetAll(ctx, offChainTxsHashKey).Result()
	if err != nil {
		return "", fmt.Errorf("failed to get offchain txs: %v", err)
	}

	outpointStr := outpoint.String()
	for txid, txStr := range txsMap {
		var offchainTx domain.OffchainTx
		if err := json.Unmarshal([]byte(txStr), &offchainTx); err != nil {
			continue
		}
		for _, tx := range offchainTx.CheckpointTxs {
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
			if err != nil {
				continue
			}
			for _, in := range ptx.UnsignedTx.TxIn {
				if in.PreviousOutPoint.String() == outpointStr {
					return txid, nil
				}
			}
		}
	}
	return "", nil
}
