package redislivestore

import (
	"context"
	"encoding/json"
	"strings"

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
	rdb *redis.Client
}

func NewOffChainTxStore(rdb *redis.Client) ports.OffChainTxStore {
	return &offChainTxStore{rdb: rdb}
}

func (s *offChainTxStore) Add(offchainTx domain.OffchainTx) {
	ctx := context.Background()
	inputs := make([]string, 0)
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			inputs = append(inputs, in.PreviousOutPoint.String())
		}
	}
	val, _ := json.Marshal(offchainTx)
	_, _ = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, offChainTxsHashKey, offchainTx.ArkTxid, val)
		if len(inputs) > 0 {
			pipe.SAdd(ctx, offChainInputsSetKey, inputs)
		}
		return nil
	})
}

func (s *offChainTxStore) Remove(arkTxid string) {
	ctx := context.Background()
	txStr, err := s.rdb.HGet(ctx, offChainTxsHashKey, arkTxid).Result()
	if err != nil {
		return
	}
	var offchainTx domain.OffchainTx
	if err := json.Unmarshal([]byte(txStr), &offchainTx); err != nil {
		return
	}
	inputs := make([]string, 0)
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			inputs = append(inputs, in.PreviousOutPoint.String())
		}
	}
	_, _ = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HDel(ctx, offChainTxsHashKey, arkTxid)
		if len(inputs) > 0 {
			pipe.SRem(ctx, offChainInputsSetKey, inputs)
		}
		return nil
	})
}

func (s *offChainTxStore) Get(arkTxid string) (domain.OffchainTx, bool) {
	ctx := context.Background()
	txStr, err := s.rdb.HGet(ctx, offChainTxsHashKey, arkTxid).Result()
	if err != nil {
		return domain.OffchainTx{}, false
	}
	var offchainTx domain.OffchainTx
	if err := json.Unmarshal([]byte(txStr), &offchainTx); err != nil {
		return domain.OffchainTx{}, false
	}
	return offchainTx, true
}

func (s *offChainTxStore) Includes(outpoint domain.Outpoint) bool {
	ctx := context.Background()
	exists, _ := s.rdb.SIsMember(ctx, offChainInputsSetKey, outpoint.String()).Result()
	return exists
}
