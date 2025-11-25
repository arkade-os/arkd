package redislivestore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/redis/go-redis/v9"
)

type forfeitTxsStore struct {
	rdb          *redis.Client
	builder      ports.TxBuilder
	numOfRetries int
	retryDelay   time.Duration
}

const (
	forfeitTxsStoreTxsKey     = "forfeitTxsStore:txs"
	forfeitTxsStoreConnsKey   = "forfeitTxsStore:connectors"
	forfeitTxsStoreVtxosKey   = "forfeitTxsStore:vtxos"
	forfeitTxsStoreConnIdxKey = "forfeitTxsStore:connidx"
)

func NewForfeitTxsStore(
	rdb *redis.Client, builder ports.TxBuilder, numOfRetries int,
) ports.ForfeitTxsStore {
	return &forfeitTxsStore{
		rdb:          rdb,
		builder:      builder,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

func (s *forfeitTxsStore) Init(
	ctx context.Context, connectors tree.FlatTxTree, intents []domain.Intent,
) error {
	connBytes, err := json.Marshal(connectors)
	if err != nil {
		return fmt.Errorf("failed to marshal connectors: %v", err)
	}

	vtxosToSign := make([]domain.Vtxo, 0)
	for _, intent := range intents {
		for _, vtxo := range intent.Inputs {
			if !vtxo.RequiresForfeit() {
				continue
			}
			vtxosToSign = append(vtxosToSign, vtxo)
		}
	}
	vtxosBytes, err := json.Marshal(vtxosToSign)
	if err != nil {
		return fmt.Errorf("failed to marshal vtxos to sign: %v", err)
	}

	forfeitTxs := make(map[string]string)
	for _, vtxo := range vtxosToSign {
		forfeitTxs[vtxo.Outpoint.String()] = ""
	}

	connIndex := make(map[string]domain.Outpoint)
	if len(vtxosToSign) > 0 {
		connectorsOutpoints := make([]domain.Outpoint, 0)
		leaves := tree.FlatTxTree(connectors).Leaves()
		if len(leaves) == 0 {
			return fmt.Errorf("no connectors found")
		}
		for _, leaf := range leaves {
			connectorsOutpoints = append(
				connectorsOutpoints, domain.Outpoint{Txid: leaf.Txid, VOut: 0},
			)
		}
		if len(vtxosToSign) > len(connectorsOutpoints) {
			return fmt.Errorf(
				"more vtxos to sign than outpoints, %d > %d",
				len(vtxosToSign), len(connectorsOutpoints),
			)
		}
		for i, connectorOutpoint := range connectorsOutpoints {
			connIndex[connectorOutpoint.String()] = vtxosToSign[i].Outpoint
		}
	}
	idxBytes, err := json.Marshal(connIndex)
	if err != nil {
		return fmt.Errorf("failed to marshal connector index: %v", err)
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				for vtxoKey, forfeit := range forfeitTxs {
					pipe.HSet(ctx, forfeitTxsStoreTxsKey, vtxoKey, forfeit)
				}
				pipe.Set(ctx, forfeitTxsStoreConnsKey, connBytes, 0)
				pipe.Set(ctx, forfeitTxsStoreVtxosKey, vtxosBytes, 0)
				pipe.Set(ctx, forfeitTxsStoreConnIdxKey, idxBytes, 0)
				return nil
			})
			return err
		}); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to init forfeit txs after max num of retries: %v", err)
}

func (s *forfeitTxsStore) Sign(ctx context.Context, txs []string) error {
	if len(txs) == 0 {
		return nil
	}
	if s.builder == nil {
		return fmt.Errorf("missing builder for tx verification")
	}

	vtxosBytes, err := s.rdb.Get(ctx, forfeitTxsStoreVtxosKey).Bytes()
	if err != nil {
		return fmt.Errorf("failed to get vtxos to sign: %v", err)
	}
	var vtxos []domain.Vtxo
	if err := json.Unmarshal(vtxosBytes, &vtxos); err != nil {
		return fmt.Errorf(
			"malformed vtxos to sign in storage (out=%s): %v", string(vtxosBytes), err,
		)
	}
	connBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnsKey).Bytes()
	if err != nil {
		return fmt.Errorf("failed to get connectors: %v", err)
	}
	var connectors tree.FlatTxTree
	if err := json.Unmarshal(connBytes, &connectors); err != nil {
		return fmt.Errorf("malformed connectors in storage (out=%s): %v", string(connBytes), err)
	}
	idxBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnIdxKey).Bytes()
	if err != nil {
		return fmt.Errorf("failed to get connector indexes: %v", err)
	}
	connIndex := make(map[string]domain.Outpoint)
	if err := json.Unmarshal(idxBytes, &connIndex); err != nil {
		return fmt.Errorf(
			"malformed connector indexes in storage (out=%s): %v", string(idxBytes), err,
		)
	}
	validTxs, err := s.builder.VerifyForfeitTxs(vtxos, connectors, txs)
	if err != nil {
		return err
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				for vtxoKey, validTx := range validTxs {
					txBytes, err := json.Marshal(validTx)
					if err != nil {
						return err
					}
					pipe.HSet(ctx, forfeitTxsStoreTxsKey, vtxoKey.String(), string(txBytes))
				}
				return nil
			})
			return err
		}); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to add signed forfeit txs after max number of retries: %v", err)
}

func (s *forfeitTxsStore) Reset(ctx context.Context) error {
	var err error
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, forfeitTxsStoreTxsKey)
				pipe.Del(ctx, forfeitTxsStoreConnsKey)
				pipe.Del(ctx, forfeitTxsStoreVtxosKey)
				pipe.Del(ctx, forfeitTxsStoreConnIdxKey)
				return nil
			})
			return err
		}); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to reset forfeit txs after max number of retries: %v", err)
}

func (s *forfeitTxsStore) Pop(ctx context.Context) ([]string, error) {
	hash, err := s.rdb.HGetAll(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(hash))

	usedConnectors := make(map[domain.Outpoint]struct{})
	for vtxo, forfeitJSON := range hash {
		if len(forfeitJSON) == 0 {
			return nil, fmt.Errorf("missing forfeit tx for vtxo %s", vtxo)
		}
		var validTx ports.ValidForfeitTx
		if err := json.Unmarshal([]byte(forfeitJSON), &validTx); err != nil {
			return nil, fmt.Errorf("failed to unmarshal forfeit tx for vtxo %s: %v", vtxo, err)
		}
		if _, used := usedConnectors[validTx.Connector]; used {
			return nil, fmt.Errorf(
				"connector %s for vtxo %s is used more than once", validTx.Connector, vtxo,
			)
		}
		usedConnectors[validTx.Connector] = struct{}{}
		result = append(result, validTx.Tx)
	}

	if err := s.Reset(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *forfeitTxsStore) AllSigned(ctx context.Context) (bool, error) {
	hash, err := s.rdb.HGetAll(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return false, err
	}
	for _, forfeitJSON := range hash {
		if len(forfeitJSON) == 0 {
			return false, nil
		}
		var validTx ports.ValidForfeitTx
		if err := json.Unmarshal([]byte(forfeitJSON), &validTx); err != nil {
			return false, fmt.Errorf(
				"failed to unmarshal signed forfeit tx (out=%s): %v", forfeitJSON, err,
			)
		}
		if len(validTx.Tx) == 0 {
			return false, nil
		}
	}
	return true, nil
}

func (s *forfeitTxsStore) GetUnsignedInputs(ctx context.Context) ([]domain.Outpoint, error) {
	hash, err := s.rdb.HGetAll(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return nil, err
	}
	vtxoKeys := make([]domain.Outpoint, 0)
	for vtxoStr, forfeitJSON := range hash {
		var vtxoKey domain.Outpoint
		if err := vtxoKey.FromString(vtxoStr); err != nil {
			return nil, fmt.Errorf("malformed data in storage: %v", err)
		}
		if len(forfeitJSON) == 0 {
			vtxoKeys = append(vtxoKeys, vtxoKey)
			continue
		}
		var validTx ports.ValidForfeitTx
		if err := json.Unmarshal([]byte(forfeitJSON), &validTx); err != nil {
			vtxoKeys = append(vtxoKeys, vtxoKey)
			continue
		}
		if len(validTx.Tx) == 0 {
			vtxoKeys = append(vtxoKeys, vtxoKey)
		}
	}

	return vtxoKeys, nil
}

func (s *forfeitTxsStore) Len(ctx context.Context) (int, error) {
	count, err := s.rdb.HLen(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return -1, err
	}
	return int(count), nil
}

func (s *forfeitTxsStore) GetConnectorsIndexes(
	ctx context.Context,
) (map[string]domain.Outpoint, error) {
	idxBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnIdxKey).Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector indexes: %v", err)
	}
	connIndex := make(map[string]domain.Outpoint)
	if err := json.Unmarshal(idxBytes, &connIndex); err != nil {
		return nil, fmt.Errorf(
			"malformed connector indexes in storage (out=%s): %v", string(idxBytes), err,
		)
	}
	return connIndex, nil
}
