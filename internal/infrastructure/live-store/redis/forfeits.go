package redislivestore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/redis/go-redis/v9"
)

type forfeitTxsStore struct {
	rdb     *redis.Client
	builder ports.TxBuilder
}

const (
	forfeitTxsStoreTxsKey     = "forfeitTxsStore:txs"
	forfeitTxsStoreConnsKey   = "forfeitTxsStore:connectors"
	forfeitTxsStoreVtxosKey   = "forfeitTxsStore:vtxos"
	forfeitTxsStoreConnIdxKey = "forfeitTxsStore:connidx"
)

func NewForfeitTxsStore(rdb *redis.Client, builder ports.TxBuilder) ports.ForfeitTxsStore {
	return &forfeitTxsStore{
		rdb:     rdb,
		builder: builder,
	}
}

func (s *forfeitTxsStore) Init(connectors tree.FlatTxTree, intents []domain.Intent) error {
	ctx := context.Background()
	vtxosToSign := make([]domain.Vtxo, 0)
	for _, intent := range intents {
		for _, vtxo := range intent.Inputs {
			if !vtxo.RequiresForfeit() {
				continue
			}
			vtxosToSign = append(vtxosToSign, vtxo)
		}
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
	// Store in Redis atomically
	pipe := s.rdb.TxPipeline()
	for vtxoKey, forfeit := range forfeitTxs {
		pipe.HSet(ctx, forfeitTxsStoreTxsKey, vtxoKey, forfeit)
	}
	connBytes, _ := json.Marshal(connectors)
	pipe.Set(ctx, forfeitTxsStoreConnsKey, connBytes, 0)
	vtxosBytes, _ := json.Marshal(vtxosToSign)
	pipe.Set(ctx, forfeitTxsStoreVtxosKey, vtxosBytes, 0)
	idxBytes, _ := json.Marshal(connIndex)
	pipe.Set(ctx, forfeitTxsStoreConnIdxKey, idxBytes, 0)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *forfeitTxsStore) Sign(txs []string) error {
	if len(txs) == 0 {
		return nil
	}
	ctx := context.Background()
	vtxosBytes, err := s.rdb.Get(ctx, forfeitTxsStoreVtxosKey).Bytes()
	if err != nil {
		return err
	}
	var vtxos []domain.Vtxo
	if err := json.Unmarshal(vtxosBytes, &vtxos); err != nil {
		return err
	}
	connBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnsKey).Bytes()
	if err != nil {
		return err
	}
	var connectors tree.FlatTxTree
	if err := json.Unmarshal(connBytes, &connectors); err != nil {
		return err
	}
	idxBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnIdxKey).Bytes()
	if err != nil {
		return err
	}
	connIndex := make(map[string]domain.Outpoint)
	if err := json.Unmarshal(idxBytes, &connIndex); err != nil {
		return err
	}
	if s.builder == nil {
		return fmt.Errorf("forfeitTxsStore builder not set")
	}
	validTxs, err := s.builder.VerifyForfeitTxs(vtxos, connectors, txs)
	if err != nil {
		return err
	}

	pipe := s.rdb.TxPipeline()
	for vtxoKey, validTx := range validTxs {
		txBytes, err := json.Marshal(validTx)
		if err != nil {
			return err
		}
		pipe.HSet(ctx, forfeitTxsStoreTxsKey, vtxoKey.String(), string(txBytes))
	}
	_, err = pipe.Exec(ctx)

	return err
}

func (s *forfeitTxsStore) Reset() {
	ctx := context.Background()
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, forfeitTxsStoreTxsKey)
	pipe.Del(ctx, forfeitTxsStoreConnsKey)
	pipe.Del(ctx, forfeitTxsStoreVtxosKey)
	pipe.Del(ctx, forfeitTxsStoreConnIdxKey)
	_, _ = pipe.Exec(ctx)
}

func (s *forfeitTxsStore) Pop() ([]string, error) {
	ctx := context.Background()
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
			return nil, fmt.Errorf("failed to unmarshal forfeit tx for vtxo %s: %w", vtxo, err)
		}
		if _, used := usedConnectors[validTx.Connector]; used {
			return nil, fmt.Errorf(
				"connector %s for vtxo %s is used more than once", validTx.Connector, vtxo,
			)
		}
		usedConnectors[validTx.Connector] = struct{}{}
		result = append(result, validTx.Tx)
	}
	s.Reset()
	return result, nil
}

func (s *forfeitTxsStore) AllSigned() bool {
	ctx := context.Background()
	hash, err := s.rdb.HGetAll(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return false
	}
	for _, forfeitJSON := range hash {
		if len(forfeitJSON) == 0 {
			return false
		}
		var validTx ports.ValidForfeitTx
		if err := json.Unmarshal([]byte(forfeitJSON), &validTx); err != nil {
			return false
		}
		if len(validTx.Tx) == 0 {
			return false
		}
	}
	return true
}

func (s *forfeitTxsStore) Len() int {
	ctx := context.Background()
	count, err := s.rdb.HLen(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return 0
	}
	return int(count)
}

func (s *forfeitTxsStore) GetConnectorsIndexes() map[string]domain.Outpoint {
	ctx := context.Background()
	idxBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnIdxKey).Bytes()
	if err != nil {
		return nil
	}
	connIndex := make(map[string]domain.Outpoint)
	if err := json.Unmarshal(idxBytes, &connIndex); err != nil {
		return nil
	}
	return connIndex
}
