package redislivestore

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	txReqStoreReqIdsKey        = "txreq:ids"
	txReqStoreVtxosKey         = "txreq:vtxos"
	txReqStoreVtxosToRemoveKey = "txreq:vtxosToRemove"
)

type txRequestsStore struct {
	rdb      *redis.Client
	requests *KVStore[ports.TimedTxRequest]

	numOfRetries int
}

func NewTxRequestsStore(rdb *redis.Client, numOfRetries int) ports.TxRequestsStore {
	return &txRequestsStore{
		rdb:          rdb,
		requests:     NewRedisKVStore[ports.TimedTxRequest](rdb, "txreq:"),
		numOfRetries: numOfRetries,
	}
}

func (s *txRequestsStore) Len() int64 {
	ctx := context.Background()
	ids, err := s.rdb.SMembers(ctx, txReqStoreReqIdsKey).Result()
	if err != nil {
		return 0
	}

	reqs, err := s.requests.GetMulti(ctx, ids)
	if err != nil {
		return 0
	}

	count := int64(0)
	for _, tx := range reqs {
		if tx != nil && len(tx.Receivers) > 0 {
			count++
		}
	}

	return count
}

func (s *txRequestsStore) Push(request domain.TxRequest, boardingInputs []ports.BoardingInput, cosignerPubkeys []string) error {
	ctx := context.Background()
	var err error
	for attempt := 0; attempt < s.numOfRetries; attempt++ {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			exists, err := tx.SIsMember(ctx, txReqStoreReqIdsKey, request.Id).Result()
			if err != nil {
				return err
			}
			if exists {
				return fmt.Errorf("duplicated tx request %s", request.Id)
			}
			// Check input duplicates directly in Redis set
			for _, input := range request.Inputs {
				if input.IsNote() {
					continue
				}
				key := input.String()
				exists, err := tx.SIsMember(ctx, txReqStoreVtxosKey, key).Result()
				if err != nil {
					return err
				}
				if exists {
					return fmt.Errorf("duplicated input, %s already registered by another request", key)
				}
			}

			// Check boarding inputs similarly if you store them

			now := time.Now()
			timedReq := &ports.TimedTxRequest{
				TxRequest:           request,
				BoardingInputs:      boardingInputs,
				Timestamp:           now,
				CosignersPublicKeys: cosignerPubkeys,
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				if err := s.requests.SetPipe(ctx, pipe, request.Id, timedReq); err != nil {
					return err
				}

				pipe.SAdd(ctx, txReqStoreReqIdsKey, request.Id)
				for _, vtxo := range request.Inputs {
					if vtxo.IsNote() {
						continue
					}
					pipe.SAdd(ctx, txReqStoreVtxosKey, vtxo.String())
				}

				return nil
			})

			return err
		}, txReqStoreVtxosKey, txReqStoreReqIdsKey) // WATCH both keys
		if err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

func (s *txRequestsStore) Pop(num int64) []ports.TimedTxRequest {
	ctx := context.Background()
	ids, err := s.rdb.SMembers(ctx, txReqStoreReqIdsKey).Result()
	if err != nil {
		return nil
	}

	var requestsByTime []ports.TimedTxRequest
	for _, id := range ids {
		req, err := s.requests.Get(ctx, id)
		if err != nil || req == nil {
			log.Debugf("pop:tx request %s not found", id)
			continue
		}

		if len(req.Receivers) > 0 {
			requestsByTime = append(requestsByTime, *req)
		}
	}

	sort.SliceStable(requestsByTime, func(i, j int) bool {
		return requestsByTime[i].Timestamp.Before(requestsByTime[j].Timestamp)
	})
	if num < 0 || num > int64(len(requestsByTime)) {
		num = int64(len(requestsByTime))
	}

	result := make([]ports.TimedTxRequest, 0, num)
	var vtxosToRemove []string
	for _, req := range requestsByTime[:num] {
		result = append(result, req)
		for _, vtxo := range req.Inputs {
			vtxosToRemove = append(vtxosToRemove, vtxo.String())
		}

		if err := s.requests.Delete(ctx, req.Id); err != nil {
			log.Warnf("pop:failed to delete tx request %s: %v", req.Id, err)
		}

		s.rdb.SRem(ctx, txReqStoreReqIdsKey, req.Id)
	}

	if len(vtxosToRemove) > 0 {
		s.rdb.SAdd(ctx, txReqStoreVtxosToRemoveKey, vtxosToRemove)
	}
	return result
}

func (s *txRequestsStore) View(id string) (*domain.TxRequest, bool) {
	ctx := context.Background()
	req, err := s.requests.Get(ctx, id)
	if err != nil || req == nil {
		log.Debugf("view:tx request %s not found", id)
		return nil, false
	}

	return &req.TxRequest, true
}

func (s *txRequestsStore) ViewAll(ids []string) ([]ports.TimedTxRequest, error) {
	ctx := context.Background()
	var result []ports.TimedTxRequest
	if len(ids) > 0 {
		reqs, err := s.requests.GetMulti(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, t := range reqs {
			if t != nil {
				result = append(result, *t)
			}
		}
		return result, nil
	}

	allIDs, err := s.rdb.SMembers(ctx, txReqStoreReqIdsKey).Result()
	if err != nil {
		return nil, err
	}

	txs, err := s.requests.GetMulti(ctx, allIDs)
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

func (s *txRequestsStore) Update(request domain.TxRequest, cosignerPubkeys []string) error {
	ctx := context.Background()
	req, err := s.requests.Get(ctx, request.Id)
	if err != nil || req == nil {
		return err
	}

	// Sum of inputs = vtxos + boarding utxos + notes + recovered vtxos
	sumOfInputs := uint64(0)
	for _, input := range request.Inputs {
		sumOfInputs += input.Amount
	}
	for _, boardingInput := range req.BoardingInputs {
		sumOfInputs += boardingInput.Amount
	}

	// Sum of outputs = receivers VTXOs
	sumOfOutputs := uint64(0)
	for _, receiver := range request.Receivers {
		sumOfOutputs += receiver.Amount
	}

	if sumOfInputs != sumOfOutputs {
		return fmt.Errorf("sum of inputs %d does not match sum of outputs %d", sumOfInputs, sumOfOutputs)
	}

	req.TxRequest = request
	if len(cosignerPubkeys) > 0 {
		req.CosignersPublicKeys = cosignerPubkeys
	}

	return s.requests.Set(ctx, request.Id, req)
}

func (s *txRequestsStore) Delete(ids []string) error {
	ctx := context.Background()
	for _, id := range ids {
		req, err := s.requests.Get(ctx, id)
		if err != nil || req == nil {
			log.Debugf("delete:tx request %s not found", id)
			continue
		}

		for _, vtxo := range req.Inputs {
			s.rdb.SRem(ctx, txReqStoreVtxosKey, vtxo.String())
		}

		if err := s.requests.Delete(ctx, id); err != nil {
			log.Warnf("delete:failed to delete tx request %s: %v", id, err)
		}

		s.rdb.SRem(ctx, txReqStoreReqIdsKey, id)
	}
	return nil
}

func (s *txRequestsStore) DeleteAll() error {
	ctx := context.Background()
	ids, err := s.rdb.SMembers(ctx, txReqStoreReqIdsKey).Result()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.requests.Delete(ctx, id); err != nil {
			log.Warnf("delete:failed to delete tx request %s: %v", id, err)
		}
	}
	s.rdb.Del(ctx, txReqStoreReqIdsKey)
	s.rdb.Del(ctx, txReqStoreVtxosKey)
	s.rdb.Del(ctx, txReqStoreVtxosToRemoveKey)
	return nil
}

func (s *txRequestsStore) DeleteVtxos() {
	ctx := context.Background()
	vtxosToRemove, err := s.rdb.SMembers(ctx, txReqStoreVtxosToRemoveKey).Result()
	if err != nil {
		return
	}

	if len(vtxosToRemove) > 0 {
		s.rdb.SRem(ctx, txReqStoreVtxosKey, vtxosToRemove)
	}

	s.rdb.Del(ctx, txReqStoreVtxosToRemoveKey)
}

func (s *txRequestsStore) IncludesAny(outpoints []domain.Outpoint) (bool, string) {
	ctx := context.Background()
	for _, out := range outpoints {
		exists, err := s.rdb.SIsMember(ctx, txReqStoreVtxosKey, out.String()).Result()
		if err == nil && exists {
			return true, out.String()
		} else if err != nil {
			log.Warnf("includesAny:failed to check vtxo %s: %v", out.String(), err)
		}
	}
	return false, ""
}
