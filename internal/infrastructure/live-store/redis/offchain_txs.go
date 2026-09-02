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
	log "github.com/sirupsen/logrus"
)

// rebuildTimeout bounds the startup rebuild of the inputs hash.
const rebuildTimeout = 30 * time.Second

const (
	offChainTxsHashKey = "offChainTxStore:txs"
	// offChainInputsHashKey is an owner-tagged HASH: field = spent-input
	// outpoint string, value = owning arkTxid. It replaces the former untagged
	// SET (a deliberately new key name, so a mixed-version rollout cannot hit a
	// WRONGTYPE on the old key; the set is an ephemeral in-flight cache).
	offChainInputsHashKey = "offChainTxStore:inputsByOwner"
)

// claimScript owner-tags a batch of outpoints atomically in the inputs hash.
// KEYS[1]=inputs hash. ARGV[1]=owner, ARGV[2..]=outpoints. Returns
// {status, conflict}: "conflict" + the outpoint held by a different owner
// (registers nothing), "owned" if the owner already held all of them
// (registers nothing), else "fresh" after registering all to the owner.
var claimScript = redis.NewScript(`
local owner = ARGV[1]
for i = 2, #ARGV do
  local cur = redis.call('HGET', KEYS[1], ARGV[i])
  if cur and cur ~= owner then
    return {'conflict', ARGV[i]}
  end
end
local anyNew = false
for i = 2, #ARGV do
  if redis.call('HGET', KEYS[1], ARGV[i]) == false then
    anyNew = true
  end
end
if not anyNew then
  return {'owned', ''}
end
for i = 2, #ARGV do
  redis.call('HSET', KEYS[1], ARGV[i], owner)
end
return {'fresh', ''}
`)

// addScript is claimScript plus storing the tx body atomically, so a conflict
// stores nothing. KEYS[1]=inputs hash, KEYS[2]=txs hash. ARGV[1]=owner
// (arkTxid), ARGV[2]=tx json, ARGV[3..]=outpoints.
var addScript = redis.NewScript(`
local owner = ARGV[1]
for i = 3, #ARGV do
  local cur = redis.call('HGET', KEYS[1], ARGV[i])
  if cur and cur ~= owner then
    return {'conflict', ARGV[i]}
  end
end
local anyNew = false
for i = 3, #ARGV do
  if redis.call('HGET', KEYS[1], ARGV[i]) == false then
    anyNew = true
  end
end
for i = 3, #ARGV do
  redis.call('HSET', KEYS[1], ARGV[i], owner)
end
redis.call('HSET', KEYS[2], owner, ARGV[2])
if anyNew then
  return {'fresh', ''}
else
  return {'owned', ''}
end
`)

// releaseScript owner-scoped-deletes outpoints from the inputs hash.
// KEYS[1]=inputs hash. ARGV[1]=owner, ARGV[2..]=outpoints.
var releaseScript = redis.NewScript(`
local owner = ARGV[1]
for i = 2, #ARGV do
  if redis.call('HGET', KEYS[1], ARGV[i]) == owner then
    redis.call('HDEL', KEYS[1], ARGV[i])
  end
end
return 1
`)

// removeScript is releaseScript plus deleting the tx body.
// KEYS[1]=inputs hash, KEYS[2]=txs hash. ARGV[1]=arkTxid, ARGV[2..]=outpoints.
var removeScript = redis.NewScript(`
local owner = ARGV[1]
for i = 2, #ARGV do
  if redis.call('HGET', KEYS[1], ARGV[i]) == owner then
    redis.call('HDEL', KEYS[1], ARGV[i])
  end
end
redis.call('HDEL', KEYS[2], owner)
return 1
`)

type offChainTxStore struct {
	rdb          *redis.Client
	numOfRetries int
	retryDelay   time.Duration
}

func NewOffChainTxStore(rdb *redis.Client, numOfRetries int) ports.OffChainTxStore {
	s := &offChainTxStore{
		rdb:          rdb,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), rebuildTimeout)
	defer cancel()
	if err := s.rebuildInputs(ctx); err != nil {
		log.WithError(err).Warn(
			"failed to rebuild offchain tx inputs from stored txs, " +
				"in-flight txs accepted before this start are unprotected until projected",
		)
	}
	return s
}

// rebuildInputs re-registers, under its arkTxid, every spent input of every
// stored tx body. A tx accepted by the previous version, which kept an untagged
// set instead of this hash, or whose entries were deleted by hand during a
// rollback, gets its single-spend protection back that way. It only ever adds,
// and never overwrites an owner, so it is safe on every start and cannot race
// a concurrent Add, which writes a body and its inputs together.
func (s *offChainTxStore) rebuildInputs(ctx context.Context) error {
	bodies, err := s.rdb.HGetAll(ctx, offChainTxsHashKey).Result()
	if err != nil {
		return fmt.Errorf("failed to list stored offchain txs: %v", err)
	}
	registered := 0
	for arkTxid, body := range bodies {
		var offchainTx domain.OffchainTx
		if err := json.Unmarshal([]byte(body), &offchainTx); err != nil {
			log.WithError(err).Warnf("skipping malformed stored offchain tx %s", arkTxid)
			continue
		}
		inputs, _ := checkpointInputs(offchainTx)
		for _, in := range inputs {
			added, err := s.rdb.HSetNX(ctx, offChainInputsHashKey, in, arkTxid).Result()
			if err != nil {
				return fmt.Errorf("failed to re-register input %s of %s: %v", in, arkTxid, err)
			}
			if added {
				registered++
			}
		}
	}
	if registered > 0 {
		log.Infof(
			"re-registered %d spent input(s) from %d stored offchain tx(s)",
			registered, len(bodies),
		)
	}
	return nil
}

func (s *offChainTxStore) Add(
	ctx context.Context, offchainTx domain.OffchainTx,
) (ports.ClaimStatus, *domain.Outpoint, error) {
	// A checkpoint tx that fails to parse is skipped, they are validated upstream.
	inputs, _ := checkpointInputs(offchainTx)
	val, err := json.Marshal(offchainTx)
	if err != nil {
		return ports.ClaimFresh, nil, fmt.Errorf(
			"failed to marshal offchain tx %s: %v", offchainTx.ArkTxid, err,
		)
	}

	args := make([]interface{}, 0, 2+len(inputs))
	args = append(args, offchainTx.ArkTxid, string(val))
	for _, in := range inputs {
		args = append(args, in)
	}
	res, err := s.eval(ctx, addScript, []string{offChainInputsHashKey, offChainTxsHashKey}, args...)
	if err != nil {
		return ports.ClaimFresh, nil, fmt.Errorf(
			"failed to add offchain tx %s: %v", offchainTx.ArkTxid, err,
		)
	}
	return parseClaimResult(res)
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
	inputs, err := checkpointInputs(offchainTx)
	if err != nil {
		return fmt.Errorf("malformed offchain checkpoint tx in storage %s: %v", arkTxid, err)
	}

	args := make([]interface{}, 0, 1+len(inputs))
	args = append(args, arkTxid)
	for _, in := range inputs {
		args = append(args, in)
	}
	if _, err := s.eval(
		ctx, removeScript, []string{offChainInputsHashKey, offChainTxsHashKey}, args...,
	); err != nil {
		return fmt.Errorf("failed to remove offchain tx %s: %v", arkTxid, err)
	}
	return nil
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

func (s *offChainTxStore) ClaimOutpoints(
	ctx context.Context, owner string, outpoints []domain.Outpoint,
) (ports.ClaimStatus, *domain.Outpoint, error) {
	if len(outpoints) == 0 {
		return ports.ClaimAlreadyOwned, nil, nil
	}
	args := make([]interface{}, 0, 1+len(outpoints))
	args = append(args, owner)
	for _, o := range outpoints {
		args = append(args, o.String())
	}
	res, err := s.eval(ctx, claimScript, []string{offChainInputsHashKey}, args...)
	if err != nil {
		return ports.ClaimFresh, nil, fmt.Errorf("failed to claim outpoints: %v", err)
	}
	return parseClaimResult(res)
}

func (s *offChainTxStore) ReleaseOutpoints(
	ctx context.Context, owner string, outpoints []domain.Outpoint,
) error {
	if len(outpoints) == 0 {
		return nil
	}
	args := make([]interface{}, 0, 1+len(outpoints))
	args = append(args, owner)
	for _, o := range outpoints {
		args = append(args, o.String())
	}
	if _, err := s.eval(ctx, releaseScript, []string{offChainInputsHashKey}, args...); err != nil {
		return fmt.Errorf("failed to release outpoints: %v", err)
	}
	return nil
}

func (s *offChainTxStore) Includes(ctx context.Context, outpoint domain.Outpoint) (bool, error) {
	exists, err := s.rdb.HExists(ctx, offChainInputsHashKey, outpoint.String()).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence of input %s: %v", outpoint, err)
	}
	return exists, nil
}

// eval runs an atomic Lua script, retrying on transient redis errors. The
// script itself is the atomicity boundary, so no WATCH/MULTI is needed.
func (s *offChainTxStore) eval(
	ctx context.Context, script *redis.Script, keys []string, args ...interface{},
) (interface{}, error) {
	var lastErr error
	for range s.numOfRetries {
		res, err := script.Run(ctx, s.rdb, keys, args...).Result()
		if err == nil {
			return res, nil
		}
		lastErr = err
		time.Sleep(s.retryDelay)
	}
	return nil, lastErr
}

// parseClaimResult maps the {status, conflict} Lua reply to the tri-state.
func parseClaimResult(res interface{}) (ports.ClaimStatus, *domain.Outpoint, error) {
	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 {
		return ports.ClaimFresh, nil, fmt.Errorf("unexpected claim result: %v", res)
	}
	status, _ := arr[0].(string)
	switch status {
	case "fresh":
		return ports.ClaimFresh, nil, nil
	case "owned":
		return ports.ClaimAlreadyOwned, nil, nil
	case "conflict":
		conflictStr, _ := arr[1].(string)
		var out domain.Outpoint
		if err := out.FromString(conflictStr); err != nil {
			return ports.ClaimConflict, nil, fmt.Errorf(
				"malformed conflicting outpoint %q: %v", conflictStr, err,
			)
		}
		return ports.ClaimConflict, &out, nil
	default:
		return ports.ClaimFresh, nil, fmt.Errorf("unknown claim status %q", status)
	}
}

// checkpointInputs returns every spent-input outpoint of every checkpoint tx of
// the offchain tx, the set the conflict domain registers. Checkpoint txs that
// fail to parse are skipped and the last parse error is returned, so callers
// choose whether that is fatal.
func checkpointInputs(offchainTx domain.OffchainTx) ([]string, error) {
	inputs := make([]string, 0)
	var parseErr error
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			parseErr = err
			continue
		}
		for _, in := range ptx.UnsignedTx.TxIn {
			inputs = append(inputs, in.PreviousOutPoint.String())
		}
	}
	return inputs, parseErr
}
