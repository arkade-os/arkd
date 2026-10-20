package redislivestore

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestForfeitTxsStoreSign(t *testing.T) {
	var vtxos []domain.Vtxo
	var connectors tree.FlatTxTree
	var conns []domain.Outpoint
	for i := range 4 {
		vtxos = append(vtxos, domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: fmt.Sprintf("%064x", i+1)},
			RootCommitmentTxid: "commitment",
		})
		connector := domain.Outpoint{Txid: fmt.Sprintf("%064x", i+10)}
		connectors = append(connectors, tree.TxTreeNode{Txid: connector.Txid})
		conns = append(conns, connector)
	}
	intents := []domain.Intent{
		{Id: "alice", Inputs: vtxos[:2]},
		{Id: "bob", Inputs: vtxos[2:]},
	}
	a0, a1, b0, b1 := vtxos[0].Outpoint, vtxos[1].Outpoint, vtxos[2].Outpoint, vtxos[3].Outpoint
	submissions := map[string]struct{ vtxo, connector domain.Outpoint }{
		"a0": {a0, conns[0]}, "a1": {a1, conns[1]},
		"b0": {b0, conns[2]}, "b1": {b1, conns[3]},
		"a0-swapped": {a0, conns[1]}, "a1-swapped": {a1, conns[0]},
		"alice-using-bobs-connector": {a0, conns[2]},
		"unknown-connector":          {a0, domain.Outpoint{Txid: "unknown"}},
		"unknown-vtxo":               {domain.Outpoint{Txid: "unknown"}, conns[0]},
	}
	verify := func(txs []string) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
		valid := make(map[domain.Outpoint]ports.ValidForfeitTx)
		for _, tx := range txs {
			submission, ok := submissions[tx]
			if !ok {
				return nil, fmt.Errorf("invalid forfeit")
			}
			valid[submission.vtxo] = ports.ValidForfeitTx{Tx: tx, Connector: submission.connector}
		}
		return valid, nil
	}
	newStore := func(t *testing.T) *forfeitTxsStore {
		t.Helper()
		// Keep these keys separate from the live-store suite in DB 14.
		rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 3})
		s := NewForfeitTxsStore(rdb, forfeitTestBuilder{verify: verify}, 5).(*forfeitTxsStore)
		t.Cleanup(func() {
			require.NoError(t, s.Reset(context.Background()))
			require.NoError(t, rdb.Close())
		})
		require.NoError(t, s.Init(t.Context(), "round-1", connectors, intents))
		return s
	}
	stored := func(t *testing.T, s *forfeitTxsStore) map[string]string {
		t.Helper()
		hash, err := s.rdb.HGetAll(t.Context(), forfeitTxsStoreTxsKey).Result()
		require.NoError(t, err)
		return hash
	}

	t.Run("valid", func(t *testing.T) {
		// conn0 would go with a0 and conn1 with a1: since both vtxos belong to alice's intent,
		// she can use them the other way around.
		t.Run("connectors swapped between vtxos of the same intent", func(t *testing.T) {
			s := newStore(t)
			require.NoError(t, s.Sign(t.Context(), []string{"a0-swapped", "a1-swapped"}))
			unsigned, err := s.GetUnsignedInputs(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, []domain.Outpoint{b0, b1}, unsigned)
		})

		t.Run("signing again replaces the stored forfeit txs", func(t *testing.T) {
			s := newStore(t)
			permuted := []string{"a0-swapped", "a1-swapped", "b0", "b1"}
			require.NoError(t, s.Sign(t.Context(), permuted))
			before := stored(t, s)
			require.NoError(t, s.Sign(t.Context(), permuted))
			require.Equal(t, before, stored(t, s))
			// Both replacements must be overlaid before checking uniqueness.
			require.NoError(t, s.Sign(t.Context(), []string{"a0", "a1"}))
			allSigned, err := s.AllSigned(t.Context())
			require.NoError(t, err)
			require.True(t, allSigned)
			forfeits, err := s.Pop(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"a0", "a1", "b0", "b1"}, forfeits)
		})

		t.Run("replacing a forfeit tx frees its connector", func(t *testing.T) {
			s := newStore(t)
			require.NoError(t, s.Sign(t.Context(), []string{"a0"}))
			// a0 moves from conn0 to conn1, so a1 can take conn0.
			require.NoError(t, s.Sign(t.Context(), []string{"a0-swapped"}))
			require.NoError(t, s.Sign(t.Context(), []string{"a1-swapped"}))
		})

		t.Run("concurrent submissions not conflicting each other", func(t *testing.T) {
			s := newStore(t)
			ready, release := make(chan struct{}, 2), make(chan struct{})
			var executions atomic.Int32
			s.rdb.AddHook(forfeitExecHook{beforeExec: func() {
				if executions.Add(1) <= 2 {
					ready <- struct{}{}
					<-release
				}
			}})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			errs := make(chan error, 2)
			for _, tx := range []string{"a0", "a1"} {
				go func() { errs <- s.Sign(ctx, []string{tx}) }()
			}
			for range 2 {
				select {
				case <-ready:
				case <-ctx.Done():
					close(release)
					t.Fatal("submissions did not reach EXEC")
				}
			}
			close(release)
			for range 2 {
				require.NoError(t, <-errs)
			}
			unsigned, err := s.GetUnsignedInputs(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, []domain.Outpoint{b0, b1}, unsigned)
			require.EqualValues(t, 3, executions.Load(), "WATCH conflict must be retried")
		})
	})

	t.Run("invalid", func(t *testing.T) {
		// Every rejected submission must leave the stored forfeit txs untouched, including
		// the valid ones submitted along with the invalid one.
		testCases := []struct {
			name string
			// Forfeit txs successfully signed before the rejected submission.
			signed []string
			// Overrides the vtxo -> intent ownership stored at init, nil to keep it.
			setIntents func(t *testing.T, s *forfeitTxsStore)
			txs        []string
			wantErr    string
		}{
			// Same as the valid swap, but across different intents.
			{
				name:    "connector of another intent",
				txs:     []string{"alice-using-bobs-connector", "a1"},
				wantErr: "different intent",
			},
			{
				name:    "connector of another intent already signed by its owner",
				signed:  []string{"b0"},
				txs:     []string{"alice-using-bobs-connector"},
				wantErr: "different intent",
			},
			{
				name:    "connector used twice in the same submission",
				txs:     []string{"a0", "a1-swapped", "b1"},
				wantErr: "used more than once",
			},
			{
				name:    "connector already used by a stored forfeit tx",
				signed:  []string{"a0"},
				txs:     []string{"a1-swapped"},
				wantErr: "used more than once",
			},
			{
				name:    "unknown connector",
				txs:     []string{"b0", "unknown-connector"},
				wantErr: "unknown connector",
			},
			{
				name:    "unknown vtxo",
				txs:     []string{"b0", "unknown-vtxo"},
				wantErr: "missing intent ownership",
			},
			{
				name:    "invalid forfeit tx",
				txs:     []string{"b0", "invalid-forfeit"},
				wantErr: "invalid forfeit",
			},
			{
				name: "missing intent ownership",
				setIntents: func(t *testing.T, s *forfeitTxsStore) {
					require.NoError(t, s.rdb.Del(t.Context(), forfeitTxsStoreIntentsKey).Err())
				},
				txs:     []string{"a0-swapped"},
				wantErr: "failed to get vtxo intents",
			},
			{
				name: "vtxo without intent",
				setIntents: func(t *testing.T, s *forfeitTxsStore) {
					intents := fmt.Sprintf(`{"%s":"alice"}`, a1)
					err := s.rdb.Set(t.Context(), forfeitTxsStoreIntentsKey, intents, 0).Err()
					require.NoError(t, err)
				},
				txs:     []string{"a0-swapped"},
				wantErr: "missing intent ownership",
			},
			{
				name: "connector without intent",
				setIntents: func(t *testing.T, s *forfeitTxsStore) {
					intents := fmt.Sprintf(`{"%s":"alice"}`, a0)
					err := s.rdb.Set(t.Context(), forfeitTxsStoreIntentsKey, intents, 0).Err()
					require.NoError(t, err)
				},
				txs:     []string{"a0-swapped"},
				wantErr: "missing intent ownership",
			},
			{
				name: "empty intent",
				setIntents: func(t *testing.T, s *forfeitTxsStore) {
					intents := fmt.Sprintf(`{"%s":"","%s":""}`, a0, a1)
					err := s.rdb.Set(t.Context(), forfeitTxsStoreIntentsKey, intents, 0).Err()
					require.NoError(t, err)
				},
				txs:     []string{"a0-swapped"},
				wantErr: "missing intent ownership",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				s := newStore(t)
				if len(tc.signed) > 0 {
					require.NoError(t, s.Sign(t.Context(), tc.signed))
				}
				if tc.setIntents != nil {
					tc.setIntents(t, s)
				}
				before := stored(t, s)
				require.ErrorContains(t, s.Sign(t.Context(), tc.txs), tc.wantErr)
				require.Equal(t, before, stored(t, s))
			})
		}

		t.Run("concurrent submissions conflicting each other", func(t *testing.T) {
			s := newStore(t)
			ready, release := make(chan struct{}, 2), make(chan struct{})
			var executions atomic.Int32
			s.rdb.AddHook(forfeitExecHook{beforeExec: func() {
				if executions.Add(1) <= 2 {
					ready <- struct{}{}
					<-release
				}
			}})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			errs := make(chan error, 2)
			for _, tx := range []string{"a0", "a1-swapped"} {
				go func() { errs <- s.Sign(ctx, []string{tx}) }()
			}
			for range 2 {
				select {
				case <-ready:
				case <-ctx.Done():
					close(release)
					t.Fatal("submissions did not reach EXEC")
				}
			}
			close(release)
			// Both claim conn0: only one can win.
			var failures int
			for range 2 {
				if err := <-errs; err != nil {
					require.ErrorContains(t, err, "used more than once")
					failures++
				}
			}
			require.Equal(t, 1, failures)
			unsigned, err := s.GetUnsignedInputs(t.Context())
			require.NoError(t, err)
			require.Len(t, unsigned, 3)
		})

		// A forfeit tx verified for a batch must never be stored in another one, even when the
		// new batch has the same vtxos, connectors and intents.
		t.Run("batch changed while signing", func(t *testing.T) {
			testCases := []struct {
				name string
				// Changes the batch through the given store.
				changeBatch func(t *testing.T, s *forfeitTxsStore)
				// Whether the change happens right before Sign commits, rather than while the
				// submission is being verified.
				beforeCommit bool
			}{
				{
					name: "batch reset during verification",
					changeBatch: func(t *testing.T, s *forfeitTxsStore) {
						require.NoError(t, s.Reset(t.Context()))
					},
				},
				{
					name: "batch replaced during verification",
					changeBatch: func(t *testing.T, s *forfeitTxsStore) {
						replacement := []domain.Intent{{Id: "new intent", Inputs: vtxos[:1]}}
						err := s.Init(t.Context(), "round-2", connectors[:1], replacement)
						require.NoError(t, err)
					},
				},
				{
					name: "new batch with the same data during verification",
					changeBatch: func(t *testing.T, s *forfeitTxsStore) {
						require.NoError(t, s.Reset(t.Context()))
						require.NoError(t, s.Init(t.Context(), "round-2", connectors, intents))
					},
				},
				{
					name: "new batch with the same data before commit",
					changeBatch: func(t *testing.T, s *forfeitTxsStore) {
						require.NoError(t, s.Init(t.Context(), "round-2", connectors, intents))
					},
					beforeCommit: true,
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					s := newStore(t)
					require.NoError(t, s.Sign(t.Context(), []string{"b0"}))

					// Sign must leave the store as the change left it.
					var want map[string]string
					if tc.beforeCommit {
						// Use another client, so that the change doesn't trigger the hook.
						other := redis.NewClient(s.rdb.Options())
						t.Cleanup(func() { require.NoError(t, other.Close()) })
						otherStore := NewForfeitTxsStore(other, nil, 5).(*forfeitTxsStore)
						var executions atomic.Int32
						s.rdb.AddHook(forfeitExecHook{beforeExec: func() {
							if executions.Add(1) == 1 {
								tc.changeBatch(t, otherStore)
								want = stored(t, s)
							}
						}})
					} else {
						s.builder = forfeitTestBuilder{verify: func(
							txs []string,
						) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
							tc.changeBatch(t, s)
							want = stored(t, s)
							return verify(txs)
						}}
					}

					err := s.Sign(t.Context(), []string{"a0"})
					require.ErrorContains(t, err, "batch changed during verification")
					require.Equal(t, want, stored(t, s))
				})
			}
		})
	})
}

type forfeitTestBuilder struct {
	ports.TxBuilder
	verify func([]string) (map[domain.Outpoint]ports.ValidForfeitTx, error)
}

func (b forfeitTestBuilder) VerifyAndRebuildForfeitTxs(
	_ []domain.Vtxo, _ tree.FlatTxTree, txs []string,
) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
	return b.verify(txs)
}

// Pause immediately before EXEC to force competing submissions to validate
// against the same stored forfeits, and to exercise WATCH conflict retries.
type forfeitExecHook struct {
	beforeExec func()
}

func (h forfeitExecHook) DialHook(next redis.DialHook) redis.DialHook          { return next }
func (h forfeitExecHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook { return next }
func (h forfeitExecHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if len(cmds) > 0 && cmds[0].Name() == "multi" {
			h.beforeExec()
		}
		return next(ctx, cmds)
	}
}
