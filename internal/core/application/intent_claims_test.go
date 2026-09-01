package application

import (
	"context"
	"errors"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/require"
)

func TestIntentClaimRelease(t *testing.T) {
	ctx := context.Background()

	t.Run("releases each intent's inputs under its own id", func(t *testing.T) {
		// The conflict domain is owner-tagged, so a release under the wrong id
		// would leave the claim in place and the vtxo unspendable.
		rec := &recordingOffchainTxStore{}
		s := &service{cache: testLiveStore{offchainTxs: rec}}

		s.releaseClaimsOfIntents(ctx, []domain.Intent{
			claimIntent("intent-a", "aa", "bb"),
			claimIntent("intent-b", "cc"),
		})

		require.Equal(t, map[string][]string{
			"intent-a": {outpointStr("aa"), outpointStr("bb")},
			"intent-b": {outpointStr("cc")},
		}, rec.released())
	})

	t.Run("looks intents up when the caller only holds ids", func(t *testing.T) {
		rec := &recordingOffchainTxStore{}
		s := &service{cache: testLiveStore{
			offchainTxs: rec,
			intents: testIntentStore{intents: []ports.TimedIntent{
				{Intent: claimIntent("intent-a", "aa")},
			}},
		}}

		s.releaseClaimsOfIntentIds(ctx, []string{"intent-a"})

		require.Equal(t, map[string][]string{"intent-a": {outpointStr("aa")}}, rec.released())
	})

	t.Run("releases nothing when the intent has no vtxo inputs", func(t *testing.T) {
		// A boarding-only intent claims nothing, so it must not release either.
		rec := &recordingOffchainTxStore{}
		s := &service{cache: testLiveStore{offchainTxs: rec}}

		s.releaseClaimsOfIntents(ctx, []domain.Intent{{Id: "intent-a"}})

		require.Empty(t, rec.released())
	})

	t.Run("a lookup failure does not panic or release the wrong claims", func(t *testing.T) {
		rec := &recordingOffchainTxStore{}
		s := &service{cache: testLiveStore{
			offchainTxs: rec,
			intents:     testIntentStore{err: errors.New("store down")},
		}}

		s.releaseClaimsOfIntentIds(ctx, []string{"intent-a"})

		require.Empty(t, rec.released())
	})

	t.Run("round start releases selected intents that are no longer queued", func(t *testing.T) {
		// After a round, a popped intent is either registered on the round or
		// dropped, both gone from the queue, or re-pushed and still queued. Only
		// the first two must release, or a dropped intent's vtxos stay claimed.
		rec := &recordingOffchainTxStore{}
		s := &service{cache: testLiveStore{
			offchainTxs: rec,
			intents: &claimIntentStore{
				selected: []ports.TimedIntent{
					{Intent: claimIntent("intent-a", "aa")},
					{Intent: claimIntent("intent-b", "bb")},
					{Intent: claimIntent("intent-c", "cc")},
				},
				all: []ports.TimedIntent{{Intent: claimIntent("intent-b", "bb")}},
			},
		}}

		s.releaseClaimsOfSelectedIntents(ctx)

		require.Equal(t, map[string][]string{
			"intent-a": {outpointStr("aa")},
			"intent-c": {outpointStr("cc")},
		}, rec.released())
	})

	t.Run("round start with nothing selected releases nothing", func(t *testing.T) {
		rec := &recordingOffchainTxStore{}
		s := &service{cache: testLiveStore{offchainTxs: rec, intents: &claimIntentStore{}}}

		s.releaseClaimsOfSelectedIntents(ctx)

		require.Empty(t, rec.released())
	})

	t.Run("admin delete releases the named intents", func(t *testing.T) {
		rec := &recordingOffchainTxStore{}
		intents := &claimIntentStore{all: []ports.TimedIntent{
			{Intent: claimIntent("intent-a", "aa")},
		}}
		a := &adminService{liveStore: testLiveStore{offchainTxs: rec, intents: intents}}

		require.NoError(t, a.DeleteIntents(ctx, "intent-a"))

		require.Equal(t, map[string][]string{"intent-a": {outpointStr("aa")}}, rec.released())
		require.Equal(t, []string{"intent-a"}, intents.deleted)
	})

	t.Run("admin delete-all releases every queued intent", func(t *testing.T) {
		// ViewAll with no ids returns everything, which is what delete-all needs.
		rec := &recordingOffchainTxStore{}
		intents := &claimIntentStore{all: []ports.TimedIntent{
			{Intent: claimIntent("intent-a", "aa")},
			{Intent: claimIntent("intent-b", "bb")},
		}}
		a := &adminService{liveStore: testLiveStore{offchainTxs: rec, intents: intents}}

		require.NoError(t, a.DeleteIntents(ctx))

		require.Equal(t, map[string][]string{
			"intent-a": {outpointStr("aa")},
			"intent-b": {outpointStr("bb")},
		}, rec.released())
		require.True(t, intents.deletedAll)
	})
}

// --- test doubles and fixtures ---

// recordingOffchainTxStore records what was released, keyed by owner.
type recordingOffchainTxStore struct {
	ports.OffChainTxStore
	calls map[string][]string
}

func (r *recordingOffchainTxStore) ReleaseOutpoints(
	_ context.Context, owner string, outpoints []domain.Outpoint,
) error {
	if r.calls == nil {
		r.calls = make(map[string][]string)
	}
	for _, o := range outpoints {
		r.calls[owner] = append(r.calls[owner], o.String())
	}
	return nil
}

func (r *recordingOffchainTxStore) released() map[string][]string { return r.calls }

// claimIntentStore is an IntentStore that serves ViewAll and GetSelectedIntents
// and records deletions.
type claimIntentStore struct {
	ports.IntentStore
	all        []ports.TimedIntent
	selected   []ports.TimedIntent
	deleted    []string
	deletedAll bool
}

func (s *claimIntentStore) GetSelectedIntents(_ context.Context) ([]ports.TimedIntent, error) {
	return s.selected, nil
}

func (s *claimIntentStore) ViewAll(
	_ context.Context, ids []string,
) ([]ports.TimedIntent, error) {
	if len(ids) <= 0 {
		return s.all, nil
	}
	out := make([]ports.TimedIntent, 0, len(ids))
	for _, intent := range s.all {
		for _, id := range ids {
			if intent.Id == id {
				out = append(out, intent)
			}
		}
	}
	return out, nil
}

func (s *claimIntentStore) Delete(_ context.Context, ids []string) error {
	s.deleted = append(s.deleted, ids...)
	return nil
}

func (s *claimIntentStore) DeleteAll(_ context.Context) error {
	s.deletedAll = true
	return nil
}

// claimIntent builds an intent owning one vtxo input per seed.
func claimIntent(id string, seeds ...string) domain.Intent {
	inputs := make([]domain.Vtxo, 0, len(seeds))
	for _, seed := range seeds {
		inputs = append(inputs, domain.Vtxo{Outpoint: domain.Outpoint{Txid: outpointTxid(seed)}})
	}
	return domain.Intent{Id: id, Inputs: inputs}
}

func outpointTxid(seed string) string {
	txid := ""
	for len(txid) < 64 {
		txid += seed
	}
	return txid[:64]
}

func outpointStr(seed string) string {
	return domain.Outpoint{Txid: outpointTxid(seed)}.String()
}
