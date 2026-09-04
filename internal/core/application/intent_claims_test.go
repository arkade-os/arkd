package application

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestIntentClaimRelease(t *testing.T) {
	ctx := context.Background()

	t.Run("releases each intent's inputs under its own id", func(t *testing.T) {
		// The conflict domain is owner-tagged, so a release under the wrong id
		// would leave the claim in place and the vtxo unspendable.
		rec := &recordingOffchainTxStore{}

		releaseClaimsOfIntents(ctx, rec, []domain.Intent{
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

		releaseClaimsOfIntents(ctx, rec, []domain.Intent{{Id: "intent-a"}})

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

	t.Run("delete by proof releases the matching intents", func(t *testing.T) {
		message := intent.DeleteMessage{
			BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete},
		}
		encodedMessage, err := message.Encode()
		require.NoError(t, err)
		proof := testNoteIntentProof(t, encodedMessage, &wire.TxOut{
			Value: int64(testDust) * 2, PkScript: testP2TRScript(t),
		})

		// Serve the proof's ownership input as a vtxo whose pubkey matches its
		// witness utxo, so the proof verifies and matches the queued intent.
		witness := proof.Inputs[1].WitnessUtxo
		op := proof.GetOutpoints()[0]
		vtxo := domain.Vtxo{
			Outpoint: domain.Outpoint{Txid: op.Hash.String(), VOut: op.Index},
			Amount:   uint64(witness.Value),
			PubKey:   hex.EncodeToString(witness.PkScript[2:]),
		}
		vtxos := &mockedVtxoRepo{}
		vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return([]domain.Vtxo{vtxo}, nil)
		repos := &mockedRepoManager{}
		repos.On("Vtxos").Return(vtxos)

		rec := &recordingOffchainTxStore{}
		intents := &claimIntentStore{all: []ports.TimedIntent{
			{Intent: domain.Intent{Id: "intent-a", Inputs: []domain.Vtxo{vtxo}}},
		}}
		s := &service{
			repoManager: repos,
			cache: testLiveStore{
				settings:    testSettingsStore{settings: &ports.Settings{SignerPubkey: testPubkey(t)}},
				offchainTxs: rec,
				intents:     intents,
			},
		}

		require.NoError(t, s.DeleteIntentsByProof(ctx, *proof, message))

		require.Equal(t, map[string][]string{
			"intent-a": {vtxo.Outpoint.String()},
		}, rec.released())
		require.Equal(t, []string{"intent-a"}, intents.deleted)
	})

	// Both services drop intents and both must release through the same helper.
	// A second copy that drifted would leak claims on whichever path missed a
	// fix, with no error to show it.
	t.Run("the service and the admin service release identically", func(t *testing.T) {
		intents := []domain.Intent{claimIntent("intent-a", "aa", "bb")}

		fromService := &recordingOffchainTxStore{}
		svc := &service{cache: testLiveStore{
			offchainTxs: fromService,
			intents:     testIntentStore{intents: []ports.TimedIntent{{Intent: intents[0]}}},
		}}
		svc.releaseClaimsOfIntentIds(ctx, []string{"intent-a"})

		fromAdmin := &recordingOffchainTxStore{}
		a := &adminService{liveStore: testLiveStore{
			offchainTxs: fromAdmin,
			intents:     &claimIntentStore{all: []ports.TimedIntent{{Intent: intents[0]}}},
		}}
		require.NoError(t, a.DeleteIntents(ctx, "intent-a"))

		require.Equal(t, fromService.released(), fromAdmin.released())
		require.Equal(t, map[string][]string{
			"intent-a": {outpointStr("aa"), outpointStr("bb")},
		}, fromAdmin.released())
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
		// It deletes that snapshot by id rather than wiping the store, so the
		// deleted set is exactly the released set.
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
		require.Equal(t, []string{"intent-a", "intent-b"}, intents.deleted)
		require.False(t, intents.deletedAll, "delete-all must delete the snapshot, not wipe the store")
	})

	t.Run("admin delete-all keeps an intent registered after the snapshot", func(t *testing.T) {
		// Registered between the snapshot and the delete, intent-c holds a claim
		// nobody released. Wiping the store would delete it and leave that claim
		// behind, with no round to release it from since it was never popped.
		rec := &recordingOffchainTxStore{}
		intents := &claimIntentStore{all: []ports.TimedIntent{
			{Intent: claimIntent("intent-a", "aa")},
		}}
		intents.afterViewAll = func() {
			intents.all = append(intents.all, ports.TimedIntent{Intent: claimIntent("intent-c", "cc")})
		}
		a := &adminService{liveStore: testLiveStore{offchainTxs: rec, intents: intents}}

		require.NoError(t, a.DeleteIntents(ctx))

		require.Equal(t, map[string][]string{"intent-a": {outpointStr("aa")}}, rec.released())
		require.Equal(t, []string{"intent-a"}, intents.deleted)
		require.False(t, intents.deletedAll)
	})

	t.Run("admin delete fails without deleting when the lookup fails", func(t *testing.T) {
		// Deleting without the snapshot would drop intents whose claims were
		// never released, so the call fails instead.
		rec := &recordingOffchainTxStore{}
		intents := &claimIntentStore{err: errors.New("store down")}
		a := &adminService{liveStore: testLiveStore{offchainTxs: rec, intents: intents}}

		require.Error(t, a.DeleteIntents(ctx, "intent-a"))

		require.Empty(t, rec.released())
		require.Empty(t, intents.deleted)
		require.False(t, intents.deletedAll)
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
// and records deletions. afterViewAll, when set, runs once a ViewAll snapshot
// has been taken, to simulate a registration racing the caller.
type claimIntentStore struct {
	ports.IntentStore
	all          []ports.TimedIntent
	selected     []ports.TimedIntent
	err          error
	afterViewAll func()
	deleted      []string
	deletedAll   bool
}

func (s *claimIntentStore) GetSelectedIntents(_ context.Context) ([]ports.TimedIntent, error) {
	return s.selected, nil
}

func (s *claimIntentStore) ViewAll(
	_ context.Context, ids []string,
) ([]ports.TimedIntent, error) {
	if s.err != nil {
		return nil, s.err
	}
	out := make([]ports.TimedIntent, 0, len(s.all))
	for _, intent := range s.all {
		if len(ids) <= 0 || slices.Contains(ids, intent.Id) {
			out = append(out, intent)
		}
	}
	if s.afterViewAll != nil {
		s.afterViewAll()
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
