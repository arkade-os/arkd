package application

import (
	"context"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const filterTestPubkey = "0000000000000000000000000000000000000000000000000000000000000001"

// filterTestVtxo builds a vtxo with the flag combination under test. A note has
// no commitment txids, an expired vtxo has an ExpiresAt in the past.
func filterTestVtxo(txid string, spent, swept, unrolled, note, expired bool) domain.Vtxo {
	v := domain.Vtxo{
		Outpoint: domain.Outpoint{Txid: txid, VOut: 0},
		Amount:   1000,
		PubKey:   filterTestPubkey,
		Spent:    spent,
		Swept:    swept,
		Unrolled: unrolled,
	}
	if !note {
		v.RootCommitmentTxid = "commitment"
		v.CommitmentTxids = []string{"commitment"}
	}
	if expired {
		v.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	} else {
		v.ExpiresAt = time.Now().Add(time.Hour).Unix()
	}
	return v
}

func newFilterTestIndexer(vtxos []domain.Vtxo) *indexerService {
	vtxoRepo := &mockedVtxoRepo{}
	vtxoRepo.On(
		"GetAllVtxosWithPubKeys", mock.Anything, []string{filterTestPubkey}, int64(0), int64(0),
	).Return(vtxos, nil)

	repoManager := &mockedRepoManager{}
	repoManager.On("Vtxos").Return(vtxoRepo)

	return &indexerService{repoManager: repoManager, txExposure: exposurePublic}
}

func outpointsOf(vtxos []domain.Vtxo) []string {
	out := make([]string, 0, len(vtxos))
	for _, v := range vtxos {
		out = append(out, v.Outpoint.String())
	}
	return out
}

// The fixture set covers every combination that changes the outcome of the
// spendable, recoverable and renewable predicates.
func filterTestFixtures() []struct {
	name        string
	vtxo        domain.Vtxo
	spendable   bool
	recoverable bool
} {
	return []struct {
		name        string
		vtxo        domain.Vtxo
		spendable   bool
		recoverable bool
	}{
		// spent=F swept=F unrolled=F note=F expired=F
		{"plain", filterTestVtxo("a1", false, false, false, false, false), true, false},
		// swept vtxos stop requiring a forfeit, so they become recoverable
		{"swept", filterTestVtxo("a2", false, true, false, false, false), false, true},
		// expired and note vtxos are both spendable and recoverable
		{"expired", filterTestVtxo("a3", false, false, false, false, true), true, true},
		{"note", filterTestVtxo("a4", false, false, false, true, false), true, true},
		{"spent", filterTestVtxo("a5", true, false, false, false, false), false, false},
		{"unrolled", filterTestVtxo("a6", false, false, true, false, false), false, false},
		{"spent and swept", filterTestVtxo("a7", true, true, false, false, false), false, false},
	}
}

// TestGetVtxosRenewableIsUnionOfSpendableAndRecoverable pins the invariant the
// renewableOnly filter relies on. It holds only because RequiresForfeit expands
// to (Swept || IsExpired || IsNote || Unrolled), so any unspent, non-unrolled
// vtxo lands in the spendable set when not swept and in the recoverable set
// otherwise. If RequiresForfeit ever gains a condition, this test fails instead
// of the filter silently returning the wrong set.
func TestGetVtxosRenewableIsUnionOfSpendableAndRecoverable(t *testing.T) {
	ctx := context.Background()
	fixtures := filterTestFixtures()

	all := make([]domain.Vtxo, 0, len(fixtures))
	for _, f := range fixtures {
		all = append(all, f.vtxo)
	}
	pubkeys := []string{filterTestPubkey}

	get := func(spendable, recoverable, renewable bool) []domain.Vtxo {
		t.Helper()
		svc := newFilterTestIndexer(all)
		resp, err := svc.GetVtxos(
			ctx, pubkeys, spendable, false, recoverable, false, renewable, 0, 0, nil,
		)
		require.NoError(t, err)
		return resp.Vtxos
	}

	spendable := get(true, false, false)
	recoverable := get(false, true, false)
	renewable := get(false, false, true)

	// Each filter matches the hand-labelled expectation.
	wantSpendable := make([]string, 0)
	wantRecoverable := make([]string, 0)
	union := make(map[string]struct{})
	for _, f := range fixtures {
		key := f.vtxo.Outpoint.String()
		if f.spendable {
			wantSpendable = append(wantSpendable, key)
			union[key] = struct{}{}
		}
		if f.recoverable {
			wantRecoverable = append(wantRecoverable, key)
			union[key] = struct{}{}
		}
	}
	require.ElementsMatch(t, wantSpendable, outpointsOf(spendable), "spendableOnly")
	require.ElementsMatch(t, wantRecoverable, outpointsOf(recoverable), "recoverableOnly")

	wantUnion := make([]string, 0, len(union))
	for key := range union {
		wantUnion = append(wantUnion, key)
	}
	require.ElementsMatch(t, wantUnion, outpointsOf(renewable), "renewableOnly must be the union")

	// And the union is exactly the unspent, non-unrolled vtxos.
	wantRenewable := make([]string, 0)
	for _, f := range fixtures {
		if !f.vtxo.Spent && !f.vtxo.Unrolled {
			wantRenewable = append(wantRenewable, f.vtxo.Outpoint.String())
		}
	}
	require.ElementsMatch(t, wantRenewable, outpointsOf(renewable))
}

// TestGetVtxosFiltersAreMutuallyExclusive covers the service-level guard, which
// is enforced independently of the gRPC handler.
func TestGetVtxosFiltersAreMutuallyExclusive(t *testing.T) {
	ctx := context.Background()
	pubkeys := []string{filterTestPubkey}

	tests := []struct {
		name                                              string
		spendable, spent, recoverable, pending, renewable bool
	}{
		{"spendable and renewable", true, false, false, false, true},
		{"spent and renewable", false, true, false, false, true},
		{"recoverable and renewable", false, false, true, false, true},
		{"pending and renewable", false, false, false, true, true},
		{"spendable and spent", true, true, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newFilterTestIndexer(nil)
			_, err := svc.GetVtxos(
				ctx, pubkeys,
				tt.spendable, tt.spent, tt.recoverable, tt.pending, tt.renewable,
				0, 0, nil,
			)
			require.ErrorContains(t, err, "mutually exclusive")
		})
	}
}

// TestGetVtxosRenewableExcludesSpentAndUnrolled guards the two flags the filter
// actually tests, independently of the union invariant above.
func TestGetVtxosRenewableExcludesSpentAndUnrolled(t *testing.T) {
	ctx := context.Background()
	all := []domain.Vtxo{
		filterTestVtxo("b1", false, false, false, false, false),
		filterTestVtxo("b2", true, false, false, false, false),
		filterTestVtxo("b3", false, false, true, false, false),
	}

	svc := newFilterTestIndexer(all)
	resp, err := svc.GetVtxos(
		ctx, []string{filterTestPubkey}, false, false, false, false, true, 0, 0, nil,
	)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"b1:0"}, outpointsOf(resp.Vtxos))
}
