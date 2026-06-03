package application

import (
	"context"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func (m *mockedRoundRepo) GetRoundIds(
	ctx context.Context, startedAfter, startedBefore int64, withFailed, withCompleted bool,
) ([]string, error) {
	args := m.Called(ctx, startedAfter, startedBefore, withFailed, withCompleted)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*domain.Round), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) PatchCollectedFees(
	ctx context.Context, feesByRoundId map[string]uint64,
) error {
	return m.Called(ctx, feesByRoundId).Error(0)
}

func TestAdminGetCollectedFees(t *testing.T) {
	ctx := t.Context()

	feeIntent := func(in, out uint64) map[string]domain.Intent {
		return map[string]domain.Intent{
			"i": {
				Inputs:    []domain.Vtxo{{Amount: in}},
				Receivers: []domain.Receiver{{Amount: out}},
			},
		}
	}

	rounds := []*domain.Round{
		// new round, fee persisted -> use stored value.
		{
			Id:            "new-positive",
			CollectedFees: 5000,
		},
		// round with a genuine zero fee -> NOT patched (stays 0)
		{
			Id:            "zero-fee-unpatched",
			CollectedFees: 0,
			Intents:       feeIntent(10000, 10000),
		},
		// old round, zero (unpersisted) fee -> recomputed from intents: 200.
		{
			Id:            "zero-fee-patched",
			CollectedFees: 0,
			Intents:       feeIntent(10000, 9800),
		},
	}

	repo := &mockedRoundRepo{}
	ids := make([]string, len(rounds))
	for i, r := range rounds {
		ids[i] = r.Id
		repo.On("GetRoundWithId", mock.Anything, r.Id).Return(r, nil)
	}
	repo.On("GetRoundIds", mock.Anything, int64(0), int64(0), false, true).Return(ids, nil)

	// Only the old, recomputed, non-zero round is lazily patched. The patch
	// happens in a goroutine, so signal the test when it lands.
	patched := make(chan map[string]uint64, 1)
	repo.On("PatchCollectedFees", mock.Anything, mock.Anything).
		Return(nil).
		Run(func(args mock.Arguments) {
			patched <- args.Get(1).(map[string]uint64)
		})

	rm := &mockedRepoManager{}
	rm.On("Rounds").Return(repo)

	svc := &adminService{repoManager: rm}
	total, err := svc.GetCollectedFees(ctx, 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(5000+0+200), total)

	select {
	case got := <-patched:
		require.Equal(t, map[string]uint64{"zero-fee-patched": 200}, got)
	case <-time.After(2 * time.Second):
		t.Fatal("expected PatchCollectedFees to be called for the recomputed round")
	}

	repo.AssertExpectations(t)
}

func TestAdminGetCollectedFeesNoPatchWhenNotNeeded(t *testing.T) {
	ctx := t.Context()

	// One round with a persisted fee and one with a genuine zero fee (inputs ==
	// outputs): nothing to recompute to a non-zero value, so no patch is queued.
	rounds := []*domain.Round{
		{Id: "stored", CollectedFees: 3000},
		{
			Id:            "genuine-zero",
			CollectedFees: 0,
			Intents: map[string]domain.Intent{
				"i": {
					Inputs:    []domain.Vtxo{{Amount: 10000}},
					Receivers: []domain.Receiver{{Amount: 10000}},
				},
			},
		},
	}

	repo := &mockedRoundRepo{}
	ids := make([]string, len(rounds))
	for i, r := range rounds {
		ids[i] = r.Id
		repo.On("GetRoundWithId", mock.Anything, r.Id).Return(r, nil)
	}
	repo.On("GetRoundIds", mock.Anything, int64(0), int64(0), false, true).Return(ids, nil)

	rm := &mockedRepoManager{}
	rm.On("Rounds").Return(repo)

	svc := &adminService{repoManager: rm}
	total, err := svc.GetCollectedFees(ctx, 0, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(3000), total)

	// The patch is gated on a non-empty batch, so no goroutine is ever spawned.
	repo.AssertNotCalled(t, "PatchCollectedFees", mock.Anything, mock.Anything)
}
