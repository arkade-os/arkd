package application

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAdminGetCollectedFees(t *testing.T) {
	ctx := t.Context()

	repo := &mockedRoundRepo{}
	repo.On("SumCollectedFees", mock.Anything, int64(100), int64(200)).
		Return(uint64(5200), nil)

	rm := &mockedRepoManager{}
	rm.On("Rounds").Return(repo)

	// The endpoint is now a single aggregate over what storage holds: no round is
	// loaded, no wallet is touched.
	svc := &adminService{repoManager: rm, walletSvc: &mockedWallet{}}
	total, err := svc.GetCollectedFees(ctx, 100, 200)
	require.NoError(t, err)
	require.Equal(t, uint64(5200), total)

	repo.AssertNotCalled(t, "GetRoundWithId", mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
}

func (m *mockedRoundRepo) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*domain.Round), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockedRoundRepo) SumCollectedFees(
	ctx context.Context, after, before int64,
) (uint64, error) {
	args := m.Called(ctx, after, before)
	return args.Get(0).(uint64), args.Error(1)
}

func mockIntent(in, out uint64) map[string]domain.Intent {
	return map[string]domain.Intent{
		"i": {
			Inputs:    []domain.Vtxo{{Amount: in}},
			Receivers: []domain.Receiver{{Amount: out}},
		},
	}
}
