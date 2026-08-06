package application

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/require"
)

func TestCheckIfBanned(t *testing.T) {
	ctx := t.Context()
	script := mockOutputScript{0x51}

	t.Run("huge threshold does not ban a script with no convictions", func(t *testing.T) {
		// A negative ban threshold stored before validation existed reaches us as a
		// huge uint64: it must not wrap and ban everyone.
		svc := &service{repoManager: &mockedBanRepoManager{}}
		require.NoError(t, svc.checkIfBanned(ctx, ^uint64(0), script))
	})

	t.Run("threshold reached bans the script", func(t *testing.T) {
		svc := &service{repoManager: &mockedBanRepoManager{
			convictions: []domain.ScriptConviction{{}, {}},
		}}
		require.ErrorContains(t, svc.checkIfBanned(ctx, 2, script), "is banned by 2 convictions")
	})

	t.Run("zero threshold disables banning", func(t *testing.T) {
		svc := &service{repoManager: &mockedBanRepoManager{
			convictions: []domain.ScriptConviction{{}, {}},
		}}
		require.NoError(t, svc.checkIfBanned(ctx, 0, script))
	})
}

type mockOutputScript []byte

func (s mockOutputScript) OutputScript() ([]byte, error) {
	return s, nil
}

type mockedBanRepoManager struct {
	ports.RepoManager // unimplemented methods panic on call
	convictions       []domain.ScriptConviction
}

func (m *mockedBanRepoManager) Convictions() domain.ConvictionRepository {
	return &mockedConvictionRepo{convictions: m.convictions}
}

type mockedConvictionRepo struct {
	domain.ConvictionRepository // unimplemented methods panic on call
	convictions                 []domain.ScriptConviction
}

func (m *mockedConvictionRepo) GetActiveScriptConvictions(
	ctx context.Context, script string,
) ([]domain.ScriptConviction, error) {
	return m.convictions, nil
}
