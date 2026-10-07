package db_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestService only covers sqlite and postgres, so the badger round lookups are checked here.
func TestRoundRepositoryBadger(t *testing.T) {
	svc, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "badger",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{t.TempDir(), nil},
		Settings:         validSettings(),
	}, nil)
	require.NoError(t, err)
	defer svc.Close()

	t.Run("rounds with commitment txids", func(t *testing.T) {
		ctx := t.Context()
		round := domain.Round{
			Id:             uuid.New().String(),
			CommitmentTxid: randomString(32),
			Stage:          domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
		}
		require.NoError(t, svc.Rounds().AddOrUpdateRound(ctx, round))

		got, err := svc.Rounds().GetRoundsWithCommitmentTxids(
			ctx, []string{round.CommitmentTxid, randomString(32)},
		)
		require.NoError(t, err)
		require.Equal(t, map[string]any{round.CommitmentTxid: nil}, got)
	})
}
