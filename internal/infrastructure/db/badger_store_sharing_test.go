package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	"github.com/stretchr/testify/require"
)

func TestBadgerStoreIsPerService(t *testing.T) {
	ctx := context.Background()

	t.Run("a closed service does not poison the next one", func(t *testing.T) {
		// The ark repository used to be memoized in a package-level var, so the
		// store outlived the service that opened it and every later service in
		// the process inherited the closed handle, failing with "DB Closed".
		newBadgerService(t, t.TempDir()).Close()

		second := newBadgerService(t, t.TempDir())
		defer second.Close()

		_, err := second.OffchainTxs().GetOffchainTxs(ctx, domain.OffchainTxFilter{})
		require.NoError(t, err)
	})

	t.Run("each service reads its own directory", func(t *testing.T) {
		// Memoizing ignored the directory argument, so a second service opened
		// against another directory silently served the first one's data.
		svcA := newBadgerService(t, t.TempDir())
		arkTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		require.NoError(t, svcA.OffchainTxs().AddOrUpdateOffchainTx(
			ctx, acceptedOffchainTx(arkTxid),
		))
		stored, err := svcA.OffchainTxs().GetOffchainTxs(
			ctx, domain.OffchainTxFilter{WithTxids: []string{arkTxid}},
		)
		require.NoError(t, err)
		require.Len(t, stored, 1, "sanity: the first service stored it")
		svcA.Close()

		svcB := newBadgerService(t, t.TempDir())
		defer svcB.Close()

		got, err := svcB.OffchainTxs().GetOffchainTxs(
			ctx, domain.OffchainTxFilter{WithTxids: []string{arkTxid}},
		)
		require.NoError(t, err)
		require.Empty(t, got, "a fresh directory must not see the other service's tx")
	})

	t.Run("round and offchain stores are one object", func(t *testing.T) {
		// badger locks its directory, so both slots have to be backed by the
		// same badgerhold store rather than two opened against the same path.
		svc := newBadgerService(t, t.TempDir())
		defer svc.Close()

		require.Same(t, any(svc.Rounds()), any(svc.OffchainTxs()))
	})
}

// --- helpers ---

func newBadgerService(t *testing.T, dir string) ports.RepoManager {
	t.Helper()
	svc, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "badger",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{dir, nil},
		Settings:         validSettings(),
	}, nil)
	require.NoError(t, err)
	return svc
}

// acceptedOffchainTx builds an offchain tx at the accepted stage, which is what
// GetOffchainTxs exposes.
func acceptedOffchainTx(arkTxid string) *domain.OffchainTx {
	checkpointTxid := "0000000000000000000000000000000000000000000000000000000000000001"
	return domain.NewOffchainTxFromEvents([]domain.Event{
		domain.OffchainTxRequested{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxRequested,
			},
			ArkTx:                 randomTx(),
			UnsignedCheckpointTxs: map[string]string{checkpointTxid: randomTx()},
			StartingTimestamp:     time.Now().Unix(),
		},
		domain.OffchainTxAccepted{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxAccepted,
			},
			CommitmentTxids:     map[string]string{checkpointTxid: randomString(32)},
			FinalArkTx:          randomTx(),
			SignedCheckpointTxs: map[string]string{checkpointTxid: randomTx()},
			RootCommitmentTxid:  randomString(32),
			ExpiryTimestamp:     time.Now().Add(time.Hour).Unix(),
		},
	})
}
