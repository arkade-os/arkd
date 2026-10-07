package watermilldb_test

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestClose(t *testing.T) {
	startedRoundEvents := func(id string) []domain.Event {
		return []domain.Event{
			domain.RoundStarted{
				RoundEvent: domain.RoundEvent{Id: id, Type: domain.EventTypeRoundStarted},
				Timestamp:  time.Now().Unix(),
			},
		}
	}

	tests := []struct {
		name string
		// inFlight holds a dispatched handler open when Close is called.
		inFlight bool
	}{
		{
			name: "no inflight handlers",
		},
		{
			name:     "inflight handler",
			inFlight: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := pgdb.OpenDb(pgEventConnect(t), false)
			require.NoError(t, err)
			// nolint:errcheck
			t.Cleanup(func() { db.Close() })

			repo, err := pgdb.NewEventRepository(db)
			require.NoError(t, err)
			t.Cleanup(repo.Close)

			release := make(chan struct{})
			if tt.inFlight {
				entered := make(chan struct{})
				repo.RegisterEventsHandler(domain.RoundTopic, func([]domain.Event) {
					close(entered)
					<-release
				})

				id := uuid.New().String()
				require.NoError(t, repo.Save(t.Context(), domain.RoundTopic, id, startedRoundEvents(id)))

				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "the saved events were never dispatched to the handler")
				}
			}

			closed := make(chan struct{})
			go func() {
				defer close(closed)
				repo.Close()
			}()

			if tt.inFlight {
				select {
				case <-closed:
					require.FailNow(t, "Close returned while a handler was still running")
				case <-time.After(100 * time.Millisecond):
				}
				close(release)
			}

			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				require.FailNow(t, "Close did not return")
			}

			// The publisher is closed, so no event can be saved and dispatched anymore.
			id := uuid.New().String()
			require.Error(t, repo.Save(t.Context(), domain.RoundTopic, id, startedRoundEvents(id)))
		})
	}
}

// pgEventConnect returns the DSN of the event database of this package in the postgres container
// started by `make pgtest`, creating it if it does not exist yet. The other packages reset the
// databases they use, and packages run in parallel, so this one has a database of its own.
func pgEventConnect(t *testing.T) string {
	t.Helper()
	const dsn = "postgresql://root:secret@127.0.0.1:5432/%s?sslmode=disable"
	const name = "watermill_events"
	admin, err := sql.Open("postgres", fmt.Sprintf(dsn, "event"))
	require.NoError(t, err)
	defer func() { _ = admin.Close() }()

	var exists bool
	require.NoError(t, admin.QueryRow(
		"SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name,
	).Scan(&exists))
	if !exists {
		_, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name))
		require.NoError(t, err)
	}
	return fmt.Sprintf(dsn, name)
}
