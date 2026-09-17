package watermilldb_test

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const pgEventDsn = "postgresql://root:secret@127.0.0.1:5432/event?sslmode=disable"

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
			db, err := pgdb.OpenDb(pgEventDsn, false)
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
