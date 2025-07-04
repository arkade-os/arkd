package pgdb

import (
	"fmt"

	"database/sql"

	watermillSQL "github.com/ThreeDotsLabs/watermill-sql/v3/pkg/sql"
	"github.com/arkade-os/arkd/internal/core/domain"
	watermilldb "github.com/arkade-os/arkd/internal/infrastructure/db/watermill"
)

func NewEventRepository(config ...interface{}) (domain.EventRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}

	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open event repository: invalid config")
	}

	publisher, err := watermillSQL.NewPublisher(db,
		watermillSQL.PublisherConfig{
			SchemaAdapter:        watermillSQL.DefaultPostgreSQLSchema{},
			AutoInitializeSchema: true,
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot open event repository: %w", err)
	}

	return watermilldb.NewWatermillEventRepository(publisher), nil
}
