package badgerdb

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
	"github.com/timshannon/badgerhold/v4"
)

const maxRetries = 5

func createDB(dbDir string, logger badger.Logger) (*badgerhold.Store, error) {
	isInMemory := len(dbDir) <= 0

	opts := badger.DefaultOptions(dbDir)
	opts.Logger = logger

	if isInMemory {
		opts.InMemory = true
	} else {
		opts.Compression = options.ZSTD
	}

	db, err := badgerhold.Open(badgerhold.Options{
		Encoder:          badgerhold.DefaultEncode,
		Decoder:          badgerhold.DefaultDecode,
		SequenceBandwith: 100,
		Options:          opts,
	})
	if err != nil {
		return nil, err
	}

	if !isInMemory {
		ticker := time.NewTicker(30 * time.Minute)

		go func() {
			for {
				<-ticker.C
				if err := db.Badger().RunValueLogGC(0.5); err != nil && err != badger.ErrNoRewrite {
					logger.Errorf("%s", err)
				}
			}
		}()
	}

	return db, nil
}

func serializeEvents(events []domain.Event) (*eventsDTO, error) {
	rawEvents := make([][]byte, 0, len(events))
	for _, event := range events {
		buf, err := serializeEvent(event)
		if err != nil {
			return nil, err
		}
		rawEvents = append(rawEvents, buf)
	}
	return &eventsDTO{rawEvents}, nil
}

func deserializeEvents(rawEvents [][]byte) ([]domain.Event, error) {
	events := make([]domain.Event, 0)
	for _, buf := range rawEvents {
		event, err := deserializeEvent(buf)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func serializeEvent(event domain.Event) ([]byte, error) {
	switch eventType := event.(type) {
	default:
		return json.Marshal(eventType)
	}
}

func deserializeEvent(buf []byte) (domain.Event, error) {
	var eventType struct {
		Type domain.EventType
	}

	if err := json.Unmarshal(buf, &eventType); err != nil {
		return nil, err
	}

	switch eventType.Type {
	case domain.EventTypeRoundStarted:
		var event = domain.RoundStarted{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeRoundFinalizationStarted:
		var event = domain.RoundFinalizationStarted{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeRoundFinalized:
		var event = domain.RoundFinalized{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeRoundFailed:
		var event = domain.RoundFailed{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeIntentsRegistered:
		var event = domain.IntentsRegistered{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxRequested:
		var event = domain.OffchainTxRequested{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxAccepted:
		var event = domain.OffchainTxAccepted{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxFinalized:
		var event = domain.OffchainTxFinalized{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxFailed:
		var event = domain.OffchainTxFailed{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	}

	return nil, fmt.Errorf("unknown event")
}
