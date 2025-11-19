package redislivestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	currentRoundKey      = "currentRoundStore:round"
	boardingInputsKey    = "boardingInputsStore:numOfInputs"
	boardingInputSigsKey = "boardingInputsStore:signatures"
)

type currentRoundStore struct {
	rdb          *redis.Client
	numOfRetries int
}

type boardingInputsStore struct {
	rdb          *redis.Client
	numOfRetries int
}

func NewCurrentRoundStore(rdb *redis.Client, numOfRetries int) ports.CurrentRoundStore {
	return &currentRoundStore{rdb: rdb, numOfRetries: numOfRetries}
}

func (s *currentRoundStore) Upsert(
	ctx context.Context, fn func(m *domain.Round) *domain.Round,
) (err error) {
	for attempt := 0; attempt < s.numOfRetries; attempt++ {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			updated := fn(s.Get(ctx))
			val, err := json.Marshal(updated)
			if err != nil {
				return err
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, currentRoundKey, val, 0)
				return nil
			})

			return err
		}); err == nil {
			return nil
		}
	}
	return err
}

func (s *currentRoundStore) Get(ctx context.Context) *domain.Round {
	data, err := s.rdb.Get(ctx, currentRoundKey).Bytes()
	if err != nil {
		return nil
	}

	type roundAlias domain.Round
	var temp struct {
		roundAlias
		Changes []json.RawMessage `json:"Changes"` // use the exported field name
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		log.Warnf("failed to unmarshal round: %s", err)
		return nil
	}

	var events []domain.Event
	for _, raw := range temp.Changes {
		var probe map[string]interface{}
		if err := json.Unmarshal(raw, &probe); err != nil {
			log.Warnf("failed to unmarshal event: %s", err)
			return nil
		}

		var evt domain.Event
		rawType, ok := probe["Type"]
		if !ok {
			log.Warnf("failed to unmarshal event: missing type")
			return nil
		}
		var eventType domain.EventType
		switch v := rawType.(type) {
		case float64:
			eventType = domain.EventType(int(v))
		case string:
			atoi, err := strconv.Atoi(v)
			if err != nil {
				log.Warnf("failed to unmarshal event: %s", err)
				return nil
			}
			eventType = domain.EventType(atoi)
		default:
			log.Warnf("failed to unmarshal event: unknown type")
			return nil
		}
		switch eventType {
		case domain.EventTypeRoundStarted:
			var e domain.RoundStarted
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeRoundFinalizationStarted:
			var e domain.RoundFinalizationStarted
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeRoundFinalized:
			var e domain.RoundFinalized
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeRoundFailed:
			var e domain.RoundFailed
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		case domain.EventTypeIntentsRegistered:
			var e domain.IntentsRegistered
			if err := json.Unmarshal(raw, &e); err != nil {
				log.Warnf("failed to unmarshal round started: %s", err)
				return nil
			}
			evt = e
		default:
			continue
		}
		events = append(events, evt)
	}

	round := domain.Round(temp.roundAlias)
	round.Changes = events

	return &round
}

func (s *currentRoundStore) Fail(ctx context.Context, err error) []domain.Event {
	var events []domain.Event
	if err := s.Upsert(ctx, func(m *domain.Round) *domain.Round {
		m.Fail(err)
		return m
	}); err != nil {
		log.Warnf("fail: failed to upsert round: %s", err)
		return nil
	}

	round := s.Get(ctx)
	if round == nil {
		return nil
	}
	events = append(events, round.Events()...)

	return events
}

func NewBoardingInputsStore(rdb *redis.Client, numOfRetries int) ports.BoardingInputsStore {
	return &boardingInputsStore{rdb: rdb, numOfRetries: numOfRetries}
}

func (b *boardingInputsStore) Set(numOfInputs int) {
	ctx := context.Background()
	b.rdb.Set(ctx, boardingInputsKey, numOfInputs, 0)
}

func (b *boardingInputsStore) Get() int {
	ctx := context.Background()
	num, err := b.rdb.Get(ctx, boardingInputsKey).Int()
	if err != nil {
		return 0
	}
	return num
}

func (b *boardingInputsStore) AddSignatures(
	ctx context.Context, batchId string, inputSigs map[uint32]ports.SignedBoardingInput,
) (err error) {
	key := fmt.Sprintf("%s:%s", boardingInputSigsKey, batchId)

	// Prepare arguments first so serialization errors happen before the transaction
	type fieldVal struct {
		field string
		value string
	}
	fields := make([]fieldVal, 0, len(inputSigs))

	for inIndex, sig := range inputSigs {
		field := fmt.Sprintf("%d", inIndex)
		value, err := newSigsDTO(sig).serialize()
		if err != nil {
			return err
		}
		fields = append(fields, fieldVal{field, string(value)})
	}

	// Transactional update with retry logic
	for range b.numOfRetries {
		if err = b.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := b.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				for _, fv := range fields {
					pipe.HSetNX(ctx, key, fv.field, fv.value)
				}
				return nil
			})
			return err
		}); err == nil {
			return nil
		}
		<-time.After(100 * time.Millisecond)
	}

	return err
}

func (b *boardingInputsStore) GetSignatures(
	ctx context.Context, batchId string,
) (map[uint32]ports.SignedBoardingInput, error) {
	key := fmt.Sprintf("%s:%s", boardingInputSigsKey, batchId)
	values, err := b.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	m := make(map[uint32]ports.SignedBoardingInput)
	for key, value := range values {
		rawSig := &sigsDTO{}
		sig, err := rawSig.deserialize([]byte(value))
		if err != nil {
			return nil, err
		}
		inIndex, err := strconv.Atoi(key)
		if err != nil {
			return nil, err
		}

		m[uint32(inIndex)] = *sig
	}
	return m, nil
}

func (b *boardingInputsStore) DeleteSignatures(ctx context.Context, batchId string) error {
	key := fmt.Sprintf("%s:%s", boardingInputSigsKey, batchId)
	return b.rdb.Del(ctx, key).Err()
}

type sigDTO struct {
	XOnlyPubKey string `json:"xOnlyPubkey"`
	LeafHash    string `json:"leafHash"`
	Signature   string `json:"signature"`
	SigHash     uint32 `json:"sighash"`
}

type leafScriptDTO struct {
	ControlBlock string `json:"controlBlock"`
	Script       string `json:"script"`
	LeafVersion  uint32 `json:"leafVersion"`
}

type sigsDTO struct {
	Signatures []sigDTO      `json:"signatures"`
	LeafScript leafScriptDTO `json:"leafScript"`
}

func newSigsDTO(in ports.SignedBoardingInput) sigsDTO {
	sigs := make([]sigDTO, 0, len(in.Signatures))
	for _, s := range in.Signatures {
		sigs = append(sigs, sigDTO{
			XOnlyPubKey: hex.EncodeToString(s.XOnlyPubKey),
			LeafHash:    hex.EncodeToString(s.LeafHash),
			Signature:   hex.EncodeToString(s.Signature),
			SigHash:     uint32(s.SigHash),
		})
	}
	leafScript := leafScriptDTO{
		ControlBlock: hex.EncodeToString(in.LeafScript.ControlBlock),
		Script:       hex.EncodeToString(in.LeafScript.Script),
		LeafVersion:  uint32(in.LeafScript.LeafVersion),
	}
	return sigsDTO{
		Signatures: sigs,
		LeafScript: leafScript,
	}
}

func (s sigsDTO) serialize() ([]byte, error) {
	return json.Marshal(s)
}

func (s sigsDTO) deserialize(buf []byte) (*ports.SignedBoardingInput, error) {
	if err := json.Unmarshal(buf, &s); err != nil {
		return nil, err
	}

	sigs := make([]*psbt.TaprootScriptSpendSig, 0, len(s.Signatures))
	for _, rawSig := range s.Signatures {
		xOnlyPubkey, err := hex.DecodeString(rawSig.XOnlyPubKey)
		if err != nil {
			return nil, err
		}
		leafHash, err := hex.DecodeString(rawSig.LeafHash)
		if err != nil {
			return nil, err
		}
		sig, err := hex.DecodeString(rawSig.Signature)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: xOnlyPubkey,
			LeafHash:    leafHash,
			Signature:   sig,
			SigHash:     txscript.SigHashType(rawSig.SigHash),
		})
	}
	cb, err := hex.DecodeString(s.LeafScript.ControlBlock)
	if err != nil {
		return nil, err
	}
	script, err := hex.DecodeString(s.LeafScript.Script)
	if err != nil {
		return nil, err
	}
	return &ports.SignedBoardingInput{
		Signatures: sigs,
		LeafScript: &psbt.TaprootTapLeafScript{
			ControlBlock: cb,
			Script:       script,
			LeafVersion:  txscript.TapscriptLeafVersion(s.LeafScript.LeafVersion),
		},
	}, nil
}
