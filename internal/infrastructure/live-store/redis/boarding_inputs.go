package redislivestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/redis/go-redis/v9"
)

type boardingInputsStore struct {
	rdb          *redis.Client
	numOfRetries int
	retryDelay   time.Duration
}

func NewBoardingInputsStore(rdb *redis.Client, numOfRetries int) ports.BoardingInputsStore {
	return &boardingInputsStore{
		rdb:          rdb,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

func (b *boardingInputsStore) Set(ctx context.Context, numOfInputs int) error {
	var err error
	for range b.numOfRetries {
		if err = b.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, boardingInputsKey, numOfInputs, 0)
				return nil
			})
			return err
		}, boardingInputsKey); err == nil {
			return nil
		}
		time.Sleep(b.retryDelay)
	}
	return fmt.Errorf(
		"failed to update number of boarding inputs after max number of retries: %v", err,
	)
}

func (b *boardingInputsStore) Get(ctx context.Context) (int, error) {
	num, err := b.rdb.Get(ctx, boardingInputsKey).Int()
	if err != nil {
		return -1, err
	}
	return num, nil
}

func (b *boardingInputsStore) AddSignatures(
	ctx context.Context, batchId string, inputSigs map[uint32]ports.SignedBoardingInput,
) error {
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

	var err error
	for range b.numOfRetries {
		if err = b.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				for _, fv := range fields {
					pipe.HSetNX(ctx, key, fv.field, fv.value)
				}
				return nil
			})
			return err
		}, key); err == nil {
			return nil
		}
		time.Sleep(b.retryDelay)
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
			return nil, fmt.Errorf("malformed signatures for input %s in storage: %v", key, err)
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
