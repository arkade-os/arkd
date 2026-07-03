package redislivestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/redis/go-redis/v9"
)

const (
	settingsKey = "settings"
)

type settingsStore struct {
	rdb          *redis.Client
	numOfRetries int
	retryDelay   time.Duration
}

func NewSettingsStore(rdb *redis.Client, numOfRetries int) ports.SettingsStore {
	return &settingsStore{
		rdb:          rdb,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

func (s *settingsStore) Upsert(ctx context.Context, settings ports.Settings) error {
	data := newSettingsDTO(settings)
	val, err := json.Marshal(data)
	if err != nil {
		return err
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, settingsKey, val, 0)
				return nil
			})

			return err
		}, settingsKey); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to add or update settings after max number of retries: %v", err)
}

func (s *settingsStore) Get(ctx context.Context) (*ports.Settings, error) {
	data, err := s.rdb.Get(ctx, settingsKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get settings: %v", err)
	}

	var dto settingsDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("malformed settings in storage (out=%s): %s", string(data), err)
	}

	settings, err := dto.parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse settings from cache: %w", err)
	}
	return settings, nil
}

func (s *settingsStore) UpdateLastBatch(ctx context.Context, at time.Time, id string) error {
	var lastBatchAt int64
	if !at.IsZero() {
		lastBatchAt = at.Unix()
	}

	// LastBatchAt/LastBatchId are stored inside the single settings blob, so we
	// read-modify-write it under a WATCH to update just those two fields while
	// preserving everything else, retrying on optimistic-lock contention.
	var err error
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, settingsKey).Bytes()
			if err != nil {
				// No settings cached yet: there is nothing to attach the
				// last-batch metadata to, so skip rather than persist an
				// otherwise zero-value settings blob.
				if errors.Is(err, redis.Nil) {
					return nil
				}
				return fmt.Errorf("failed to get settings: %v", err)
			}

			var dto settingsDTO
			if err := json.Unmarshal(data, &dto); err != nil {
				return fmt.Errorf(
					"malformed settings in storage (out=%s): %s", string(data), err,
				)
			}
			dto.LastBatchAt = lastBatchAt
			dto.LastBatchId = id

			val, err := json.Marshal(dto)
			if err != nil {
				return err
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, settingsKey, val, 0)
				return nil
			})
			return err
		}, settingsKey); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to update last batch after max number of retries: %v", err)
}

type scheduledSessionDTO struct {
	StartTime                 int64
	EndTime                   int64
	Period                    int64
	Duration                  int64
	RoundMinParticipantsCount int64
	RoundMaxParticipantsCount int64
}

func newScheduledSessionDTO(session *domain.ScheduledSession) scheduledSessionDTO {
	if session == nil {
		return scheduledSessionDTO{}
	}

	return scheduledSessionDTO{
		StartTime:                 session.StartTime.Unix(),
		EndTime:                   session.EndTime.Unix(),
		Period:                    int64(session.Period.Seconds()),
		Duration:                  int64(session.Duration.Seconds()),
		RoundMinParticipantsCount: session.RoundMinParticipantsCount,
		RoundMaxParticipantsCount: session.RoundMaxParticipantsCount,
	}
}

func (s scheduledSessionDTO) parse() *domain.ScheduledSession {
	var empty scheduledSessionDTO
	if s == empty {
		return nil
	}
	return &domain.ScheduledSession{
		StartTime:                 time.Unix(s.StartTime, 0),
		EndTime:                   time.Unix(s.EndTime, 0),
		Period:                    time.Duration(s.Period) * time.Second,
		Duration:                  time.Duration(s.Duration) * time.Second,
		RoundMinParticipantsCount: s.RoundMinParticipantsCount,
		RoundMaxParticipantsCount: s.RoundMaxParticipantsCount,
	}
}

type batchFeesDTO = domain.BatchFees

type deprecatedSignerDTO struct {
	PubKey string
	// unix timestamp after which the key is no longer accepted, 0 if unset
	CutoffDate int64
}

type settingsDTO struct {
	SessionDuration               int64
	UnrolledVtxoMinExpiryMargin   int64
	BanThreshold                  uint64
	BanDuration                   int64
	UnilateralExitDelay           int64
	PublicUnilateralExitDelay     int64
	CheckpointExitDelay           int64
	BoardingExitDelay             int64
	VtxoTreeExpiry                int64
	RoundMinParticipantsCount     int64
	RoundMaxParticipantsCount     int64
	VtxoMinAmount                 int64
	VtxoMaxAmount                 int64
	UtxoMinAmount                 int64
	UtxoMaxAmount                 int64
	SettlementMinExpiryGap        int64
	VtxoNoCsvValidationCutoffDate int64
	MaxTxWeight                   uint64
	MaxOpReturnOutputs            uint64
	AssetTxMaxWeightRatio         float32
	NoteUriPrefix                 string
	BuildVersionHeader            string
	BuildVersionHeaderRequired    bool
	DigestHeaderRequired          bool
	ScheduledSession              scheduledSessionDTO
	BatchFees                     batchFeesDTO
	Network                       string
	DustAmount                    uint64
	SignerPubkey                  string
	DeprecatedSignerPubkeys       []deprecatedSignerDTO
	ForfeitPubkey                 string
	ForfeitAddress                string
	CheckpointTapscript           string
	LastBatchAt                   int64
	LastBatchId                   string
}

func newSettingsDTO(settings ports.Settings) settingsDTO {
	var vtxoNoCsvValidationCutoffDate int64
	if !settings.VtxoNoCsvValidationCutoffDate.IsZero() {
		vtxoNoCsvValidationCutoffDate = settings.VtxoNoCsvValidationCutoffDate.Unix()
	}
	var signerPubkey string
	if settings.SignerPubkey != nil {
		signerPubkey = hex.EncodeToString(settings.SignerPubkey.SerializeCompressed())
	}
	var forfeitPubkey string
	if settings.ForfeitPubkey != nil {
		forfeitPubkey = hex.EncodeToString(settings.ForfeitPubkey.SerializeCompressed())
	}

	deprecatedSignerPubkeys := make([]deprecatedSignerDTO, 0, len(settings.DeprecatedSignerPubkeys))
	for _, deprecated := range settings.DeprecatedSignerPubkeys {
		if deprecated.PubKey == nil {
			continue
		}
		var cutoffDate int64
		if !deprecated.CutoffDate.IsZero() {
			cutoffDate = deprecated.CutoffDate.Unix()
		}
		deprecatedSignerPubkeys = append(deprecatedSignerPubkeys, deprecatedSignerDTO{
			PubKey:     hex.EncodeToString(deprecated.PubKey.SerializeCompressed()),
			CutoffDate: cutoffDate,
		})
	}

	var lastBatchAt int64
	if !settings.LastBatchAt.IsZero() {
		lastBatchAt = settings.LastBatchAt.Unix()
	}

	return settingsDTO{
		SessionDuration:               int64(settings.SessionDuration.Seconds()),
		UnrolledVtxoMinExpiryMargin:   int64(settings.UnrolledVtxoMinExpiryMargin.Seconds()),
		BanThreshold:                  settings.BanThreshold,
		BanDuration:                   int64(settings.BanDuration.Seconds()),
		UnilateralExitDelay:           settings.UnilateralExitDelay.Seconds(),
		PublicUnilateralExitDelay:     settings.PublicUnilateralExitDelay.Seconds(),
		CheckpointExitDelay:           settings.CheckpointExitDelay.Seconds(),
		BoardingExitDelay:             settings.BoardingExitDelay.Seconds(),
		VtxoTreeExpiry:                settings.VtxoTreeExpiry.Seconds(),
		RoundMinParticipantsCount:     settings.RoundMinParticipantsCount,
		RoundMaxParticipantsCount:     settings.RoundMaxParticipantsCount,
		VtxoMinAmount:                 settings.VtxoMinAmount,
		VtxoMaxAmount:                 settings.VtxoMaxAmount,
		UtxoMinAmount:                 settings.UtxoMinAmount,
		UtxoMaxAmount:                 settings.UtxoMaxAmount,
		SettlementMinExpiryGap:        int64(settings.SettlementMinExpiryGap.Seconds()),
		VtxoNoCsvValidationCutoffDate: vtxoNoCsvValidationCutoffDate,
		MaxTxWeight:                   settings.MaxTxWeight,
		MaxOpReturnOutputs:            settings.MaxOpReturnOutputs,
		AssetTxMaxWeightRatio:         settings.AssetTxMaxWeightRatio,
		NoteUriPrefix:                 settings.NoteUriPrefix,
		BuildVersionHeader:            settings.BuildVersionHeader,
		BuildVersionHeaderRequired:    settings.BuildVersionHeaderRequired,
		DigestHeaderRequired:          settings.DigestHeaderRequired,
		BatchFees:                     settings.BatchFees,
		Network:                       settings.Network.Name,
		DustAmount:                    settings.DustAmount,
		SignerPubkey:                  signerPubkey,
		DeprecatedSignerPubkeys:       deprecatedSignerPubkeys,
		ForfeitPubkey:                 forfeitPubkey,
		ForfeitAddress:                settings.ForfeitAddress,
		CheckpointTapscript:           hex.EncodeToString(settings.CheckpointTapscript),
		ScheduledSession:              newScheduledSessionDTO(settings.ScheduledSession),
		LastBatchAt:                   lastBatchAt,
		LastBatchId:                   settings.LastBatchId,
	}
}

func (s settingsDTO) parse() (*ports.Settings, error) {
	signerPubkey, err := parsePubkey(s.SignerPubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signer pubkey: %w", err)
	}
	forfeitPubkey, err := parsePubkey(s.ForfeitPubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse forfeit pubkey: %w", err)
	}
	deprecatedSignerPubkeys := make(
		[]ports.DeprecatedSignerPubkey,
		0,
		len(s.DeprecatedSignerPubkeys),
	)
	for _, deprecated := range s.DeprecatedSignerPubkeys {
		pubkey, err := parsePubkey(deprecated.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse deprecated signer pubkey: %w", err)
		}
		var cutoffDate time.Time
		if deprecated.CutoffDate > 0 {
			cutoffDate = time.Unix(deprecated.CutoffDate, 0)
		}
		deprecatedSignerPubkeys = append(deprecatedSignerPubkeys, ports.DeprecatedSignerPubkey{
			PubKey:     pubkey,
			CutoffDate: cutoffDate,
		})
	}
	checkpointTapscript, err := hex.DecodeString(s.CheckpointTapscript)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint tapscript: %w", err)
	}
	var vtxoNoCsvValidationCutoffDate time.Time
	if s.VtxoNoCsvValidationCutoffDate > 0 {
		vtxoNoCsvValidationCutoffDate = time.Unix(s.VtxoNoCsvValidationCutoffDate, 0)
	}
	unilateralExitDelay, _ := arklib.ParseRelativeLocktime(uint32(s.UnilateralExitDelay))
	publicUnilateralExitDelay, _ := arklib.ParseRelativeLocktime(
		uint32(s.PublicUnilateralExitDelay),
	)
	checkpointExitDelay, _ := arklib.ParseRelativeLocktime(uint32(s.CheckpointExitDelay))
	boardingExitDelay, _ := arklib.ParseRelativeLocktime(uint32(s.BoardingExitDelay))
	vtxoTreeExpiry, _ := arklib.ParseRelativeLocktime(uint32(s.VtxoTreeExpiry))
	unrolledVtxoMinExpiryMargin := time.Duration(s.UnrolledVtxoMinExpiryMargin) * time.Second
	var lastBatchAt time.Time
	if s.LastBatchAt > 0 {
		lastBatchAt = time.Unix(s.LastBatchAt, 0)
	}
	return &ports.Settings{
		Settings: domain.Settings{
			SessionDuration:               time.Duration(s.SessionDuration) * time.Second,
			UnrolledVtxoMinExpiryMargin:   unrolledVtxoMinExpiryMargin,
			BanThreshold:                  s.BanThreshold,
			BanDuration:                   time.Duration(s.BanDuration) * time.Second,
			UnilateralExitDelay:           unilateralExitDelay,
			PublicUnilateralExitDelay:     publicUnilateralExitDelay,
			CheckpointExitDelay:           checkpointExitDelay,
			BoardingExitDelay:             boardingExitDelay,
			VtxoTreeExpiry:                vtxoTreeExpiry,
			RoundMinParticipantsCount:     s.RoundMinParticipantsCount,
			RoundMaxParticipantsCount:     s.RoundMaxParticipantsCount,
			VtxoMinAmount:                 s.VtxoMinAmount,
			VtxoMaxAmount:                 s.VtxoMaxAmount,
			UtxoMinAmount:                 s.UtxoMinAmount,
			UtxoMaxAmount:                 s.UtxoMaxAmount,
			SettlementMinExpiryGap:        time.Duration(s.SettlementMinExpiryGap) * time.Second,
			VtxoNoCsvValidationCutoffDate: vtxoNoCsvValidationCutoffDate,
			MaxTxWeight:                   s.MaxTxWeight,
			MaxOpReturnOutputs:            s.MaxOpReturnOutputs,
			AssetTxMaxWeightRatio:         s.AssetTxMaxWeightRatio,
			NoteUriPrefix:                 s.NoteUriPrefix,
			BuildVersionHeader:            s.BuildVersionHeader,
			BuildVersionHeaderRequired:    s.BuildVersionHeaderRequired,
			DigestHeaderRequired:          s.DigestHeaderRequired,
			ScheduledSession:              s.ScheduledSession.parse(),
			BatchFees:                     s.BatchFees,
		},
		Network:                 networkFromString(s.Network),
		DustAmount:              s.DustAmount,
		SignerPubkey:            signerPubkey,
		DeprecatedSignerPubkeys: deprecatedSignerPubkeys,
		ForfeitPubkey:           forfeitPubkey,
		ForfeitAddress:          s.ForfeitAddress,
		CheckpointTapscript:     checkpointTapscript,
		LastBatchAt:             lastBatchAt,
		LastBatchId:             s.LastBatchId,
	}, nil
}

func networkFromString(net string) arklib.Network {
	switch net {
	case arklib.BitcoinTestNet.Name:
		return arklib.BitcoinTestNet
	case arklib.BitcoinTestNet4.Name:
		return arklib.BitcoinTestNet4
	case arklib.BitcoinSigNet.Name:
		return arklib.BitcoinSigNet
	case arklib.BitcoinMutinyNet.Name:
		return arklib.BitcoinMutinyNet
	case arklib.BitcoinRegTest.Name:
		return arklib.BitcoinRegTest
	case arklib.Bitcoin.Name:
		fallthrough
	default:
		return arklib.Bitcoin
	}
}

func parsePubkey(key string) (*btcec.PublicKey, error) {
	if len(key) <= 0 {
		return nil, nil
	}
	buf, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid format, expected hex got %s", key)
	}
	return btcec.ParsePubKey(buf)
}
