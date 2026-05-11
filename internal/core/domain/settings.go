package domain

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"
	"unicode"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

const (
	MinAllowedSequence = 512
	// MaxSatoshis is the maximum number of satoshis that can ever exist (21M BTC).
	MaxSatoshis = 21_000_000 * 1e8
)

// ErrInvalidSettings is returned when settings fail validation.
type ErrInvalidSettings struct {
	Reason string
}

func (e *ErrInvalidSettings) Error() string {
	return fmt.Sprintf("invalid settings: %s", e.Reason)
}

// ToRelativeLocktime converts a raw locktime value to a typed RelativeLocktime.
// Values >= MinAllowedSequence (512) are interpreted as seconds (BIP68
// time-based relative locktimes use 512-second granularity units), while values
// < 512 are interpreted as blocks. Config validation enforces that time-based
// values are multiples of 512.
func ToRelativeLocktime(locktime int64) arklib.RelativeLocktime {
	if locktime >= MinAllowedSequence {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: uint32(locktime)}
	}
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: uint32(locktime)}
}

type Settings struct {
	BanThreshold                  int64
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
	MaxTxWeight                   int64
	UpdatedAt                     time.Time
}

func (s Settings) Validate() error {
	if s.UnilateralExitDelay <= 0 {
		return &ErrInvalidSettings{"unilateral exit delay must be greater than 0"}
	}
	if s.BoardingExitDelay <= 0 {
		return &ErrInvalidSettings{"boarding exit delay must be greater than 0"}
	}
	if s.VtxoTreeExpiry <= 0 {
		return &ErrInvalidSettings{"vtxo tree expiry must be greater than 0"}
	}
	if s.BanThreshold < 1 {
		return &ErrInvalidSettings{"ban threshold must be at least 1"}
	}
	if s.BanDuration < 1 {
		return &ErrInvalidSettings{"ban duration must be at least 1"}
	}
	if s.RoundMinParticipantsCount < 1 {
		return &ErrInvalidSettings{"round min participants count must be at least 1"}
	}
	if s.RoundMaxParticipantsCount < s.RoundMinParticipantsCount {
		return &ErrInvalidSettings{
			"round max participants count must be >= round min participants count",
		}
	}
	if s.PublicUnilateralExitDelay < s.UnilateralExitDelay {
		return &ErrInvalidSettings{
			"public unilateral exit delay must be >= unilateral exit delay",
		}
	}
	if s.UnilateralExitDelay == s.BoardingExitDelay {
		return &ErrInvalidSettings{
			"unilateral exit delay and boarding exit delay must be different",
		}
	}
	if s.CheckpointExitDelay <= 0 {
		return &ErrInvalidSettings{"checkpoint exit delay must be greater than 0"}
	}
	if s.MaxTxWeight <= 0 {
		return &ErrInvalidSettings{"max tx weight must be greater than 0"}
	}
	if s.UnilateralExitDelay > math.MaxUint32 {
		return &ErrInvalidSettings{"unilateral exit delay exceeds maximum uint32 value"}
	}
	if s.BoardingExitDelay > math.MaxUint32 {
		return &ErrInvalidSettings{"boarding exit delay exceeds maximum uint32 value"}
	}
	if s.VtxoTreeExpiry > math.MaxUint32 {
		return &ErrInvalidSettings{"vtxo tree expiry exceeds maximum uint32 value"}
	}
	if s.CheckpointExitDelay > math.MaxUint32 {
		return &ErrInvalidSettings{"checkpoint exit delay exceeds maximum uint32 value"}
	}
	if s.VtxoMinAmount < -1 || s.VtxoMinAmount > MaxSatoshis {
		return &ErrInvalidSettings{"vtxo min amount must be -1 (dust) or between 0 and 21M BTC"}
	}
	if s.VtxoMaxAmount < -1 || s.VtxoMaxAmount > MaxSatoshis {
		return &ErrInvalidSettings{"vtxo max amount must be -1 (unset) or between 0 and 21M BTC"}
	}
	if s.UtxoMinAmount < -1 || s.UtxoMinAmount > MaxSatoshis {
		return &ErrInvalidSettings{"utxo min amount must be -1 (dust) or between 0 and 21M BTC"}
	}
	if s.UtxoMaxAmount < -1 || s.UtxoMaxAmount > MaxSatoshis {
		return &ErrInvalidSettings{"utxo max amount must be -1 (unset) or between 0 and 21M BTC"}
	}
	if s.VtxoMinAmount != -1 && s.VtxoMaxAmount != -1 && s.VtxoMinAmount > s.VtxoMaxAmount {
		return &ErrInvalidSettings{"vtxo min amount must be <= vtxo max amount"}
	}
	if s.UtxoMinAmount != -1 && s.UtxoMaxAmount != -1 && s.UtxoMinAmount > s.UtxoMaxAmount {
		return &ErrInvalidSettings{"utxo min amount must be <= utxo max amount"}
	}
	return nil
}

// validUpdateFields is the set of snake_case field names accepted by Merge,
// built from the Settings struct fields (excluding UpdatedAt).
var validUpdateFields = buildValidUpdateFields()

func buildValidUpdateFields() map[string]struct{} {
	t := reflect.TypeOf(Settings{})
	fields := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		if name == "UpdatedAt" {
			continue
		}
		fields[camelToSnake(name)] = struct{}{}
	}
	return fields
}

func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Merge combines the receiver (incoming request) with stored settings
// according to updateFields. If non-empty, only the listed
// fields are written from the request; all other fields remain as stored.
// If updateFields is empty, every field from the request is written as-is —
// fields not set in the request default to 0, so callers must populate all
// fields. Field names use snake_case matching the proto field names.
// Returns an error if any field name in updateFields is not recognized.
func (s Settings) Merge(stored Settings, updateFields []string) (Settings, error) {
	if len(updateFields) == 0 {
		s.UpdatedAt = stored.UpdatedAt
		return s, nil
	}

	fields := make(map[string]struct{}, len(updateFields))
	for _, f := range updateFields {
		if _, ok := validUpdateFields[f]; !ok {
			return Settings{}, fmt.Errorf("unknown update field: %q", f)
		}
		if _, dup := fields[f]; dup {
			return Settings{}, fmt.Errorf("duplicate update field: %q", f)
		}
		fields[f] = struct{}{}
	}

	result := stored
	if _, ok := fields["ban_threshold"]; ok {
		result.BanThreshold = s.BanThreshold
	}
	if _, ok := fields["ban_duration"]; ok {
		result.BanDuration = s.BanDuration
	}
	if _, ok := fields["unilateral_exit_delay"]; ok {
		result.UnilateralExitDelay = s.UnilateralExitDelay
	}
	if _, ok := fields["public_unilateral_exit_delay"]; ok {
		result.PublicUnilateralExitDelay = s.PublicUnilateralExitDelay
	}
	if _, ok := fields["checkpoint_exit_delay"]; ok {
		result.CheckpointExitDelay = s.CheckpointExitDelay
	}
	if _, ok := fields["boarding_exit_delay"]; ok {
		result.BoardingExitDelay = s.BoardingExitDelay
	}
	if _, ok := fields["vtxo_tree_expiry"]; ok {
		result.VtxoTreeExpiry = s.VtxoTreeExpiry
	}
	if _, ok := fields["round_min_participants_count"]; ok {
		result.RoundMinParticipantsCount = s.RoundMinParticipantsCount
	}
	if _, ok := fields["round_max_participants_count"]; ok {
		result.RoundMaxParticipantsCount = s.RoundMaxParticipantsCount
	}
	if _, ok := fields["vtxo_min_amount"]; ok {
		result.VtxoMinAmount = s.VtxoMinAmount
	}
	if _, ok := fields["vtxo_max_amount"]; ok {
		result.VtxoMaxAmount = s.VtxoMaxAmount
	}
	if _, ok := fields["utxo_min_amount"]; ok {
		result.UtxoMinAmount = s.UtxoMinAmount
	}
	if _, ok := fields["utxo_max_amount"]; ok {
		result.UtxoMaxAmount = s.UtxoMaxAmount
	}
	if _, ok := fields["settlement_min_expiry_gap"]; ok {
		result.SettlementMinExpiryGap = s.SettlementMinExpiryGap
	}
	if _, ok := fields["vtxo_no_csv_validation_cutoff_date"]; ok {
		result.VtxoNoCsvValidationCutoffDate = s.VtxoNoCsvValidationCutoffDate
	}
	if _, ok := fields["max_tx_weight"]; ok {
		result.MaxTxWeight = s.MaxTxWeight
	}
	return result, nil
}

func NewSettings(
	banThreshold, banDuration,
	unilateralExitDelay, publicUnilateralExitDelay,
	checkpointExitDelay, boardingExitDelay,
	vtxoTreeExpiry,
	roundMinParticipantsCount, roundMaxParticipantsCount,
	vtxoMinAmount, vtxoMaxAmount,
	utxoMinAmount, utxoMaxAmount,
	settlementMinExpiryGap,
	vtxoNoCsvValidationCutoffDate,
	maxTxWeight int64,
) *Settings {
	return &Settings{
		BanThreshold:                  banThreshold,
		BanDuration:                   banDuration,
		UnilateralExitDelay:           unilateralExitDelay,
		PublicUnilateralExitDelay:     publicUnilateralExitDelay,
		CheckpointExitDelay:           checkpointExitDelay,
		BoardingExitDelay:             boardingExitDelay,
		VtxoTreeExpiry:                vtxoTreeExpiry,
		RoundMinParticipantsCount:     roundMinParticipantsCount,
		RoundMaxParticipantsCount:     roundMaxParticipantsCount,
		VtxoMinAmount:                 vtxoMinAmount,
		VtxoMaxAmount:                 vtxoMaxAmount,
		UtxoMinAmount:                 utxoMinAmount,
		UtxoMaxAmount:                 utxoMaxAmount,
		SettlementMinExpiryGap:        settlementMinExpiryGap,
		VtxoNoCsvValidationCutoffDate: vtxoNoCsvValidationCutoffDate,
		MaxTxWeight:                   maxTxWeight,
	}
}
