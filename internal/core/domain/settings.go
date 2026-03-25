package domain

import (
	"fmt"
	"math"
	"time"

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

// Merge returns a copy of s where any zero-valued field is replaced by the
// corresponding value from other. This allows callers to send only the fields
// they want to change.
func (s Settings) Merge(other Settings) Settings {
	if s.BanThreshold == 0 {
		s.BanThreshold = other.BanThreshold
	}
	if s.BanDuration == 0 {
		s.BanDuration = other.BanDuration
	}
	if s.UnilateralExitDelay == 0 {
		s.UnilateralExitDelay = other.UnilateralExitDelay
	}
	if s.PublicUnilateralExitDelay == 0 {
		s.PublicUnilateralExitDelay = other.PublicUnilateralExitDelay
	}
	if s.CheckpointExitDelay == 0 {
		s.CheckpointExitDelay = other.CheckpointExitDelay
	}
	if s.BoardingExitDelay == 0 {
		s.BoardingExitDelay = other.BoardingExitDelay
	}
	if s.VtxoTreeExpiry == 0 {
		s.VtxoTreeExpiry = other.VtxoTreeExpiry
	}
	if s.RoundMinParticipantsCount == 0 {
		s.RoundMinParticipantsCount = other.RoundMinParticipantsCount
	}
	if s.RoundMaxParticipantsCount == 0 {
		s.RoundMaxParticipantsCount = other.RoundMaxParticipantsCount
	}
	if s.VtxoMinAmount == 0 {
		s.VtxoMinAmount = other.VtxoMinAmount
	}
	if s.VtxoMaxAmount == 0 {
		s.VtxoMaxAmount = other.VtxoMaxAmount
	}
	if s.UtxoMinAmount == 0 {
		s.UtxoMinAmount = other.UtxoMinAmount
	}
	if s.UtxoMaxAmount == 0 {
		s.UtxoMaxAmount = other.UtxoMaxAmount
	}
	if s.SettlementMinExpiryGap == 0 {
		s.SettlementMinExpiryGap = other.SettlementMinExpiryGap
	}
	if s.VtxoNoCsvValidationCutoffDate == 0 {
		s.VtxoNoCsvValidationCutoffDate = other.VtxoNoCsvValidationCutoffDate
	}
	if s.MaxTxWeight == 0 {
		s.MaxTxWeight = other.MaxTxWeight
	}
	return s
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
