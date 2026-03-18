package domain

import (
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

const MinAllowedSequence = 512

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
	if s.MaxTxWeight <= 0 {
		return &ErrInvalidSettings{"max tx weight must be greater than 0"}
	}
	return nil
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
