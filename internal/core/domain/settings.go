package domain

import (
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

const MinAllowedSequence = 512

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
		return fmt.Errorf("unilateral exit delay must be greater than 0")
	}
	if s.BoardingExitDelay <= 0 {
		return fmt.Errorf("boarding exit delay must be greater than 0")
	}
	if s.VtxoTreeExpiry <= 0 {
		return fmt.Errorf("vtxo tree expiry must be greater than 0")
	}
	if s.BanDuration < 1 {
		return fmt.Errorf("ban duration must be at least 1")
	}
	if s.RoundMinParticipantsCount < 1 {
		return fmt.Errorf("round min participants count must be at least 1")
	}
	if s.RoundMaxParticipantsCount < s.RoundMinParticipantsCount {
		return fmt.Errorf(
			"round max participants count must be >= round min participants count",
		)
	}
	if s.PublicUnilateralExitDelay < s.UnilateralExitDelay {
		return fmt.Errorf(
			"public unilateral exit delay must be >= unilateral exit delay",
		)
	}
	if s.UnilateralExitDelay == s.BoardingExitDelay {
		return fmt.Errorf("unilateral exit delay and boarding exit delay must be different")
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
