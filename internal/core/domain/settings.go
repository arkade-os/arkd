package domain

import "time"

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
