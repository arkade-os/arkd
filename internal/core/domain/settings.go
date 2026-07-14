package domain

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain/batchtrigger"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
)

const (
	bitcoinBlockWeight = 4_000_000
	minSessionDuration = 2 * time.Second
	minBanDuration     = 1 * time.Second
)

var (
	// asset packet overhead: OP_RETURN(1) + push_data(1) + magic_bytes + marker(1) + varuint_count(1)
	assetPacketOverheadWU uint64 = (1 + 1 + uint64(len(extension.ArkadeMagic)) + 1 + 1) * 4

	// ref group weight
	refAssetId, _ = asset.NewAssetId(
		"0100000000000000000000000000000000000000000000000000000000000000", 0,
	)
	// we assume that to spend an asset, we need to transfer it to at least 1 output.
	// the minimum group size is 1 input + 1 output + asset Id (not an issuance)
	refGroup = asset.AssetGroup{
		AssetId: refAssetId,
		Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 1}},
		Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1}},
	}
	groupBytes, _ = refGroup.Serialize()
	// group is in OP_RETURN, so weight = bytes * 4
	refGroupWeight = uint64(len(groupBytes)) * 4 // 180 WU
)

type Settings struct {
	SessionDuration               time.Duration
	UnrolledVtxoMinExpiryMargin   time.Duration
	BanThreshold                  uint64
	BanDuration                   time.Duration
	UnilateralExitDelay           arklib.RelativeLocktime
	PublicUnilateralExitDelay     arklib.RelativeLocktime
	CheckpointExitDelay           arklib.RelativeLocktime
	BoardingExitDelay             arklib.RelativeLocktime
	VtxoTreeExpiry                arklib.RelativeLocktime
	RoundMinParticipantsCount     int64
	RoundMaxParticipantsCount     int64
	VtxoMinAmount                 int64
	VtxoMaxAmount                 int64
	UtxoMinAmount                 int64
	UtxoMaxAmount                 int64
	SettlementMinExpiryGap        time.Duration
	VtxoNoCsvValidationCutoffDate time.Time
	MaxTxWeight                   uint64
	MaxOpReturnOutputs            uint64
	AssetTxMaxWeightRatio         float32
	NoteUriPrefix                 string
	ScheduledSession              *ScheduledSession
	BatchFees                     BatchFees
	BuildVersionHeader            string
	BuildVersionHeaderRequired    bool
	DigestHeaderRequired          bool
	BatchTrigger                  string
	RateLimitEnabled              bool
	RateLimitMaxVelocity          float64
	RateLimitMaxCooldownSecs      int64
	UpdatedAt                     time.Time
}

func NewSettings(
	sessionDuration, unrolledVtxoMinExpiryMargin, banThreshold, banDuration,
	settlementMinExpiryGap, vtxoNoCsvValidationCutoffDate,
	roundMinParticipantsCount, roundMaxParticipantsCount,
	vtxoMinAmount, vtxoMaxAmount, utxoMinAmount, utxoMaxAmount int64,
	unilateralExitDelay, publicUnilateralExitDelay, checkpointExitDelay,
	boardingExitDelay, vtxoTreeExpiry arklib.RelativeLocktime,
	maxTxWeight, maxOpReturnOutputs uint64,
	assetTxMaxWeightRatio float32, noteUriPrefix, minVersionAccepted string,
	minVersionRequired, digestHeaderRequired bool,
	batchTrigger string,
	rateLimitEnabled bool, rateLimitMaxVelocity float64, rateLimitMaxCooldownSecs int64,
) (*Settings, error) {
	settings := &Settings{
		SessionDuration:               time.Duration(sessionDuration) * time.Second,
		UnrolledVtxoMinExpiryMargin:   time.Duration(unrolledVtxoMinExpiryMargin) * time.Second,
		BanThreshold:                  uint64(banThreshold),
		BanDuration:                   time.Duration(banDuration) * time.Second,
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
		SettlementMinExpiryGap:        time.Duration(settlementMinExpiryGap) * time.Second,
		VtxoNoCsvValidationCutoffDate: time.Unix(vtxoNoCsvValidationCutoffDate, 0),
		MaxTxWeight:                   maxTxWeight,
		MaxOpReturnOutputs:            maxOpReturnOutputs,
		AssetTxMaxWeightRatio:         assetTxMaxWeightRatio,
		NoteUriPrefix:                 noteUriPrefix,
		BuildVersionHeader:            minVersionAccepted,
		BuildVersionHeaderRequired:    minVersionRequired,
		DigestHeaderRequired:          digestHeaderRequired,
		BatchTrigger:                  batchTrigger,
		RateLimitEnabled:              rateLimitEnabled,
		RateLimitMaxVelocity:          rateLimitMaxVelocity,
		RateLimitMaxCooldownSecs:      rateLimitMaxCooldownSecs,
		UpdatedAt:                     time.Now(),
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return settings, nil
}

func (s Settings) Validate() error {
	if s.SessionDuration < minSessionDuration {
		return fmt.Errorf(
			"invalid session duration (%s), must be at least %s",
			s.SessionDuration, minSessionDuration,
		)
	}
	if s.UnrolledVtxoMinExpiryMargin < 0 {
		return fmt.Errorf(
			"invalid unrolled vtxo min expiry margin (%s), must not be negative",
			s.UnrolledVtxoMinExpiryMargin,
		)
	}
	if s.UnrolledVtxoMinExpiryMargin < s.SessionDuration {
		return fmt.Errorf(
			"invalid unrolled vtxo min expiry margin (%s), must be at least session duration (%s)",
			s.UnrolledVtxoMinExpiryMargin, s.SessionDuration,
		)
	}
	if s.BanThreshold > 0 && s.BanDuration < minBanDuration {
		return fmt.Errorf(
			"invalid ban duration (%s), must be at least %s", s.BanDuration, minBanDuration,
		)
	}

	// Ensure vtxo tree expiry and checkpoint exit delay are of the same type
	if s.CheckpointExitDelay.Type != s.VtxoTreeExpiry.Type {
		return fmt.Errorf(
			"all delays must be above or below value %d "+
				"(checkpoint exit delay and vtxo tree expiry type mismatch)",
			arklib.MinAllowedSequence,
		)
	}

	if s.UnilateralExitDelay.Type != s.VtxoTreeExpiry.Type {
		return fmt.Errorf(
			"all delays must be above or below value %d "+
				"(unilateral exit delay and vtxo tree expiry type mismatch)",
			arklib.MinAllowedSequence,
		)
	}
	if s.BoardingExitDelay.Type != s.VtxoTreeExpiry.Type {
		return fmt.Errorf(
			"all delays must be above or below value %d "+
				"(boarding exit delay and vtxo tree expiry type mismatch)",
			arklib.MinAllowedSequence,
		)
	}

	// Make sure the public unilateral exit delay type matches the internal one
	if s.PublicUnilateralExitDelay.Type != s.UnilateralExitDelay.Type {
		return fmt.Errorf(
			"public unilateral exit delay and unilateral exit delay must have the same type",
		)
	}

	// Round seconds-based delays to multiples of arklib.MinAllowedSequence (BIP68 requirement).
	// Block-based delays don't need rounding.
	if s.VtxoTreeExpiry.Value <= 0 {
		return fmt.Errorf("vtxo tree expiry value must be greater than 0")
	}

	if s.UnilateralExitDelay.Value == s.BoardingExitDelay.Value {
		return fmt.Errorf("unilateral exit delay and boarding exit delay must be different")
	}

	if s.PublicUnilateralExitDelay.Value > 0 &&
		s.PublicUnilateralExitDelay.Value < s.UnilateralExitDelay.Value {
		return fmt.Errorf(
			"public unilateral exit delay must be greater than or equal to unilateral exit delay",
		)
	}

	if s.VtxoMinAmount == 0 {
		return fmt.Errorf("vtxo min amount must be greater than 0")
	}

	if s.UtxoMinAmount == 0 {
		return fmt.Errorf("utxo min amount must be greater than 0")
	}

	// Max amounts of -1 (no limit) or 0 (special sentinel, e.g. boarding disabled)
	// are not concrete upper bounds, so only enforce ordering when both ends are set.
	if s.VtxoMaxAmount > 0 && s.VtxoMinAmount > 0 && s.VtxoMaxAmount < s.VtxoMinAmount {
		return fmt.Errorf(
			"vtxo max amount must be greater than or equal to min amount, got %d < %d",
			s.VtxoMaxAmount, s.VtxoMinAmount,
		)
	}
	if s.UtxoMaxAmount > 0 && s.UtxoMinAmount > 0 && s.UtxoMaxAmount < s.UtxoMinAmount {
		return fmt.Errorf(
			"utxo max amount must be greater than or equal to min amount, got %d < %d",
			s.UtxoMaxAmount, s.UtxoMinAmount,
		)
	}

	if s.MaxTxWeight == 0 {
		return fmt.Errorf("max tx weight must be greater than 0")
	}
	if s.MaxTxWeight > bitcoinBlockWeight {
		return fmt.Errorf(
			"max tx weight can't exceed bitcoin block weight (%d)", bitcoinBlockWeight,
		)
	}

	if s.MaxOpReturnOutputs == 0 {
		return fmt.Errorf("max op return outputs must be greater than 0")
	}

	if s.AssetTxMaxWeightRatio <= 0 || s.AssetTxMaxWeightRatio >= 1 {
		return fmt.Errorf(
			"asset tx max weight ratio must be in range (0, 1), got %f",
			s.AssetTxMaxWeightRatio,
		)
	}

	if s.RoundMinParticipantsCount < 1 {
		return fmt.Errorf("batch min participants count must be at least 1")
	}
	if s.RoundMaxParticipantsCount < s.RoundMinParticipantsCount {
		return fmt.Errorf(
			"batch max participants count must be >= min participants count, got %d <= %d",
			s.RoundMaxParticipantsCount, s.RoundMinParticipantsCount,
		)
	}
	if s.BuildVersionHeaderRequired && len(s.BuildVersionHeader) <= 0 {
		return fmt.Errorf("build version header is required but no version is set")
	}
	if _, err := batchtrigger.New(s.BatchTrigger); err != nil {
		return fmt.Errorf("invalid batch trigger program: %w", err)
	}
	return nil
}

// SettingsUpdate is a copy of the Settings repo struct, but with optional fields to easily handle
// changes.
type SettingsUpdate struct {
	SessionDuration               *time.Duration
	UnrolledVtxoMinExpiryMargin   *time.Duration
	BanThreshold                  *uint64
	BanDuration                   *time.Duration
	UnilateralExitDelay           *arklib.RelativeLocktime
	PublicUnilateralExitDelay     *arklib.RelativeLocktime
	CheckpointExitDelay           *arklib.RelativeLocktime
	BoardingExitDelay             *arklib.RelativeLocktime
	VtxoTreeExpiry                *arklib.RelativeLocktime
	RoundMinParticipantsCount     *int64
	RoundMaxParticipantsCount     *int64
	VtxoMinAmount                 *int64
	VtxoMaxAmount                 *int64
	UtxoMinAmount                 *int64
	UtxoMaxAmount                 *int64
	SettlementMinExpiryGap        *time.Duration
	VtxoNoCsvValidationCutoffDate *time.Time
	MaxTxWeight                   *uint64
	MaxOpReturnOutputs            *uint64
	AssetTxMaxWeightRatio         *float32
	NoteUriPrefix                 *string
	BuildVersionHeader            *string
	BuildVersionHeaderRequired    *bool
	DigestHeaderRequired          *bool
	BatchTrigger                  *string
	RateLimitEnabled              *bool
	RateLimitMaxVelocity          *float64
	RateLimitMaxCooldownSecs      *int64
}

// Update updates any field of Settings but ScheduledSession and BatchFees and returns a changelog
// with the list of all modified fields in dash-separated format.
func (s *Settings) Update(u SettingsUpdate) ([]string, error) {
	// Apply the update to a copy so that, if validation fails, the receiver is
	// left untouched. Settings holds only value types, so this is a full clone.
	updated := *s
	changelog := make([]string, 0)
	if u.SessionDuration != nil {
		updated.SessionDuration = *u.SessionDuration
		changelog = append(changelog, "session_duration")
	}
	if u.UnrolledVtxoMinExpiryMargin != nil {
		updated.UnrolledVtxoMinExpiryMargin = *u.UnrolledVtxoMinExpiryMargin
		changelog = append(changelog, "unrolled_vtxo_min_expiry_margin")
	}
	if u.BanThreshold != nil {
		updated.BanThreshold = *u.BanThreshold
		changelog = append(changelog, "ban_threshold")
	}
	if u.BanDuration != nil {
		updated.BanDuration = *u.BanDuration
		changelog = append(changelog, "ban_duration")
	}
	if u.UnilateralExitDelay != nil {
		updated.UnilateralExitDelay = *u.UnilateralExitDelay
		changelog = append(changelog, "unilateral_exit_delay")
	}
	if u.PublicUnilateralExitDelay != nil {
		updated.PublicUnilateralExitDelay = *u.PublicUnilateralExitDelay
		changelog = append(changelog, "public_unilateral_exit_delay")
	}
	if u.CheckpointExitDelay != nil {
		updated.CheckpointExitDelay = *u.CheckpointExitDelay
		changelog = append(changelog, "checkpoint_exit_delay")
	}
	if u.BoardingExitDelay != nil {
		updated.BoardingExitDelay = *u.BoardingExitDelay
		changelog = append(changelog, "boarding_exit_delay")
	}
	if u.VtxoTreeExpiry != nil {
		updated.VtxoTreeExpiry = *u.VtxoTreeExpiry
		changelog = append(changelog, "vtxo_tree_expiry")
	}
	if u.RoundMaxParticipantsCount != nil {
		updated.RoundMaxParticipantsCount = *u.RoundMaxParticipantsCount
		changelog = append(changelog, "round_max_participants_count")
	}
	if u.RoundMinParticipantsCount != nil {
		updated.RoundMinParticipantsCount = *u.RoundMinParticipantsCount
		changelog = append(changelog, "round_min_participants_count")
	}
	if u.VtxoMinAmount != nil {
		updated.VtxoMinAmount = *u.VtxoMinAmount
		changelog = append(changelog, "vtxo_min_amount")
	}
	if u.VtxoMaxAmount != nil {
		updated.VtxoMaxAmount = *u.VtxoMaxAmount
		changelog = append(changelog, "vtxo_max_amount")
	}
	if u.UtxoMinAmount != nil {
		updated.UtxoMinAmount = *u.UtxoMinAmount
		changelog = append(changelog, "utxo_min_amount")
	}
	if u.UtxoMaxAmount != nil {
		updated.UtxoMaxAmount = *u.UtxoMaxAmount
		changelog = append(changelog, "utxo_max_amount")
	}
	if u.SettlementMinExpiryGap != nil {
		updated.SettlementMinExpiryGap = *u.SettlementMinExpiryGap
		changelog = append(changelog, "settlement_min_expiry_gap")
	}
	if u.VtxoNoCsvValidationCutoffDate != nil {
		updated.VtxoNoCsvValidationCutoffDate = *u.VtxoNoCsvValidationCutoffDate
		changelog = append(changelog, "vtxo_no_csv_validation_cutoff_date")
	}
	if u.MaxTxWeight != nil {
		updated.MaxTxWeight = *u.MaxTxWeight
		changelog = append(changelog, "max_tx_weight")
	}
	if u.MaxOpReturnOutputs != nil {
		updated.MaxOpReturnOutputs = *u.MaxOpReturnOutputs
		changelog = append(changelog, "max_op_return_outputs")
	}
	if u.AssetTxMaxWeightRatio != nil {
		updated.AssetTxMaxWeightRatio = *u.AssetTxMaxWeightRatio
		changelog = append(changelog, "asset_tx_max_weight_ratio")
	}
	if u.NoteUriPrefix != nil {
		updated.NoteUriPrefix = *u.NoteUriPrefix
		changelog = append(changelog, "note_uri_prefix")
	}
	if u.BuildVersionHeader != nil {
		updated.BuildVersionHeader = *u.BuildVersionHeader
		changelog = append(changelog, "build_version_header")
	}
	if u.BuildVersionHeaderRequired != nil {
		updated.BuildVersionHeaderRequired = *u.BuildVersionHeaderRequired
		changelog = append(changelog, "build_version_header_required")
	}
	if u.DigestHeaderRequired != nil {
		updated.DigestHeaderRequired = *u.DigestHeaderRequired
		changelog = append(changelog, "digest_header_required")
	}
	if u.BatchTrigger != nil {
		updated.BatchTrigger = *u.BatchTrigger
		changelog = append(changelog, "batch_trigger")
	}
	if u.RateLimitEnabled != nil {
		updated.RateLimitEnabled = *u.RateLimitEnabled
		changelog = append(changelog, "rate_limit_enabled")
	}
	if u.RateLimitMaxVelocity != nil {
		updated.RateLimitMaxVelocity = *u.RateLimitMaxVelocity
		changelog = append(changelog, "rate_limit_max_velocity")
	}
	if u.RateLimitMaxCooldownSecs != nil {
		updated.RateLimitMaxCooldownSecs = *u.RateLimitMaxCooldownSecs
		changelog = append(changelog, "rate_limit_max_cooldown_secs")
	}

	if err := updated.Validate(); err != nil {
		return nil, err
	}

	// Validation passed: commit the changes back onto the receiver.
	*s = updated
	return changelog, nil
}

// UpdateScheduledSession updates the scheduled session settings and returns
// the changelog like Update does.
func (s *Settings) UpdateScheduledSession(updates ScheduledSessionUpdate) ([]string, error) {
	if s.ScheduledSession == nil {
		session := &ScheduledSession{}
		if err := session.Update(updates); err != nil {
			return nil, err
		}
		s.ScheduledSession = session
		return []string{"scheduled_session"}, nil
	}
	return []string{"scheduled_session"}, s.ScheduledSession.Update(updates)
}

// ClearScheduledSession deletes the scheduled session from settings and returns
// the changelog like Update does.
func (s *Settings) ClearScheduledSession() []string {
	s.ScheduledSession = nil
	return []string{"scheduled_session"}
}

// UpdateBatchFees updates the batch fees settings and returns the changelog like Update does.
func (s *Settings) UpdateBatchFees(updates BatchFeesUpdate) ([]string, error) {
	if err := s.BatchFees.Update(updates); err != nil {
		return nil, err
	}
	return []string{"batch_fees"}, nil
}

// ClearBatchFees deletes the batch fees from settings and returns the changelog like
// Update does.
func (s *Settings) ClearBatchFees() []string {
	s.BatchFees = BatchFees{}
	return []string{"batch_fees"}
}

func (s Settings) MaxAssetsPerVtxo() int {
	if s.MaxTxWeight == 0 {
		return 0
	}

	maxPacketWU := uint64(float64(s.MaxTxWeight) * float64(s.AssetTxMaxWeightRatio))
	if maxPacketWU <= assetPacketOverheadWU {
		return 0
	}

	availableWU := maxPacketWU - assetPacketOverheadWU
	return int(availableWU / refGroupWeight)
}

func (s Settings) AllowCSVBlockType() bool {
	return s.VtxoTreeExpiry.Type == arklib.LocktimeTypeBlock
}

func (s Settings) ShouldStartBatch(ctx batchtrigger.Context) (bool, error) {
	trigger, err := batchtrigger.New(s.BatchTrigger)
	if err != nil {
		return false, err
	}
	if trigger == nil {
		return true, nil
	}
	return trigger.Eval(ctx)
}
