package domain_test

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/domain/batchtrigger"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

var (
	unilateralExitDelay    = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}
	pubUnilateralExitDelay = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 2048}
	checkpointExitDelay    = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}
	boardingExitDelay      = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 2048}
	vtxoTreeExpiry         = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 4096}

	validSettings = domain.Settings{
		SessionDuration:             60 * time.Second,
		UnrolledVtxoMinExpiryMargin: 120 * time.Second,
		BanThreshold:                3,
		BanDuration:                 60 * time.Second,
		UnilateralExitDelay:         unilateralExitDelay,
		PublicUnilateralExitDelay:   pubUnilateralExitDelay,
		CheckpointExitDelay:         checkpointExitDelay,
		BoardingExitDelay:           boardingExitDelay,
		VtxoTreeExpiry:              vtxoTreeExpiry,
		RoundMinParticipantsCount:   1,
		RoundMaxParticipantsCount:   128,
		VtxoMinAmount:               1000,
		VtxoMaxAmount:               1_000_000,
		UtxoMinAmount:               1000,
		UtxoMaxAmount:               1_000_000,
		MaxTxWeight:                 100_000,
		MaxOpReturnOutputs:          3,
		AssetTxMaxWeightRatio:       0.5,
		BuildVersionHeader:          "v1.0.0",
		BuildVersionHeaderRequired:  true,
		DigestHeaderRequired:        true,
		UpdatedAt:                   time.Now(),
	}
)

func TestSettings(t *testing.T) {
	testValidateSettings(t)

	testUpdateSettings(t)

	testNewSettings(t)

	testSettingsScheduledSession(t)

	testSettingsBatchFees(t)

	testSettingsBatchTrigger(t)
}

func testValidateSettings(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			require.NoError(t, validSettings.Validate())
		})

		t.Run("invalid", func(t *testing.T) {
			shortSession := validSettings
			shortSession.SessionDuration = time.Second

			negativeMargin := validSettings
			negativeMargin.UnrolledVtxoMinExpiryMargin = -time.Second

			smallMargin := validSettings
			smallMargin.UnrolledVtxoMinExpiryMargin = 30 * time.Second

			shortBan := validSettings
			shortBan.BanDuration = 500 * time.Millisecond

			checkpointTypeMismatch := validSettings
			checkpointTypeMismatch.CheckpointExitDelay = arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeBlock, Value: 512,
			}

			unilateralTypeMismatch := validSettings
			unilateralTypeMismatch.UnilateralExitDelay = arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeBlock, Value: 1024,
			}

			boardingTypeMismatch := validSettings
			boardingTypeMismatch.BoardingExitDelay = arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeBlock, Value: 2048,
			}

			publicTypeMismatch := validSettings
			publicTypeMismatch.PublicUnilateralExitDelay = arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeBlock, Value: 2048,
			}

			zeroExpiry := validSettings
			zeroExpiry.VtxoTreeExpiry = arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeSecond, Value: 0,
			}

			equalExitDelays := validSettings
			equalExitDelays.BoardingExitDelay = unilateralExitDelay

			publicBelowUnilateral := validSettings
			publicBelowUnilateral.PublicUnilateralExitDelay = arklib.RelativeLocktime{
				Type: arklib.LocktimeTypeSecond, Value: 512,
			}

			zeroVtxoMin := validSettings
			zeroVtxoMin.VtxoMinAmount = 0

			zeroUtxoMin := validSettings
			zeroUtxoMin.UtxoMinAmount = 0

			zeroMaxTxWeight := validSettings
			zeroMaxTxWeight.MaxTxWeight = 0

			hugeMaxTxWeight := validSettings
			hugeMaxTxWeight.MaxTxWeight = 5_000_000

			zeroRatio := validSettings
			zeroRatio.AssetTxMaxWeightRatio = 0

			oneRatio := validSettings
			oneRatio.AssetTxMaxWeightRatio = 1

			zeroRoundMin := validSettings
			zeroRoundMin.RoundMinParticipantsCount = 0

			roundMaxBelowMin := validSettings
			roundMaxBelowMin.RoundMaxParticipantsCount = 0

			vtxoMaxBelowMin := validSettings
			vtxoMaxBelowMin.VtxoMinAmount = 100
			vtxoMaxBelowMin.VtxoMaxAmount = 5

			utxoMaxBelowMin := validSettings
			utxoMaxBelowMin.UtxoMinAmount = 100
			utxoMaxBelowMin.UtxoMaxAmount = 5

			zeroMaxOpReturn := validSettings
			zeroMaxOpReturn.MaxOpReturnOutputs = 0

			requiredVersionWithoutHeader := validSettings
			requiredVersionWithoutHeader.BuildVersionHeaderRequired = true
			requiredVersionWithoutHeader.BuildVersionHeader = ""

			fixtures := []struct {
				settings    domain.Settings
				expectedErr string
			}{
				{
					settings:    shortSession,
					expectedErr: "invalid session duration (1s), must be at least 2s",
				},
				{
					settings:    negativeMargin,
					expectedErr: "invalid unrolled vtxo min expiry margin (-1s), must not be negative",
				},
				{
					settings: smallMargin,
					expectedErr: "invalid unrolled vtxo min expiry margin (30s), " +
						"must be at least session duration (1m0s)",
				},
				{
					settings:    shortBan,
					expectedErr: "invalid ban duration (500ms), must be at least 1s",
				},
				{
					settings: checkpointTypeMismatch,
					expectedErr: "all delays must be above or below value 512 " +
						"(checkpoint exit delay and vtxo tree expiry type mismatch)",
				},
				{
					settings: unilateralTypeMismatch,
					expectedErr: "all delays must be above or below value 512 " +
						"(unilateral exit delay and vtxo tree expiry type mismatch)",
				},
				{
					settings: boardingTypeMismatch,
					expectedErr: "all delays must be above or below value 512 " +
						"(boarding exit delay and vtxo tree expiry type mismatch)",
				},
				{
					settings: publicTypeMismatch,
					expectedErr: "public unilateral exit delay and unilateral exit delay " +
						"must have the same type",
				},
				{
					settings:    zeroExpiry,
					expectedErr: "vtxo tree expiry value must be greater than 0",
				},
				{
					settings:    equalExitDelays,
					expectedErr: "unilateral exit delay and boarding exit delay must be different",
				},
				{
					settings: publicBelowUnilateral,
					expectedErr: "public unilateral exit delay must be greater than " +
						"or equal to unilateral exit delay",
				},
				{
					settings:    zeroVtxoMin,
					expectedErr: "vtxo min amount must be greater than 0",
				},
				{
					settings:    zeroUtxoMin,
					expectedErr: "utxo min amount must be greater than 0",
				},
				{
					settings:    zeroMaxTxWeight,
					expectedErr: "max tx weight must be greater than 0",
				},
				{
					settings:    hugeMaxTxWeight,
					expectedErr: "max tx weight can't exceed bitcoin block weight (4000000)",
				},
				{
					settings:    zeroRatio,
					expectedErr: "asset tx max weight ratio must be in range (0, 1), got 0.000000",
				},
				{
					settings:    oneRatio,
					expectedErr: "asset tx max weight ratio must be in range (0, 1), got 1.000000",
				},
				{
					settings:    zeroRoundMin,
					expectedErr: "batch min participants count must be at least 1",
				},
				{
					settings: roundMaxBelowMin,
					expectedErr: "batch max participants count must be >= " +
						"min participants count, got 0 <= 1",
				},
				{
					settings: vtxoMaxBelowMin,
					expectedErr: "vtxo max amount must be greater than or equal to " +
						"min amount, got 5 < 100",
				},
				{
					settings: utxoMaxBelowMin,
					expectedErr: "utxo max amount must be greater than or equal to " +
						"min amount, got 5 < 100",
				},
				{
					settings:    zeroMaxOpReturn,
					expectedErr: "max op return outputs must be greater than 0",
				},
				{
					settings:    requiredVersionWithoutHeader,
					expectedErr: "build version header is required but no version is set",
				},
			}

			for _, f := range fixtures {
				require.EqualError(t, f.settings.Validate(), f.expectedErr)
			}
		})
	})
}

func testUpdateSettings(t *testing.T) {
	t.Run("Update", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			settings := validSettings

			banThreshold := uint64(10)
			sessionDuration := 90 * time.Second
			vtxoMaxAmount := int64(2_000_000)
			buildVersionHeader := "v2.0.0"
			buildVersionHeaderRequired := false
			digestHeaderRequired := false

			changelog, err := settings.Update(domain.SettingsUpdate{
				BanThreshold:               &banThreshold,
				SessionDuration:            &sessionDuration,
				VtxoMaxAmount:              &vtxoMaxAmount,
				BuildVersionHeader:         &buildVersionHeader,
				BuildVersionHeaderRequired: &buildVersionHeaderRequired,
				DigestHeaderRequired:       &digestHeaderRequired,
			})
			require.NoError(t, err)

			// the changelog lists the names of the changed fields
			require.ElementsMatch(
				t, []string{
					"session_duration", "ban_threshold", "vtxo_max_amount",
					"build_version_header", "build_version_header_required",
					"digest_header_required",
				}, changelog,
			)

			// provided fields are updated
			require.Equal(t, uint64(10), settings.BanThreshold)
			require.Equal(t, 90*time.Second, settings.SessionDuration)
			require.Equal(t, int64(2_000_000), settings.VtxoMaxAmount)
			require.Equal(t, "v2.0.0", settings.BuildVersionHeader)
			require.False(t, settings.BuildVersionHeaderRequired)
			require.False(t, settings.DigestHeaderRequired)

			// omitted fields keep their previous values
			require.Equal(t, validSettings.VtxoMinAmount, settings.VtxoMinAmount)
			require.Equal(t, validSettings.MaxTxWeight, settings.MaxTxWeight)
			require.Equal(t, validSettings.UnilateralExitDelay, settings.UnilateralExitDelay)
		})

		t.Run("empty update is a no-op", func(t *testing.T) {
			settings := validSettings

			changelog, err := settings.Update(domain.SettingsUpdate{})
			require.NoError(t, err)
			require.Empty(t, changelog)
			require.Equal(t, validSettings, settings)
		})

		t.Run("invalid update leaves settings untouched", func(t *testing.T) {
			settings := validSettings

			// a valid field paired with an invalid one: the whole update is rejected
			// and nothing is committed.
			banThreshold := uint64(42)
			zeroVtxoMin := int64(0)
			changelog, err := settings.Update(domain.SettingsUpdate{
				BanThreshold:  &banThreshold,
				VtxoMinAmount: &zeroVtxoMin,
			})
			require.EqualError(t, err, "vtxo min amount must be greater than 0")
			require.Nil(t, changelog)
			require.Equal(t, validSettings, settings)
		})

		t.Run("requiring build version without a header is rejected", func(t *testing.T) {
			settings := validSettings
			settings.BuildVersionHeader = "v1.0.0"
			settings.BuildVersionHeaderRequired = false

			// Flip the required flag on while clearing the header in the same update:
			// validation must reject it and leave the settings untouched.
			required := true
			empty := ""
			changelog, err := settings.Update(domain.SettingsUpdate{
				BuildVersionHeaderRequired: &required,
				BuildVersionHeader:         &empty,
			})
			require.EqualError(t, err, "build version header is required but no version is set")
			require.Nil(t, changelog)
			require.Equal(t, "v1.0.0", settings.BuildVersionHeader)
			require.False(t, settings.BuildVersionHeaderRequired)
		})
	})
}

func testNewSettings(t *testing.T) {
	t.Run("NewSettings", func(t *testing.T) {
		sessionDuration, unrolledVtxoMinExpiryMargin := int64(60), int64(120)
		banThreshold, banDuration := int64(3), int64(60)
		settlementMinExpiryGap, vtxoNoCSVCutoffDate := int64(0), int64(0)
		vtxoMinAmount, vtxoMaxAmount := int64(1000), int64(1_000_000)
		utxoMinAmount, utxoMaxAmount := int64(1000), int64(1_000_000)
		batchMinParticipants, batchMaxParticipants := int64(1), int64(128)
		maxTxWeight, assetTxMaxWeightRatio := uint64(100_000), float32(0.5)
		maxOpReturnOutputs := uint64(2)
		noteUriPrefix := "testNote"
		buildVersionHeader, buildVersionHeaderRequired := "v1.0.0", true
		digestHeaderRequired := true
		batchTrigger := "intents_count >= 5.0"

		t.Run("valid", func(t *testing.T) {
			settings, err := domain.NewSettings(
				sessionDuration, unrolledVtxoMinExpiryMargin, banThreshold, banDuration,
				settlementMinExpiryGap, vtxoNoCSVCutoffDate,
				batchMinParticipants, batchMaxParticipants,
				vtxoMinAmount, vtxoMaxAmount, utxoMinAmount, utxoMaxAmount,
				unilateralExitDelay, pubUnilateralExitDelay, checkpointExitDelay,
				boardingExitDelay, vtxoTreeExpiry,
				maxTxWeight, maxOpReturnOutputs, assetTxMaxWeightRatio, noteUriPrefix,
				buildVersionHeader, buildVersionHeaderRequired, digestHeaderRequired,
				batchTrigger,
			)
			require.NoError(t, err)
			require.NotNil(t, settings)
			require.Equal(t, 60*time.Second, settings.SessionDuration)
			require.Equal(t, uint64(3), settings.BanThreshold)
			require.Equal(t, vtxoTreeExpiry, settings.VtxoTreeExpiry)
			require.Equal(t, buildVersionHeader, settings.BuildVersionHeader)
			require.Equal(t, buildVersionHeaderRequired, settings.BuildVersionHeaderRequired)
			require.Equal(t, digestHeaderRequired, settings.DigestHeaderRequired)
			require.Equal(t, batchTrigger, settings.BatchTrigger)
			require.False(t, settings.UpdatedAt.IsZero())
		})

		t.Run("invalid", func(t *testing.T) {
			settings, err := domain.NewSettings(
				1, unrolledVtxoMinExpiryMargin, banThreshold, banDuration,
				settlementMinExpiryGap, vtxoNoCSVCutoffDate,
				batchMinParticipants, batchMaxParticipants,
				vtxoMinAmount, vtxoMaxAmount, utxoMinAmount, utxoMaxAmount,
				unilateralExitDelay, pubUnilateralExitDelay, checkpointExitDelay,
				boardingExitDelay, vtxoTreeExpiry,
				maxTxWeight, maxOpReturnOutputs, assetTxMaxWeightRatio, noteUriPrefix,
				buildVersionHeader, buildVersionHeaderRequired, digestHeaderRequired,
				batchTrigger,
			)
			require.ErrorContains(t, err, "invalid session duration")
			require.Nil(t, settings)
		})

		t.Run("required version without header", func(t *testing.T) {
			settings, err := domain.NewSettings(
				sessionDuration, unrolledVtxoMinExpiryMargin, banThreshold, banDuration,
				settlementMinExpiryGap, vtxoNoCSVCutoffDate,
				batchMinParticipants, batchMaxParticipants,
				vtxoMinAmount, vtxoMaxAmount, utxoMinAmount, utxoMaxAmount,
				unilateralExitDelay, pubUnilateralExitDelay, checkpointExitDelay,
				boardingExitDelay, vtxoTreeExpiry,
				maxTxWeight, maxOpReturnOutputs, assetTxMaxWeightRatio, noteUriPrefix,
				"", true, true,
				batchTrigger,
			)
			require.ErrorContains(t, err, "build version header is required but no version is set")
			require.Nil(t, settings)
		})

		t.Run("invalid batch trigger", func(t *testing.T) {
			settings, err := domain.NewSettings(
				sessionDuration, unrolledVtxoMinExpiryMargin, banThreshold, banDuration,
				settlementMinExpiryGap, vtxoNoCSVCutoffDate,
				batchMinParticipants, batchMaxParticipants,
				vtxoMinAmount, vtxoMaxAmount, utxoMinAmount, utxoMaxAmount,
				unilateralExitDelay, pubUnilateralExitDelay, checkpointExitDelay,
				boardingExitDelay, vtxoTreeExpiry,
				maxTxWeight, maxOpReturnOutputs, assetTxMaxWeightRatio, noteUriPrefix,
				buildVersionHeader, buildVersionHeaderRequired, digestHeaderRequired,
				"this is not (valid cel",
			)
			require.ErrorContains(t, err, "invalid batch trigger program")
			require.Nil(t, settings)
		})
	})
}

func testSettingsScheduledSession(t *testing.T) {
	start := time.Now().Add(time.Hour)
	end := start.Add(time.Hour)
	period := 2 * time.Hour

	t.Run("UpdateScheduledSession", func(t *testing.T) {
		t.Run("creates a session when none is set", func(t *testing.T) {
			settings := validSettings
			require.Nil(t, settings.ScheduledSession)

			changelog, err := settings.UpdateScheduledSession(domain.ScheduledSessionUpdate{
				StartTime: &start,
				EndTime:   &end,
				Period:    &period,
			})
			require.NoError(t, err)
			require.Equal(t, []string{"scheduled_session"}, changelog)
			require.NotNil(t, settings.ScheduledSession)
			require.Equal(t, start, settings.ScheduledSession.StartTime)
			require.Equal(t, end, settings.ScheduledSession.EndTime)
			require.Equal(t, period, settings.ScheduledSession.Period)
		})

		t.Run("updates an existing session", func(t *testing.T) {
			settings := validSettings
			settings.ScheduledSession = &domain.ScheduledSession{
				StartTime: start, EndTime: end, Period: period,
			}

			newPeriod := 3 * time.Hour
			changelog, err := settings.UpdateScheduledSession(domain.ScheduledSessionUpdate{
				Period: &newPeriod,
			})
			require.NoError(t, err)
			require.Equal(t, []string{"scheduled_session"}, changelog)
			require.Equal(t, newPeriod, settings.ScheduledSession.Period)
		})

		t.Run("invalid update is rejected and leaves session nil", func(t *testing.T) {
			settings := validSettings

			// A period without start/end can't pass validation on the new session.
			shortPeriod := 30 * time.Minute
			changelog, err := settings.UpdateScheduledSession(domain.ScheduledSessionUpdate{
				Period: &shortPeriod,
			})
			require.EqualError(t, err, "missing start time")
			require.Empty(t, changelog)
			require.Nil(t, settings.ScheduledSession)
		})
	})

	t.Run("ClearScheduledSession", func(t *testing.T) {
		settings := validSettings
		settings.ScheduledSession = &domain.ScheduledSession{
			StartTime: start, EndTime: end, Period: period,
		}

		require.Equal(t, []string{"scheduled_session"}, settings.ClearScheduledSession())
		require.Nil(t, settings.ScheduledSession)
	})
}

func testSettingsBatchFees(t *testing.T) {
	t.Run("UpdateBatchFees", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			settings := validSettings
			fee := "0.0"

			changelog, err := settings.UpdateBatchFees(domain.BatchFeesUpdate{
				OnchainInputFee: &fee,
			})
			require.NoError(t, err)
			require.Equal(t, []string{"batch_fees"}, changelog)
			require.Equal(t, "0.0", settings.BatchFees.OnchainInputFee)
		})

		t.Run("invalid is rejected and leaves fees untouched", func(t *testing.T) {
			settings := validSettings
			badFee := "1 +"

			changelog, err := settings.UpdateBatchFees(domain.BatchFeesUpdate{
				OnchainInputFee: &badFee,
			})
			require.Error(t, err)
			require.Empty(t, changelog)
			require.Equal(t, domain.BatchFees{}, settings.BatchFees)
		})
	})

	t.Run("ClearBatchFees", func(t *testing.T) {
		settings := validSettings
		settings.BatchFees = domain.BatchFees{OnchainInputFee: "0.0"}

		require.Equal(t, []string{"batch_fees"}, settings.ClearBatchFees())
		require.Equal(t, domain.BatchFees{}, settings.BatchFees)
	})
}

func testSettingsBatchTrigger(t *testing.T) {
	t.Run("ShouldStartBatch", func(t *testing.T) {
		tests := []struct {
			name    string
			program string
			ctx     batchtrigger.Context
			want    bool
		}{
			{
				name:    "nil trigger permits with empty context",
				program: "",
				want:    true,
			},
			{
				name:    "nil trigger permits with context",
				program: "",
				ctx:     batchtrigger.Context{IntentsCount: 0},
				want:    true,
			},
			{
				name:    "true literal permits",
				program: "true",
				want:    true,
			},
			{
				name:    "false literal denies",
				program: "false",
				want:    false,
			},
			{
				name:    "intent count gate satisfied",
				program: "intents_count >= 2.0",
				ctx:     batchtrigger.Context{IntentsCount: 5},
				want:    true,
			},
			{
				name:    "intent count gate unsatisfied",
				program: "intents_count >= 2.0",
				ctx:     batchtrigger.Context{IntentsCount: 1},
				want:    false,
			},
			{
				name:    "fee revenue gate satisfied",
				program: "total_intent_fees >= 500.0",
				ctx:     batchtrigger.Context{TotalIntentFees: 1000},
				want:    true,
			},
			{
				name: "issue 1045 example: many intents, low fees",
				program: "intents_count > 1.0 && " +
					"(current_feerate <= 2.0 || time_since_last_batch >= 3600.0)",
				ctx: batchtrigger.Context{
					IntentsCount:   3,
					CurrentFeerate: 1,
				},
				want: true,
			},
			{
				name: "issue 1045 example: many intents, high fees, but stale",
				program: "intents_count > 1.0 && " +
					"(current_feerate <= 2.0 || time_since_last_batch >= 3600.0)",
				ctx: batchtrigger.Context{
					IntentsCount:       3,
					CurrentFeerate:     50,
					TimeSinceLastBatch: 7200,
				},
				want: true,
			},
			{
				name: "issue 1045 example: many intents, high fees, recent",
				program: "intents_count > 1.0 && " +
					"(current_feerate <= 2.0 || time_since_last_batch >= 3600.0)",
				ctx: batchtrigger.Context{
					IntentsCount:       3,
					CurrentFeerate:     50,
					TimeSinceLastBatch: 60,
				},
				want: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				settings := domain.Settings{BatchTrigger: tt.program}
				got, err := settings.ShouldStartBatch(tt.ctx)
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			})
		}
	})
}
