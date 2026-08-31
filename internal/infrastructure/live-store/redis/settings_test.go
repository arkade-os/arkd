package redislivestore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

// TestSettingsDTORoundTrip verifies that a ports.Settings survives the same
// serialization the redis store performs on Upsert/Get (newSettingsDTO -> JSON
// -> parse). It guards against fields silently dropped from settingsDTO, which
// is what made a runtime build-version-header change invisible to the version
// guard.
func TestSettingsDTORoundTrip(t *testing.T) {
	exit, _ := arklib.ParseRelativeLocktime(512)
	grace, _ := arklib.ParseRelativeLocktime(7168)
	tree, _ := arklib.ParseRelativeLocktime(1024)
	boarding, _ := arklib.ParseRelativeLocktime(1536)

	in := ports.Settings{
		Settings: domain.Settings{
			SessionDuration:            30 * time.Second,
			UnilateralExitDelay:        exit,
			PublicUnilateralExitDelay:  exit,
			CheckpointExitDelay:        exit,
			BoardingExitDelay:          boarding,
			VtxoTreeExpiry:             tree,
			RoundMinParticipantsCount:  1,
			RoundMaxParticipantsCount:  10,
			VtxoMinAmount:              1000,
			VtxoMaxAmount:              -1,
			UtxoMinAmount:              1000,
			UtxoMaxAmount:              -1,
			MaxTxWeight:                400000,
			MaxOpReturnOutputs:         3,
			AssetTxMaxWeightRatio:      0.5,
			NoteUriPrefix:              "ark",
			BuildVersionHeader:         "0.9.7",
			BuildVersionHeaderRequired: true,
			DigestHeaderRequired:       true,
			EpochExpiryEnabled:         true,
			EpochAnchor:                time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),
			EpochLength:                28 * 24 * time.Hour,
			RolloverWindow:             7 * 24 * time.Hour,
			SettlementCutoff:           12 * time.Hour,
			UnrollGrace:                grace,
		},
		Network:        arklib.Bitcoin,
		DustAmount:     354,
		ForfeitAddress: "forfeit-address",
		LastBatchAt:    time.Now(),
	}

	// Mimic the redis Set/Get: marshal the DTO to JSON and back before parsing.
	data, err := json.Marshal(newSettingsDTO(in))
	require.NoError(t, err)

	var dto settingsDTO
	require.NoError(t, json.Unmarshal(data, &dto))

	out, err := dto.parse()
	require.NoError(t, err)
	require.NotNil(t, out)

	// The fields that regressed: a runtime build-version policy must survive the
	// cache round-trip so the version guard can read it.
	require.Equal(t, "0.9.7", out.BuildVersionHeader)
	require.True(t, out.BuildVersionHeaderRequired)
	require.True(t, out.DigestHeaderRequired)

	// The epoch settings regressed the same way, and worse: the admin API writes
	// the repository and reports success, but a round reads this cache, so the
	// flag came back false and epoch expiry silently never activated on any
	// redis-backed deployment.
	require.True(t, out.EpochExpiryEnabled)
	require.True(t, in.EpochAnchor.Equal(out.EpochAnchor))
	require.Equal(t, in.EpochLength, out.EpochLength)
	require.Equal(t, in.RolloverWindow, out.RolloverWindow)
	require.Equal(t, in.SettlementCutoff, out.SettlementCutoff)
	require.Equal(t, in.UnrollGrace, out.UnrollGrace)

	// An unset anchor must stay unset rather than becoming the unix epoch.
	bare := in
	bare.EpochAnchor = time.Time{}
	bareData, err := json.Marshal(newSettingsDTO(bare))
	require.NoError(t, err)
	var bareDTO settingsDTO
	require.NoError(t, json.Unmarshal(bareData, &bareDTO))
	bareOut, err := bareDTO.parse()
	require.NoError(t, err)
	require.True(t, bareOut.EpochAnchor.IsZero())

	// Spot-check a few other fields to ensure the round-trip is otherwise intact.
	require.Equal(t, in.SessionDuration, out.SessionDuration)
	require.Equal(t, in.NoteUriPrefix, out.NoteUriPrefix)
	require.Equal(t, in.VtxoMaxAmount, out.VtxoMaxAmount)
	require.Equal(t, in.MaxOpReturnOutputs, out.MaxOpReturnOutputs)
	require.Equal(t, in.LastBatchAt.Unix(), out.LastBatchAt.Unix())
}
