package sqlitedb_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	sqlitedb "github.com/arkade-os/arkd/internal/infrastructure/db/sqlite"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

func TestSeedSettings(t *testing.T) {
	t.Run("fresh install", func(t *testing.T) {
		ctx := t.Context()
		db, err := sqlitedb.OpenDb(":memory:")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		createSettingsTable(t, db)
		createLegacyTables(t, db)

		defaults := validSeedDefaults(t)
		require.NoError(t, sqlitedb.SeedSettings(ctx, db, defaults))

		// settings row written with config defaults; no legacy data to overlay.
		var (
			sessionDuration int64
			batchOnchainIn  string
			ssStart         int64
		)
		err = db.QueryRow(`
			SELECT session_duration, batch_onchain_input_fee, scheduled_session_start_time
			FROM settings WHERE id = 1`).
			Scan(&sessionDuration, &batchOnchainIn, &ssStart)
		require.NoError(t, err)
		require.Equal(t, int64(30), sessionDuration)
		require.Equal(t, "", batchOnchainIn)
		require.Equal(t, int64(0), ssStart)
	})

	t.Run("backfill legacy", func(t *testing.T) {
		ctx := t.Context()
		db, err := sqlitedb.OpenDb(":memory:")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		createSettingsTable(t, db)
		createLegacyTables(t, db)

		// Insert a legacy fee row and a past-dated (recurring) scheduled session.
		_, err = db.Exec(`
		INSERT INTO intent_fees
			(created_at, offchain_input_fee_program, onchain_input_fee_program,
			 offchain_output_fee_program, onchain_output_fee_program)
		VALUES (100, '0.1', '0.2', '0.3', '0.4');`)
		require.NoError(t, err)

		// start_time deliberately in the past (1_600_000_000 = 2020) to prove the
		// future-start validation no longer blocks the seed.
		_, err = db.Exec(`
		INSERT INTO scheduled_session
			(start_time, end_time, period, duration, round_min_participants,
			 round_max_participants, updated_at)
		VALUES (1600000000, 1600003600, 3600, 60, 2, 5, 1600000000);`)
		require.NoError(t, err)

		defaults := validSeedDefaults(t)
		require.NoError(t, sqlitedb.SeedSettings(ctx, db, defaults))

		// Legacy fees + session carried into the settings row.
		var (
			batchOffchainIn string
			batchOnchainIn  string
			ssStart         int64
			ssPeriod        int64
			ssRoundMin      int64
		)
		err = db.QueryRow(`
		SELECT batch_offchain_input_fee, batch_onchain_input_fee,
		       scheduled_session_start_time, scheduled_session_period,
		       scheduled_session_round_min_participants_count
		FROM settings WHERE id = 1`).
			Scan(&batchOffchainIn, &batchOnchainIn, &ssStart, &ssPeriod, &ssRoundMin)
		require.NoError(t, err)
		require.Equal(t, "0.1", batchOffchainIn)
		require.Equal(t, "0.2", batchOnchainIn)
		require.Equal(t, int64(1600000000), ssStart)
		require.Equal(t, int64(3600), ssPeriod)
		require.Equal(t, int64(2), ssRoundMin)

		// Legacy tables consumed (emptied).
		var feeCount, ssCount int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM intent_fees`).Scan(&feeCount))
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM scheduled_session`).Scan(&ssCount))
		require.Equal(t, 0, feeCount)
		require.Equal(t, 0, ssCount)
	})

	t.Run("idempotent", func(t *testing.T) {
		ctx := t.Context()
		db, err := sqlitedb.OpenDb(":memory:")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		createSettingsTable(t, db)
		createLegacyTables(t, db)

		defaults := validSeedDefaults(t)
		require.NoError(t, sqlitedb.SeedSettings(ctx, db, defaults))

		// Simulate an admin change after the first seed.
		_, err = db.Exec(`UPDATE settings SET session_duration = 999 WHERE id = 1`)
		require.NoError(t, err)

		// A late-arriving legacy row must NOT be re-applied on the second run.
		_, err = db.Exec(`
		INSERT INTO intent_fees
			(created_at, offchain_input_fee_program, onchain_input_fee_program,
			 offchain_output_fee_program, onchain_output_fee_program)
		VALUES (200, '9', '9', '9', '9');`)
		require.NoError(t, err)

		require.NoError(t, sqlitedb.SeedSettings(ctx, db, defaults))

		var sessionDuration int64
		var batchOffchainIn string
		err = db.QueryRow(`
		SELECT session_duration, batch_offchain_input_fee FROM settings WHERE id = 1`).
			Scan(&sessionDuration, &batchOffchainIn)
		require.NoError(t, err)
		require.Equal(t, int64(999), sessionDuration) // admin change preserved
		require.Equal(t, "", batchOffchainIn)         // late legacy row NOT applied

		// The gate short-circuits before the delete, so the late legacy row is left intact.
		var feeCount int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM intent_fees`).Scan(&feeCount))
		require.Equal(t, 1, feeCount)
	})
}

// validSeedDefaults returns a fully-valid domain.Settings to use as the config
// defaults fed into SeedSettings.
func validSeedDefaults(t *testing.T) domain.Settings {
	t.Helper()
	exit, rounded := arklib.ParseRelativeLocktime(512)
	require.False(t, rounded)
	tree, rounded := arklib.ParseRelativeLocktime(1024)
	require.False(t, rounded)
	boarding, rounded := arklib.ParseRelativeLocktime(1536)
	require.False(t, rounded)
	return domain.Settings{
		SessionDuration:             30 * time.Second,
		UnrolledVtxoMinExpiryMargin: 30 * time.Second,
		UnilateralExitDelay:         exit,
		PublicUnilateralExitDelay:   exit,
		CheckpointExitDelay:         exit,
		BoardingExitDelay:           boarding,
		VtxoTreeExpiry:              tree,
		RoundMinParticipantsCount:   1,
		RoundMaxParticipantsCount:   10,
		VtxoMinAmount:               1,
		VtxoMaxAmount:               -1,
		UtxoMinAmount:               1,
		UtxoMaxAmount:               -1,
		MaxTxWeight:                 400_000,
		MaxOpReturnOutputs:          3,
		AssetTxMaxWeightRatio:       0.5,
		UpdatedAt:                   time.Unix(1_700_000_000, 0),
	}
}

// createSettingsTable creates the new settings table (copy of the add_settings
// migration) so SeedSettings can write through queries.UpsertSettings.
func createSettingsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    session_duration BIGINT NOT NULL DEFAULT 0,
    unrolled_vtxo_min_expiry_margin BIGINT NOT NULL DEFAULT 0,
    ban_threshold BIGINT NOT NULL DEFAULT 0,
    ban_duration BIGINT NOT NULL DEFAULT 0,
    unilateral_exit_delay BIGINT NOT NULL DEFAULT 0,
    public_unilateral_exit_delay BIGINT NOT NULL DEFAULT 0,
    checkpoint_exit_delay BIGINT NOT NULL DEFAULT 0,
    boarding_exit_delay BIGINT NOT NULL DEFAULT 0,
    vtxo_tree_expiry BIGINT NOT NULL DEFAULT 0,
    round_min_participants_count BIGINT NOT NULL DEFAULT 0,
    round_max_participants_count BIGINT NOT NULL DEFAULT 0,
    vtxo_min_amount BIGINT NOT NULL DEFAULT 0,
    vtxo_max_amount BIGINT NOT NULL DEFAULT 0,
    utxo_min_amount BIGINT NOT NULL DEFAULT 0,
    utxo_max_amount BIGINT NOT NULL DEFAULT 0,
    settlement_min_expiry_gap BIGINT NOT NULL DEFAULT 0,
    vtxo_no_csv_validation_cutoff_date BIGINT NOT NULL DEFAULT 0,
    max_tx_weight BIGINT NOT NULL DEFAULT 0,
    max_op_return_outputs BIGINT NOT NULL DEFAULT 0,
    asset_tx_max_weight_ratio REAL NOT NULL DEFAULT 0,
    note_uri_prefix TEXT NOT NULL DEFAULT '',
    scheduled_session_start_time BIGINT NOT NULL DEFAULT 0,
    scheduled_session_end_time BIGINT NOT NULL DEFAULT 0,
    scheduled_session_period BIGINT NOT NULL DEFAULT 0,
    scheduled_session_duration BIGINT NOT NULL DEFAULT 0,
    scheduled_session_round_min_participants_count BIGINT NOT NULL DEFAULT 0,
    scheduled_session_round_max_participants_count BIGINT NOT NULL DEFAULT 0,
    batch_onchain_input_fee TEXT NOT NULL DEFAULT '',
    batch_offchain_input_fee TEXT NOT NULL DEFAULT '',
    batch_onchain_output_fee TEXT NOT NULL DEFAULT '',
    batch_offchain_output_fee TEXT NOT NULL DEFAULT '',
    updated_at BIGINT NOT NULL
);`)
	require.NoError(t, err)
}

// createLegacyTables creates the legacy intent_fees and scheduled_session tables.
func createLegacyTables(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS intent_fees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at BIGINT NOT NULL DEFAULT 0,
    offchain_input_fee_program TEXT NOT NULL DEFAULT '',
    onchain_input_fee_program TEXT NOT NULL DEFAULT '',
    offchain_output_fee_program TEXT NOT NULL DEFAULT '',
    onchain_output_fee_program TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scheduled_session (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time INTEGER NOT NULL,
    end_time INTEGER NOT NULL,
    period INTEGER NOT NULL,
    duration INTEGER NOT NULL,
    round_min_participants INTEGER NOT NULL DEFAULT 0,
    round_max_participants INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);`)
	require.NoError(t, err)
}
