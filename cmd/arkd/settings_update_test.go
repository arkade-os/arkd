package main

import (
	"encoding/json"
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

// contextWith builds a cli.Context in which the named flags have been set,
// mirroring what urfave/cli does when the user passes them on the command line.
func contextWith(t *testing.T, args ...string) *cli.Context {
	t.Helper()

	set := flag.NewFlagSet("settings-update", flag.ContinueOnError)
	for _, f := range updateSettingsCmd.Flags {
		require.NoError(t, f.Apply(set))
	}
	require.NoError(t, set.Parse(args))

	return cli.NewContext(cli.NewApp(), set, nil)
}

// TestBuildSettingsUpdateEncodesBoolsAsBools is the regression test for a bug
// that no unit test could have caught and that only surfaced against a running
// arkd: epoch_expiry_enabled was listed among the int-valued flags, so enabling
// it posted "epochExpiryEnabled":0 and the server rejected the whole update with
//
//	invalid value for bool field epochExpiryEnabled: 0
//
// The setting could not be turned on at all from the CLI, which is the only way
// an operator turns it on.
func TestBuildSettingsUpdateEncodesBoolsAsBools(t *testing.T) {
	t.Run("enabling sends a JSON true", func(t *testing.T) {
		ctx := contextWith(t, "--epoch-expiry-enabled")

		settings, err := buildSettingsUpdate(ctx)
		require.NoError(t, err)
		require.Equal(t, true, settings["epochExpiryEnabled"])

		// The server decodes this with protojson, which accepts true/false and
		// nothing else for a bool field. Assert on the encoded form, since that is
		// what actually crossed the wire.
		encoded, err := json.Marshal(settings)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"epochExpiryEnabled":true`)
	})

	t.Run("disabling sends a JSON false, not an omission", func(t *testing.T) {
		ctx := contextWith(t, "--epoch-expiry-enabled=false")

		settings, err := buildSettingsUpdate(ctx)
		require.NoError(t, err)
		require.Equal(t, false, settings["epochExpiryEnabled"])

		encoded, err := json.Marshal(settings)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"epochExpiryEnabled":false`)
	})

	t.Run("an unset flag is omitted, keeping updates partial", func(t *testing.T) {
		ctx := contextWith(t, "--epoch-length", "600")

		settings, err := buildSettingsUpdate(ctx)
		require.NoError(t, err)
		require.NotContains(t, settings, "epochExpiryEnabled")
	})
}

// TestBuildSettingsUpdateEpochFieldTypes pins the JSON type of every epoch
// setting. Getting one wrong is rejected by the server rather than ignored, and
// the failure only appears against a live arkd.
func TestBuildSettingsUpdateEpochFieldTypes(t *testing.T) {
	ctx := contextWith(t,
		"--epoch-expiry-enabled",
		"--epoch-anchor", "1767571200",
		"--epoch-length", "2419200",
		"--rollover-window", "604800",
		"--settlement-cutoff", "43200",
		"--unroll-grace", "7168",
	)

	settings, err := buildSettingsUpdate(ctx)
	require.NoError(t, err)

	require.IsType(t, true, settings["epochExpiryEnabled"])
	for _, key := range []string{
		"epochAnchor", "epochLength", "rolloverWindow", "settlementCutoff", "unrollGrace",
	} {
		require.Contains(t, settings, key)
		require.IsType(t, int(0), settings[key], "%s must be numeric", key)
	}
}

// TestBuildSettingsUpdateRejectsEmptyUpdate keeps the CLI from posting a body
// that would clear nothing and report success.
func TestBuildSettingsUpdateRejectsEmptyUpdate(t *testing.T) {
	_, err := buildSettingsUpdate(contextWith(t))
	require.ErrorContains(t, err, "no settings provided")
}
