package sqlitedb

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// TestParseMarkersJSON_LogsOnMalformed verifies that parseMarkersJSON emits a
// warn log on malformed JSON (instead of silently swallowing the unmarshal
// error and returning nil). Surfacing corrupt markers is important so that
// operators can detect data corruption rather than having it masquerade as
// "no markers present".
func TestParseMarkersJSON_LogsOnMalformed(t *testing.T) {
	t.Run("malformed_json_logs_warning", func(t *testing.T) {
		hook := test.NewGlobal()
		t.Cleanup(func() {
			hook.Reset()
			log.SetOutput(log.StandardLogger().Out) // restore default
		})

		got := parseMarkersJSON(`not-valid-json`)
		require.Nil(t, got, "malformed JSON must still return nil for compatibility")

		entries := hook.AllEntries()
		require.NotEmpty(t, entries, "expected a warn log for malformed markers JSON")

		var matched bool
		for _, e := range entries {
			if e.Level == log.WarnLevel &&
				e.Message != "" &&
				containsAll(e.Message, "failed to parse markers JSON") {
				matched = true
				break
			}
		}
		require.True(t, matched,
			"expected a warn entry mentioning 'failed to parse markers JSON', got: %v",
			hook.AllEntries())
	})

	t.Run("empty_input_no_log", func(t *testing.T) {
		hook := test.NewGlobal()
		t.Cleanup(func() {
			hook.Reset()
		})

		got := parseMarkersJSON("")
		require.Nil(t, got)
		require.Empty(t, hook.AllEntries(),
			"empty input is not an error and must not log")
	})

	t.Run("valid_json_no_log", func(t *testing.T) {
		hook := test.NewGlobal()
		t.Cleanup(func() {
			hook.Reset()
		})

		got := parseMarkersJSON(`["m1","m2"]`)
		require.Equal(t, []string{"m1", "m2"}, got)
		require.Empty(t, hook.AllEntries(),
			"valid input must not log")
	})
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
