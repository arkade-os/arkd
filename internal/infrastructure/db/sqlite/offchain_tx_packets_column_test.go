package sqlitedb

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// The domain layer distinguishes nil packets, meaning not yet decoded, from an
// empty slice, meaning decoded and carrying no extensions. The backfill scans
// for the former, so a read that collapses the two would make every
// no-extension row look like it still needs backfilling.
func TestDecodePacketsColumn(t *testing.T) {
	for _, tc := range []struct {
		name string
		col  sql.NullString
		want []int
	}{
		{
			name: "null is not yet decoded",
			col:  sql.NullString{},
			want: nil,
		},
		{
			name: "empty is decoded with no extensions",
			col:  sql.NullString{String: "", Valid: true},
			want: []int{},
		},
		{
			name: "single packet type",
			col:  sql.NullString{String: "3", Valid: true},
			want: []int{3},
		},
		{
			name: "multiple packet types",
			col:  sql.NullString{String: "1,2,255", Valid: true},
			want: []int{1, 2, 255},
		},
		{
			name: "surrounding whitespace is tolerated",
			col:  sql.NullString{String: " 1 , 2 ", Valid: true},
			want: []int{1, 2},
		},
		{
			name: "non-integer entries are skipped rather than failing the read",
			col:  sql.NullString{String: "1,bogus,2", Valid: true},
			want: []int{1, 2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decodePacketsColumn(tc.col)

			require.Equal(t, tc.want, got)
			// Equal treats nil and []int{} as different, but be explicit since
			// this distinction is the whole point of the test.
			require.Equal(t, tc.want == nil, got == nil)
		})
	}
}
