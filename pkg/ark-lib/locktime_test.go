package arklib_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

func block(v uint32) arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: v}
}

func seconds(v uint32) arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: v}
}

func TestAbsoluteLocktimeIsSeconds(t *testing.T) {
	// Values >= 500_000_000 (nLocktimeMinSeconds) are interpreted as seconds,
	// below that as block heights.
	tests := []struct {
		name     string
		locktime arklib.AbsoluteLocktime
		expected bool
	}{
		{"zero is a block height", 0, false},
		{"just below the threshold is a block height", 499_999_999, false},
		{"exactly at the threshold is seconds", 500_000_000, true},
		{"above the threshold is seconds", 600_000_000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.locktime.IsSeconds())
		})
	}
}

func TestRelativeLocktimeSeconds(t *testing.T) {
	// SECONDS_PER_BLOCK is 1, so both block- and seconds-based locktimes report
	// their raw value as seconds.
	tests := []struct {
		name     string
		locktime arklib.RelativeLocktime
		expected int64
	}{
		{"block locktime returns its value", block(100), 100},
		{"seconds locktime returns its value", seconds(512), 512},
		{"zero block locktime returns zero", block(0), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.locktime.Seconds())
		})
	}
}

func TestRelativeLocktimeCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        arklib.RelativeLocktime
		b        arklib.RelativeLocktime
		expected int
	}{
		{"equal same type", seconds(512), seconds(512), 0},
		{"equal across types (1 sec per block)", block(512), seconds(512), 0},
		{"less than", block(100), seconds(512), -1},
		{"greater than", seconds(1024), block(512), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.a.Compare(tt.b))
		})
	}
}

func TestRelativeLocktimeLessThan(t *testing.T) {
	tests := []struct {
		name     string
		a        arklib.RelativeLocktime
		b        arklib.RelativeLocktime
		expected bool
	}{
		{"less than is true", block(100), seconds(512), true},
		{"equal is false", seconds(512), seconds(512), false},
		{"greater than is false", seconds(1024), block(512), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.a.LessThan(tt.b))
		})
	}
}

func TestBIP68Sequence(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name     string
			locktime arklib.RelativeLocktime
			expected uint32
		}{
			{"block based is the raw value", block(144), 144},
			{"block based is unconstrained", block(1000), 1000},
			{"seconds zero", seconds(0), arklib.SEQUENCE_LOCKTIME_TYPE_FLAG},
			{"seconds one granularity step", seconds(512), arklib.SEQUENCE_LOCKTIME_TYPE_FLAG | 1},
			{"seconds two granularity steps", seconds(1024), arklib.SEQUENCE_LOCKTIME_TYPE_FLAG | 2},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := arklib.BIP68Sequence(tt.locktime)
				require.NoError(t, err)
				require.Equal(t, tt.expected, got)
			})
		}

		t.Run("block locktimes roundtrip", func(t *testing.T) {
			for value := uint32(0); value <= arklib.SEQUENCE_LOCKTIME_MASK; value++ {
				loctime := arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeBlock,
					Value: value,
				}
				val, err := arklib.BIP68Sequence(loctime)
				require.NoError(t, err)

				gotLocktime, disabled := arklib.BIP68DecodeSequence(val)
				require.False(t, disabled)
				require.Equal(t, loctime, *gotLocktime)
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			locktime    arklib.RelativeLocktime
			errContains string
		}{
			{
				"seconds above the max",
				seconds(arklib.SECONDS_MAX + arklib.SECONDS_MOD),
				"seconds too large",
			},
			{
				"seconds not a multiple of the granularity",
				seconds(513),
				"must be a multiple",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := arklib.BIP68Sequence(tt.locktime)
				require.ErrorContains(t, err, tt.errContains)
			})
		}
	})
}

func TestParseRelativeLocktime(t *testing.T) {
	// Values below MinAllowedSequence (512) are blocks; at/above it they are
	// seconds, rounded down to a multiple of 512 (reporting whether rounding
	// happened).
	tests := []struct {
		name         string
		value        uint32
		expected     arklib.RelativeLocktime
		wantModified bool
	}{
		{"zero is a block locktime", 0, block(0), false},
		{"below the threshold is a block locktime", 256, block(256), false},
		{"exactly the threshold is seconds, unmodified", 512, seconds(512), false},
		{"exact multiple is seconds, unmodified", 1024, seconds(1024), false},
		{"non-multiple is rounded down to seconds", 600, seconds(512), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, modified := arklib.ParseRelativeLocktime(tt.value)
			require.Equal(t, tt.expected, got)
			require.Equal(t, tt.wantModified, modified)
		})
	}
}

func TestBIP68DecodeSequence(t *testing.T) {
	// Returns (locktime, disabled). When the disable flag is set the locktime is
	// nil. Note the seconds path subtracts 1 from the decoded value.
	tests := []struct {
		name         string
		sequence     uint32
		wantDisabled bool
		expected     arklib.RelativeLocktime
	}{
		{"disable flag set", arklib.SEQUENCE_LOCKTIME_DISABLE_FLAG, true, arklib.RelativeLocktime{}},
		{"block based", 100, false, block(100)},
		{"block zero", 0, false, block(0)},
		{"seconds one granularity step", arklib.SEQUENCE_LOCKTIME_TYPE_FLAG | 1, false, seconds(511)},
		{"seconds two granularity steps", arklib.SEQUENCE_LOCKTIME_TYPE_FLAG | 2, false, seconds(1023)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, disabled := arklib.BIP68DecodeSequence(tt.sequence)
			require.Equal(t, tt.wantDisabled, disabled)
			if tt.wantDisabled {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.expected, *got)
		})
	}
}

func TestBIP68DecodeSequenceFromBytes(t *testing.T) {
	// Inputs are the minimal little-endian script-number encodings of a sequence,
	// exactly as they appear on the stack.
	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name     string
			sequence []byte
			expected arklib.RelativeLocktime
		}{
			// 100 (block based, no flags).
			{"block based", []byte{0x64}, block(100)},
			// 0x400001 = SEQUENCE_LOCKTIME_TYPE_FLAG | 1 -> (1 << 9) seconds.
			{"seconds based", []byte{0x01, 0x00, 0x40}, seconds(512)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := arklib.BIP68DecodeSequenceFromBytes(tt.sequence)
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.expected, *got)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			sequence    []byte
			errContains string
		}{
			// 0x80000001 = SEQUENCE_LOCKTIME_DISABLE_FLAG | 1 (trailing 0x00 sign byte).
			{
				"disable flag set",
				[]byte{0x01, 0x00, 0x00, 0x80, 0x00},
				"disabled",
			},
			{
				"non-minimally encoded number",
				[]byte{0x00},
				"",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := arklib.BIP68DecodeSequenceFromBytes(tt.sequence)
				require.Error(t, err)
				if tt.errContains != "" {
					require.ErrorContains(t, err, tt.errContains)
				}
			})
		}
	})
}
