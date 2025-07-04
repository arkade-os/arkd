package note_test

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/stretchr/testify/require"
)

func TestNewNote(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
	}{
		{
			name:  "zero value",
			value: 0,
		},
		{
			name:  "valid value",
			value: 100,
		},
		{
			name:  "max value",
			value: math.MaxUint32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := note.NewNote(tt.value)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.value, got.Value)
			require.NotNil(t, got.Preimage)
			require.Len(t, got.Preimage, 32)
		})
	}
}

func TestNotePreimageUniqueness(t *testing.T) {
	preimageSet := make(map[string]struct{})
	for i := 0; i < 1_000_000; i++ {
		data, err := note.NewNote(100)
		require.NoError(t, err)
		require.Empty(
			t, preimageSet[hex.EncodeToString(data.Preimage[:])],
			"duplicated preimage: %x", data.Preimage,
		)
		preimageSet[hex.EncodeToString(data.Preimage[:])] = struct{}{}
	}
}

func TestNewNoteFromString(t *testing.T) {
	tests := []struct {
		str              string
		expectedPreimage string
		expectedValue    uint32
	}{
		{
			str:              "arknote8rFzGqZsG9RCLripA6ez8d2hQEzFKsqCeiSnXhQj56Ysw7ZQT",
			expectedPreimage: "11d2a03264d0efd311d2a03264d0efd311d2a03264d0efd311d2a03264d0efd3",
			expectedValue:    900000,
		},
		{
			str:              "arknoteSkB92YpWm4Q2ijQHH34cqbKkCZWszsiQgHVjtNeFF2Cwp59D",
			expectedPreimage: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			expectedValue:    1828932,
		},
	}

	for _, tt := range tests {
		preimage, err := hex.DecodeString(tt.expectedPreimage)
		require.NoError(t, err)
		var preimageArray [32]byte
		copy(preimageArray[:], preimage)

		n := &note.Note{
			Preimage: preimageArray,
			Value:    tt.expectedValue,
		}

		str := n.String()
		require.Equal(t, str, tt.str)

		note, err := note.NewNoteFromString(tt.str)
		require.NoError(t, err)
		require.NotNil(t, note)
		require.Equal(t, preimageArray, note.Preimage)
		require.Equal(t, tt.expectedValue, note.Value)
	}
}
