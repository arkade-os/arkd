package varint_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/internal/varint"
	"github.com/stretchr/testify/require"
)

func TestReadCanonical(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want uint64
	}{
		{"zero", []byte{0x00}, 0},
		{"one", []byte{0x01}, 1},
		{"max-single-group", []byte{0x7f}, 127},
		{"two-bytes-300", []byte{0xac, 0x02}, 300},
		{"max-uint64", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, math.MaxUint64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := bytes.NewReader(c.in)
			got, err := varint.ReadCanonical(r)
			require.NoError(t, err)
			require.Equal(t, c.want, got)
			require.Equal(t, 0, r.Len(), "must consume exactly the varint bytes")
		})
	}
}

func TestReadCanonicalRejectsNonMinimal(t *testing.T) {
	cases := map[string][]byte{
		"overlong-zero":       {0x80, 0x00},
		"overlong-one":        {0x81, 0x00},
		"overlong-300":        {0xac, 0x82, 0x00},
		"trailing-zero-group": {0x80, 0x80, 0x00},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			r := bytes.NewReader(in)
			_, err := varint.ReadCanonical(r)
			require.ErrorIs(t, err, varint.ErrNonMinimal)
		})
	}
}

func TestReadCanonicalRejectsOverflow(t *testing.T) {
	// 10th byte > 1 overflows a 64-bit integer (delegated to binary.ReadUvarint).
	in := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}
	r := bytes.NewReader(in)
	_, err := varint.ReadCanonical(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "overflow")
}
