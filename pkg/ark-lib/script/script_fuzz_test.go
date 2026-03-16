package script_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/stretchr/testify/require"
)

func FuzzDecodeClosure(f *testing.F) {
	for _, fixture := range validDecodeClosureVectors() {
		scriptBytes, err := hex.DecodeString(fixture.script)
		require.NoError(f, err)
		f.Add(scriptBytes)
	}

	for _, fixture := range invalidDecodeClosureVectors() {
		scriptBytes, err := hex.DecodeString(fixture.script)
		require.NoError(f, err)
		f.Add(scriptBytes)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		closure, err := script.DecodeClosure(data)
		if err != nil {
			return
		}
		require.NotNil(t, closure, "decode returned nil closure without error")

		rebuilt, err := closure.Script()
		require.NoErrorf(t, err, "closure serialization failed: %v", err)

		closureRoundTrip, err := script.DecodeClosure(rebuilt)
		require.NoErrorf(t, err, "roundtrip decode failed: %v closure=%#v", err, closure)

		_, err = closureRoundTrip.Script()
		require.NoErrorf(t, err, "roundtrip closure serialization failed: %v", err)
	})
}
