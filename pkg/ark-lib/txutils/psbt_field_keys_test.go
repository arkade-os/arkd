package txutils_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// An ark field key must be matched exactly. A key that merely contains a field
// name is read as that field by a lenient matcher but not by a consumer
// comparing keys exactly, and the two then disagree over whether a condition
// witness, such as a vHTLC preimage, was revealed at all.
func TestArkPsbtFieldKeyMatching(t *testing.T) {
	preimage := bytes.Repeat([]byte{0xAB}, 32)

	t.Run("accepts both supported condition encodings", func(t *testing.T) {
		for _, key := range [][]byte{
			withKeyType("condition"), // canonical
			[]byte("condition"),      // legacy, no key type prefix
		} {
			ptx := newSingleInputPsbt(t, conditionUnknown(t, key, wire.TxWitness{preimage}))

			fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.ConditionWitnessField)
			require.NoError(t, err)
			require.Len(t, fields, 1, "key %q must be accepted", key)
			require.Equal(t, preimage, []byte(fields[0][0]))
		}
	})

	t.Run("rejects keys that only contain the field name", func(t *testing.T) {
		for _, key := range [][]byte{
			[]byte("xcondition"),
			withKeyType("xcondition"),
			[]byte("conditionAAAA"),
			withKeyType("conditionAAAA"),
			[]byte("zzzconditionzzz"),
			append([]byte{0x01}, []byte("condition")...), // wrong key type byte
			[]byte("conditio"),
			{},
		} {
			ptx := newSingleInputPsbt(t, conditionUnknown(t, key, wire.TxWitness{preimage}))

			fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.ConditionWitnessField)
			require.NoError(t, err)
			require.Empty(t, fields, "key %q must be rejected", key)
		}
	})

	// A single key long enough to contain two field names must not decode as
	// both of them.
	t.Run("one key never satisfies two field types", func(t *testing.T) {
		ptx := newSingleInputPsbt(
			t, conditionUnknown(t, []byte("condition-expiry"), wire.TxWitness{preimage}),
		)

		conditions, err := txutils.GetArkPsbtFields(ptx, 0, txutils.ConditionWitnessField)
		require.NoError(t, err)
		require.Empty(t, conditions)

		expiries, err := txutils.GetArkPsbtFields(ptx, 0, txutils.VtxoTreeExpiryField)
		require.NoError(t, err)
		require.Empty(t, expiries)
	})

	// A hostile unknown field must not be able to make an unrelated decoder
	// fail: before exact matching this key reached the cosigner decoder and
	// failed pubkey parsing, turning any psbt carrying it into a hard error.
	t.Run("hostile field does not poison the cosigner decoder", func(t *testing.T) {
		ptx := newSingleInputPsbt(t, &psbt.Unknown{
			Key:   []byte("condition-cosigner"),
			Value: []byte("not-a-valid-pubkey"),
		})

		fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.CosignerPublicKeyField)
		require.NoError(t, err)
		require.Empty(t, fields)
	})

	// The cosigner key is the only one carrying data after the field name, so
	// exact matching has to allow its index without allowing arbitrary trailing
	// bytes.
	t.Run("cosigner key keeps its index suffix", func(t *testing.T) {
		ptx := newSingleInputPsbt(t)

		for i := range 3 {
			key, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			require.NoError(t, txutils.SetArkPsbtField(
				ptx, 0, txutils.CosignerPublicKeyField,
				txutils.IndexedCosignerPublicKey{Index: i, PublicKey: key.PubKey()},
			))
		}

		fields, err := txutils.GetArkPsbtFields(ptx, 0, txutils.CosignerPublicKeyField)
		require.NoError(t, err)
		require.Len(t, fields, 3)

		// A cosigner key with the wrong suffix length is not a cosigner key.
		ptx.Inputs[0].Unknowns = []*psbt.Unknown{{
			Key:   append(withKeyType("cosigner"), 0x00, 0x01),
			Value: fields[0].PublicKey.SerializeCompressed(),
		}}
		short, err := txutils.GetArkPsbtFields(ptx, 0, txutils.CosignerPublicKeyField)
		require.NoError(t, err)
		require.Empty(t, short)
	})

	// Stripping the key type byte is only unambiguous while no field name can
	// itself start with that byte.
	t.Run("no field name collides with the key type byte", func(t *testing.T) {
		for _, name := range [][]byte{
			txutils.ArkFieldTaprootTree,
			txutils.ArkFieldTreeExpiry,
			txutils.ArkFieldCosigner,
			txutils.ArkFieldConditionWitness,
		} {
			require.NotEqual(t, byte(txutils.ArkPsbtFieldKeyType), name[0])
		}
	})

	// A non-canonical key must not survive as a condition witness across the
	// re-encode arkd performs when it persists and serves a checkpoint tx.
	t.Run("rejection survives a psbt round trip", func(t *testing.T) {
		ptx := newSingleInputPsbt(
			t, conditionUnknown(t, []byte("xcondition"), wire.TxWitness{preimage}),
		)

		b64, err := ptx.B64Encode()
		require.NoError(t, err)
		reparsed, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
		require.NoError(t, err)

		fields, err := txutils.GetArkPsbtFields(reparsed, 0, txutils.ConditionWitnessField)
		require.NoError(t, err)
		require.Empty(t, fields)
	})
}

// An input carrying two condition witnesses would reveal one value to a
// consumer reading the first field set and another to one looking only for the
// canonical key, so it is rejected rather than resolved.
func TestGetArkPsbtConditionWitness(t *testing.T) {
	preimage := bytes.Repeat([]byte{0xAB}, 32)
	decoy := bytes.Repeat([]byte{0x00}, 32)

	t.Run("returns nil when unset", func(t *testing.T) {
		witness, err := txutils.GetArkPsbtConditionWitness(newSingleInputPsbt(t), 0)
		require.NoError(t, err)
		require.Nil(t, witness)
	})

	// Both accepted encodings are exercised through the accessor itself, not
	// only through GetArkPsbtFields, so that a regression in the key stripping
	// fails the guard protecting the finalizer path rather than only the
	// matcher's own test.
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"canonical key", withKeyType("condition")},
		{"legacy key", []byte("condition")},
	} {
		t.Run("returns the only witness set, "+tc.name, func(t *testing.T) {
			ptx := newSingleInputPsbt(
				t, conditionUnknown(t, tc.key, wire.TxWitness{preimage}),
			)

			witness, err := txutils.GetArkPsbtConditionWitness(ptx, 0)
			require.NoError(t, err)
			require.Len(t, witness, 1)
			require.Equal(t, preimage, witness[0])
		})
	}

	t.Run("rejects both accepted encodings set at once", func(t *testing.T) {
		ptx := newSingleInputPsbt(
			t,
			conditionUnknown(t, []byte("condition"), wire.TxWitness{preimage}),
			conditionUnknown(t, withKeyType("condition"), wire.TxWitness{decoy}),
		)

		_, err := txutils.GetArkPsbtConditionWitness(ptx, 0)
		require.ErrorContains(t, err, "expected at most one")
	})

	t.Run("rejects the same encoding repeated", func(t *testing.T) {
		ptx := newSingleInputPsbt(
			t,
			conditionUnknown(t, withKeyType("condition"), wire.TxWitness{preimage}),
			conditionUnknown(t, withKeyType("condition"), wire.TxWitness{decoy}),
		)

		_, err := txutils.GetArkPsbtConditionWitness(ptx, 0)
		require.ErrorContains(t, err, "expected at most one")
	})

	t.Run("reports an out of range input index", func(t *testing.T) {
		_, err := txutils.GetArkPsbtConditionWitness(newSingleInputPsbt(t), 5)
		require.Error(t, err)
	})
}

func newSingleInputPsbt(t *testing.T, unknowns ...*psbt.Unknown) *psbt.Packet {
	t.Helper()

	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	require.NoError(t, err)
	ptx.UnsignedTx.TxIn = []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{}, Sequence: 0}}
	ptx.Inputs = []psbt.PInput{{Unknowns: unknowns}}
	return ptx
}

func conditionUnknown(t *testing.T, key []byte, witness wire.TxWitness) *psbt.Unknown {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, psbt.WriteTxWitness(&buf, witness))
	return &psbt.Unknown{Key: key, Value: buf.Bytes()}
}

func withKeyType(name string) []byte {
	return append([]byte{txutils.ArkPsbtFieldKeyType}, []byte(name)...)
}
