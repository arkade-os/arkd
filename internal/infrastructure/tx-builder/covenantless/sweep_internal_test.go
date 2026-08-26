package txbuilder

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func testKeys(t *testing.T) script.MultisigClosure {
	t.Helper()
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return script.MultisigClosure{PubKeys: []*btcec.PublicKey{prv.PubKey()}}
}

// TestSweepInputLocktime pins how a sweep input's tapscript leaf maps to the
// nSequence and nLockTime the spending transaction must carry.
func TestSweepInputLocktime(t *testing.T) {
	keys := testKeys(t)
	grace := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
	legacyExpiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604672}
	date := arklib.AbsoluteLocktime(1788134400)

	t.Run("legacy csv leaf yields a sequence and no locktime", func(t *testing.T) {
		raw, err := (&script.CSVMultisigClosure{
			MultisigClosure: keys, Locktime: legacyExpiry,
		}).Script()
		require.NoError(t, err)

		seq, lock, err := sweepInputLocktime(raw)
		require.NoError(t, err)
		require.Zero(t, lock, "a relative-only leaf must not force an nLockTime")

		expected, err := arklib.BIP68Sequence(legacyExpiry)
		require.NoError(t, err)
		require.Equal(t, expected, seq)
	})

	t.Run("epoch leaf yields both", func(t *testing.T) {
		raw, err := (&script.CLTVCSVMultisigClosure{
			MultisigClosure: keys, ExpiryDate: date, UnrollGrace: grace,
		}).Script()
		require.NoError(t, err)

		seq, lock, err := sweepInputLocktime(raw)
		require.NoError(t, err)
		require.Equal(t, uint32(date), lock)

		expected, err := arklib.BIP68Sequence(grace)
		require.NoError(t, err)
		require.Equal(t, expected, seq)
		require.Less(
			t, seq, uint32(0xfffffffe),
			"sequence must stay non-final or CHECKLOCKTIMEVERIFY rejects the spend",
		)
	})

	t.Run("unknown leaf is rejected", func(t *testing.T) {
		raw, err := (&script.MultisigClosure{PubKeys: keys.PubKeys}).Script()
		require.NoError(t, err)
		_, _, err = sweepInputLocktime(raw)
		require.Error(t, err)
	})

	t.Run("garbage is rejected", func(t *testing.T) {
		_, _, err := sweepInputLocktime([]byte{0x01, 0x02, 0x03})
		require.Error(t, err)
	})
}

// TestSweepTxShape assembles the transaction the way sweepTransaction does and
// pins the three properties the script engine requires of it: version 2, an
// nLockTime at or above every input's expiry date, and non-final sequences.
func TestSweepTxShape(t *testing.T) {
	keys := testKeys(t)
	grace := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
	legacyExpiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604672}
	earlier := arklib.AbsoluteLocktime(1788134400)
	later := arklib.AbsoluteLocktime(1790000000)

	leaf := func(t *testing.T, c script.Closure) []byte {
		t.Helper()
		raw, err := c.Script()
		require.NoError(t, err)
		return raw
	}

	build := func(t *testing.T, leaves [][]byte) *psbt.Packet {
		t.Helper()
		ins := make([]*wire.OutPoint, 0, len(leaves))
		sequences := make([]uint32, 0, len(leaves))
		maxLockTime := uint32(0)

		for i, l := range leaves {
			ins = append(ins, &wire.OutPoint{Hash: chainhash.Hash{byte(i)}, Index: uint32(i)})
			seq, lock, err := sweepInputLocktime(l)
			require.NoError(t, err)
			sequences = append(sequences, seq)
			if lock > maxLockTime {
				maxLockTime = lock
			}
		}

		ptx, err := psbt.New(ins, nil, 2, maxLockTime, sequences)
		require.NoError(t, err)
		return ptx
	}

	t.Run("legacy only leaves nLockTime at zero", func(t *testing.T) {
		ptx := build(t, [][]byte{
			leaf(t, &script.CSVMultisigClosure{MultisigClosure: keys, Locktime: legacyExpiry}),
		})
		require.Equal(t, uint32(0), ptx.UnsignedTx.LockTime)
		require.Equal(t, int32(2), ptx.UnsignedTx.Version)
	})

	t.Run("epoch inputs take the highest expiry date", func(t *testing.T) {
		ptx := build(t, [][]byte{
			leaf(t, &script.CLTVCSVMultisigClosure{
				MultisigClosure: keys, ExpiryDate: earlier, UnrollGrace: grace,
			}),
			leaf(t, &script.CLTVCSVMultisigClosure{
				MultisigClosure: keys, ExpiryDate: later, UnrollGrace: grace,
			}),
		})
		require.Equal(t, uint32(later), ptx.UnsignedTx.LockTime)

		for i, in := range ptx.UnsignedTx.TxIn {
			require.Less(t, in.Sequence, uint32(0xfffffffe), "input %d must be non-final", i)
		}
	})
}
