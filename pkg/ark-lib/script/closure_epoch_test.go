package script_test

import (
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// 1 Sep 2026 00:00:00 UTC. 7168 == 14 * 512, a BIP68-representable seconds value.
const (
	testEpochExpiry = arklib.AbsoluteLocktime(1788134400)
	testGraceSecs   = uint32(7168)
)

func testGrace() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: testGraceSecs}
}

func testEpochClosure(pub *btcec.PublicKey) *script.CLTVCSVMultisigClosure {
	return &script.CLTVCSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{pub}},
		ExpiryDate:      testEpochExpiry,
		UnrollGrace:     testGrace(),
	}
}

func TestCLTVCSVMultisigClosureRoundTrip(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	original := testEpochClosure(prv.PubKey())
	raw, err := original.Script()
	require.NoError(t, err)

	decoded := &script.CLTVCSVMultisigClosure{}
	valid, err := decoded.Decode(raw)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, original.ExpiryDate, decoded.ExpiryDate)
	require.Equal(t, original.UnrollGrace, decoded.UnrollGrace)
	require.Len(t, decoded.PubKeys, 1)
	require.Equal(
		t, schnorr.SerializePubKey(original.PubKeys[0]), schnorr.SerializePubKey(decoded.PubKeys[0]),
	)
}

// TestCLTVCSVMultisigClosureBeyond2038 pins that the absolute locktime is not
// narrowed through int32. CLTVMultisigClosure.Decode does narrow, which breaks
// for nLockTime timestamps past 2038; the hybrid must not inherit that.
func TestCLTVCSVMultisigClosureBeyond2038(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// 1 Jan 2040 00:00:00 UTC, above math.MaxInt32 (2147483647)
	future := arklib.AbsoluteLocktime(2208988800)
	original := &script.CLTVCSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{prv.PubKey()}},
		ExpiryDate:      future,
		UnrollGrace:     testGrace(),
	}
	raw, err := original.Script()
	require.NoError(t, err)

	decoded := &script.CLTVCSVMultisigClosure{}
	valid, err := decoded.Decode(raw)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, future, decoded.ExpiryDate)
}

func TestCLTVCSVMultisigClosureDisambiguation(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	keys := script.MultisigClosure{PubKeys: []*btcec.PublicKey{prv.PubKey()}}

	hybrid := testEpochClosure(prv.PubKey())
	csvOnly := &script.CSVMultisigClosure{MultisigClosure: keys, Locktime: testGrace()}
	cltvOnly := &script.CLTVMultisigClosure{MultisigClosure: keys, Locktime: testEpochExpiry}

	t.Run("hybrid decodes as hybrid", func(t *testing.T) {
		raw, err := hybrid.Script()
		require.NoError(t, err)
		got, err := script.DecodeClosure(raw)
		require.NoError(t, err)
		require.IsType(t, &script.CLTVCSVMultisigClosure{}, got)
	})

	t.Run("csv still decodes as csv", func(t *testing.T) {
		raw, err := csvOnly.Script()
		require.NoError(t, err)
		got, err := script.DecodeClosure(raw)
		require.NoError(t, err)
		require.IsType(t, &script.CSVMultisigClosure{}, got)
	})

	t.Run("cltv still decodes as cltv", func(t *testing.T) {
		raw, err := cltvOnly.Script()
		require.NoError(t, err)
		got, err := script.DecodeClosure(raw)
		require.NoError(t, err)
		require.IsType(t, &script.CLTVMultisigClosure{}, got)
	})

	t.Run("hybrid is not accepted by the narrower types", func(t *testing.T) {
		raw, err := hybrid.Script()
		require.NoError(t, err)

		csv := &script.CSVMultisigClosure{}
		valid, _ := csv.Decode(raw)
		require.False(t, valid)

		cltv := &script.CLTVMultisigClosure{}
		valid, _ = cltv.Decode(raw)
		require.False(t, valid)

		plain := &script.MultisigClosure{}
		valid, _ = plain.Decode(raw)
		require.False(t, valid)
	})

	t.Run("narrower scripts are not accepted by the hybrid", func(t *testing.T) {
		for name, c := range map[string]script.Closure{"csv": csvOnly, "cltv": cltvOnly} {
			raw, err := c.Script()
			require.NoError(t, err, name)

			h := &script.CLTVCSVMultisigClosure{}
			valid, _ := h.Decode(raw)
			require.False(t, valid, name)
		}
	})
}

// spendHybrid locks a taproot output to the hybrid leaf and spends it, returning
// the script engine's verdict.
func spendHybrid(
	t *testing.T, prv *btcec.PrivateKey, lockTime uint32, sequence uint32, version int32,
) error {
	t.Helper()

	leafScript, err := testEpochClosure(prv.PubKey()).Script()
	require.NoError(t, err)

	tapLeaf := txscript.NewBaseTapLeaf(leafScript)
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	root := tapTree.RootNode.TapHash()
	internalKey := script.UnspendableKey()
	pkScript, err := script.P2TRScript(txscript.ComputeTaprootOutputKey(internalKey, root[:]))
	require.NoError(t, err)

	const prevValue = int64(100_000)

	tx := wire.NewMsgTx(version)
	tx.LockTime = lockTime
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0},
		Sequence:         sequence,
	})
	tx.AddTxOut(&wire.TxOut{Value: prevValue - 1000, PkScript: pkScript})

	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, prevValue)
	sig, err := txscript.RawTxInTapscriptSignature(
		tx, txscript.NewTxSigHashes(tx, fetcher), 0, prevValue, pkScript,
		tapLeaf, txscript.SigHashDefault, prv,
	)
	require.NoError(t, err)

	ctrlBlock := tapTree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	ctrl, err := ctrlBlock.ToBytes()
	require.NoError(t, err)
	tx.TxIn[0].Witness = wire.TxWitness{sig, leafScript, ctrl}

	vm, err := txscript.NewEngine(
		pkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), prevValue, fetcher,
	)
	if err != nil {
		return err
	}
	return vm.Execute()
}

// TestCLTVCSVMultisigClosureExecutes pins the exact transaction shape a sweep
// spending this leaf must have: version 2, nLockTime at or after the expiry
// date, and a non-final BIP68 sequence at or above the grace period.
func TestCLTVCSVMultisigClosureExecutes(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	seq, err := arklib.BIP68Sequence(testGrace())
	require.NoError(t, err)

	t.Run("valid spend", func(t *testing.T) {
		require.NoError(t, spendHybrid(t, prv, uint32(testEpochExpiry), seq, 2))
	})
	t.Run("nLockTime before expiry fails", func(t *testing.T) {
		require.Error(t, spendHybrid(t, prv, uint32(testEpochExpiry)-1, seq, 2))
	})
	t.Run("final sequence fails CLTV", func(t *testing.T) {
		require.Error(t, spendHybrid(t, prv, uint32(testEpochExpiry), wire.MaxTxInSequenceNum, 2))
	})
	t.Run("sequence below grace fails CSV", func(t *testing.T) {
		small, err := arklib.BIP68Sequence(
			arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		)
		require.NoError(t, err)
		require.Error(t, spendHybrid(t, prv, uint32(testEpochExpiry), small, 2))
	})
	t.Run("tx version 1 fails CSV", func(t *testing.T) {
		require.Error(t, spendHybrid(t, prv, uint32(testEpochExpiry), seq, 1))
	})
}

// TestCLTVCSVMultisigClosureWitness guards the wallet's finalizer path: it calls
// DecodeClosure then Closure.Witness to build the final witness, so a closure
// whose Witness returns the bare multisig script would make the operator unable
// to finalize its own sweep.
func TestCLTVCSVMultisigClosureWitness(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	closure := testEpochClosure(prv.PubKey())
	raw, err := closure.Script()
	require.NoError(t, err)

	ctrl := make([]byte, 33)
	sigs := map[string][]byte{
		hex.EncodeToString(schnorr.SerializePubKey(prv.PubKey())): make([]byte, 64),
	}
	witness, err := closure.Witness(ctrl, sigs)
	require.NoError(t, err)
	require.Len(t, witness, 3)
	require.Equal(
		t, raw, []byte(witness[len(witness)-2]),
		"witness must carry the hybrid script, not the bare multisig script",
	)
	require.Equal(t, ctrl, []byte(witness[len(witness)-1]))

	t.Run("missing signature is an error", func(t *testing.T) {
		_, err := closure.Witness(ctrl, map[string][]byte{})
		require.Error(t, err)
	})
}
