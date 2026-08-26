package tree_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// TestBuildLegacySweepTapTreeRootMatchesHandRolled is the guard that makes
// centralising the sweep root a safe refactor: the constructor must produce
// output byte-identical to the code it replaces. A moved root means every tree
// built against it is unspendable by the operator.
func TestBuildLegacySweepTapTreeRootMatchesHandRolled(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604672}

	// exactly what BuildCommitmentTx did inline
	want, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{prv.PubKey()}},
		Locktime:        expiry,
	}).Script()
	require.NoError(t, err)
	wantRoot := txscript.NewBaseTapLeaf(want).TapHash()

	gotRoot, gotScript, err := tree.BuildLegacySweepTapTreeRoot(prv.PubKey(), expiry)
	require.NoError(t, err)
	require.Equal(t, want, gotScript)
	require.Equal(t, wantRoot, gotRoot, "must be byte-identical to the existing root")
}

// TestBuildLegacySweepTapTreeRootMatchesAssembledTree pins the other inline form
// the codebase used: AssembleTaprootScriptTree(...).RootNode.TapHash(). For a
// single leaf the two must agree, which is why one constructor can replace both.
func TestBuildLegacySweepTapTreeRootMatchesAssembledTree(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604672}

	leafScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{prv.PubKey()}},
		Locktime:        expiry,
	}).Script()
	require.NoError(t, err)

	assembled := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leafScript))
	wantRoot := assembled.RootNode.TapHash()

	gotRoot, _, err := tree.BuildLegacySweepTapTreeRoot(prv.PubKey(), expiry)
	require.NoError(t, err)
	require.Equal(t, wantRoot, gotRoot)
}

func TestBuildEpochSweepTapTreeRoot(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	date := arklib.AbsoluteLocktime(1788134400)
	grace := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}

	root, leafScript, err := tree.BuildEpochSweepTapTreeRoot(prv.PubKey(), date, grace)
	require.NoError(t, err)
	require.NotEmpty(t, leafScript)

	decoded := &script.CLTVCSVMultisigClosure{}
	valid, err := decoded.Decode(leafScript)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, date, decoded.ExpiryDate)
	require.Equal(t, grace, decoded.UnrollGrace)

	legacyRoot, _, err := tree.BuildLegacySweepTapTreeRoot(
		prv.PubKey(), arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604672},
	)
	require.NoError(t, err)
	require.NotEqual(t, legacyRoot, root, "epoch and legacy roots must differ")
}

func TestSweepTapTreeRootIsDeterministic(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604672}

	a, _, err := tree.BuildLegacySweepTapTreeRoot(prv.PubKey(), expiry)
	require.NoError(t, err)
	b, _, err := tree.BuildLegacySweepTapTreeRoot(prv.PubKey(), expiry)
	require.NoError(t, err)
	require.Equal(t, a, b)
}
