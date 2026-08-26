package tree_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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

func TestSweepParamsRoot(t *testing.T) {
	prv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 604672}
	grace := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
	date := arklib.AbsoluteLocktime(1788134400)

	t.Run("legacy params select the legacy root", func(t *testing.T) {
		params := tree.SweepParams{Expiry: expiry}
		require.False(t, params.IsEpoch())

		got, _, err := params.Root(prv.PubKey())
		require.NoError(t, err)
		want, _, err := tree.BuildLegacySweepTapTreeRoot(prv.PubKey(), expiry)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("epoch params select the epoch root", func(t *testing.T) {
		params := tree.SweepParams{Expiry: grace, BatchExpiry: &date}
		require.True(t, params.IsEpoch())

		got, _, err := params.Root(prv.PubKey())
		require.NoError(t, err)
		want, _, err := tree.BuildEpochSweepTapTreeRoot(prv.PubKey(), date, grace)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	// The whole reason SweepParams is one type rather than an overload pair.
	t.Run("epoch and legacy roots differ for the same relative value", func(t *testing.T) {
		legacy, _, err := tree.SweepParams{Expiry: grace}.Root(prv.PubKey())
		require.NoError(t, err)
		epoch, _, err := tree.SweepParams{Expiry: grace, BatchExpiry: &date}.Root(prv.PubKey())
		require.NoError(t, err)
		require.NotEqual(t, legacy, epoch)
	})
}

// buildTreeFor constructs a batch output, a minimal commitment tx paying to it,
// and the vtxo tree spending it — enough for ValidateVtxoTree to run.
func buildTreeFor(
	t *testing.T, receivers []tree.Leaf, params tree.SweepParams,
) (*tree.TxTree, *psbt.Packet) {
	t.Helper()

	root, _, err := params.Root(signerPrvkey.PubKey())
	require.NoError(t, err)

	batchScript, batchAmount, err := tree.BuildBatchOutput(receivers, root[:])
	require.NoError(t, err)

	commitment, err := psbt.New(
		[]*wire.OutPoint{rootInput}, []*wire.TxOut{{Value: batchAmount, PkScript: batchScript}},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	treeInput := &wire.OutPoint{Hash: commitment.UnsignedTx.TxHash(), Index: 0}
	vtxoTree, err := tree.BuildVtxoTree(treeInput, receivers, root[:], params)
	require.NoError(t, err)

	return vtxoTree, commitment
}

// TestValidateVtxoTreeRejectsMismatchedSweepParams is the reason SweepParams is
// one type rather than an overload pair: an epoch tree validated with legacy
// parameters must fail, because every node's aggregate key is derived from the
// sweep root and a mismatched root reproduces nothing.
func TestValidateVtxoTreeRejectsMismatchedSweepParams(t *testing.T) {
	vectors, err := makeTestVectors()
	require.NoError(t, err)

	// ValidateVtxoTree only checks the root-derived taproot key on nodes that have
	// children, so a single-leaf tree would not exercise it at all.
	var receivers []tree.Leaf
	for _, v := range vectors {
		if len(v.receivers) > len(receivers) {
			receivers = v.receivers
		}
	}
	require.Greater(t, len(receivers), 1, "need a multi-leaf tree to exercise the sweep root")

	date := arklib.AbsoluteLocktime(1788134400)
	grace := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 12}
	epochParams := tree.SweepParams{Expiry: grace, BatchExpiry: &date}
	legacyParams := tree.SweepParams{Expiry: vtxoTreeExpiry}

	t.Run("epoch tree validates with epoch params", func(t *testing.T) {
		vtxoTree, commitment := buildTreeFor(t, receivers, epochParams)
		require.NoError(t, tree.ValidateVtxoTree(
			vtxoTree, commitment, signerPrvkey.PubKey(), epochParams,
		))
	})

	t.Run("epoch tree is rejected by legacy params", func(t *testing.T) {
		vtxoTree, commitment := buildTreeFor(t, receivers, epochParams)
		require.Error(t, tree.ValidateVtxoTree(
			vtxoTree, commitment, signerPrvkey.PubKey(), legacyParams,
		))
	})

	t.Run("legacy tree validates with legacy params", func(t *testing.T) {
		vtxoTree, commitment := buildTreeFor(t, receivers, legacyParams)
		require.NoError(t, tree.ValidateVtxoTree(
			vtxoTree, commitment, signerPrvkey.PubKey(), legacyParams,
		))
	})

	t.Run("legacy tree is rejected by epoch params", func(t *testing.T) {
		vtxoTree, commitment := buildTreeFor(t, receivers, legacyParams)
		require.Error(t, tree.ValidateVtxoTree(
			vtxoTree, commitment, signerPrvkey.PubKey(), epochParams,
		))
	})

	t.Run("a different epoch date is rejected", func(t *testing.T) {
		vtxoTree, commitment := buildTreeFor(t, receivers, epochParams)
		other := arklib.AbsoluteLocktime(1790000000)
		require.Error(t, tree.ValidateVtxoTree(
			vtxoTree, commitment, signerPrvkey.PubKey(),
			tree.SweepParams{Expiry: grace, BatchExpiry: &other},
		))
	})
}

// TestBuildVtxoTreeWritesEpochField pins the discriminator the sweeper keys on.
func TestBuildVtxoTreeWritesEpochField(t *testing.T) {
	vectors, err := makeTestVectors()
	require.NoError(t, err)
	receivers := vectors[0].receivers

	date := arklib.AbsoluteLocktime(1788134400)
	grace := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 12}

	t.Run("epoch tree carries both fields", func(t *testing.T) {
		vtxoTree, _ := buildTreeFor(
			t, receivers, tree.SweepParams{Expiry: grace, BatchExpiry: &date},
		)

		abs, err := txutils.GetArkPsbtFields(vtxoTree.Root, 0, txutils.BatchExpiryField)
		require.NoError(t, err)
		require.Len(t, abs, 1)
		require.Equal(t, date, abs[0])

		rel, err := txutils.GetArkPsbtFields(vtxoTree.Root, 0, txutils.VtxoTreeExpiryField)
		require.NoError(t, err)
		require.Len(t, rel, 1)
		require.Equal(t, grace, rel[0], "the relative field must carry the unroll grace")
	})

	t.Run("legacy tree carries only the relative field", func(t *testing.T) {
		vtxoTree, _ := buildTreeFor(t, receivers, tree.SweepParams{Expiry: vtxoTreeExpiry})

		abs, err := txutils.GetArkPsbtFields(vtxoTree.Root, 0, txutils.BatchExpiryField)
		require.NoError(t, err)
		require.Empty(t, abs, "a legacy tree must not look like an epoch tree")

		rel, err := txutils.GetArkPsbtFields(vtxoTree.Root, 0, txutils.VtxoTreeExpiryField)
		require.NoError(t, err)
		require.Len(t, rel, 1)
		require.Equal(t, vtxoTreeExpiry, rel[0])
	})
}
