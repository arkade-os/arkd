package tree_test

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// allNodes returns every node of the tree, so a mutation can be applied to the
// deeper ones too and only surface if Validate() really recurses.
func allNodes(txTree *tree.TxTree) []*tree.TxTree {
	nodes := []*tree.TxTree{txTree}
	for _, child := range txTree.Children {
		nodes = append(nodes, allNodes(child)...)
	}
	return nodes
}

// TestTxTreeValidateFinality checks that a tree holding a node that bitcoin
// would not accept right away is rejected. A pre-signed unroll path is only
// worth something if it can be broadcasted as soon as its parent confirms.
func TestTxTreeValidateFinality(t *testing.T) {
	testVectors, err := makeTestVectors()
	require.NoError(t, err)
	require.NotEmpty(t, testVectors)

	for _, v := range testVectors {
		t.Run(v.name, func(t *testing.T) {
			vtxoTree, err := tree.BuildVtxoTree(
				rootInput, v.receivers, batchOutSweepClosure[:], vtxoTreeExpiry,
			)
			require.NoError(t, err)

			connectorTree, err := tree.BuildConnectorTree(rootInput, v.receivers)
			require.NoError(t, err)

			for name, txTree := range map[string]*tree.TxTree{
				"vtxo tree": vtxoTree, "connector tree": connectorTree,
			} {
				t.Run(name, func(t *testing.T) {
					// the tree as built by the honest stack must stay valid
					require.NoError(t, txTree.Validate())

					for i, node := range allNodes(txTree) {
						node.Root.UnsignedTx.LockTime = 1
						require.ErrorContainsf(
							t, txTree.Validate(), "unexpected locktime",
							"locktime not validated on node %d", i,
						)
						node.Root.UnsignedTx.LockTime = 0
						require.NoError(t, txTree.Validate())

						node.Root.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1
						require.ErrorContainsf(
							t, txTree.Validate(), "unexpected sequence",
							"sequence not validated on node %d", i,
						)
						node.Root.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum
						require.NoError(t, txTree.Validate())
					}
				})
			}
		})
	}
}
