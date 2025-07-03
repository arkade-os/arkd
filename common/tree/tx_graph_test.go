package tree_test

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/ark-network/ark/common/tree"
	"github.com/stretchr/testify/require"
)

func TestGraphSerialization(t *testing.T) {
	t.Parallel()

	testVectors, err := makeTestVectors()
	require.NoError(t, err)
	require.NotEmpty(t, testVectors)

	for _, v := range testVectors {
		t.Run(v.name, func(t *testing.T) {
			sharedOutScript, sharedOutAmount, err := tree.BuildBatchOutput(
				v.receivers, sweepRoot[:],
			)
			require.NoError(t, err)
			require.NotNil(t, sharedOutScript)
			require.NotZero(t, sharedOutAmount)

			vtxoTree, err := tree.BuildVtxoTree(
				rootInput, v.receivers, sweepRoot[:], vtxoTreeExpiry,
			)
			require.NoError(t, err)
			require.NotNil(t, vtxoTree)

			serialized, err := vtxoTree.Serialize()
			require.NoError(t, err)
			require.NotNil(t, serialized)

			err = vtxoTree.Validate()
			require.NoError(t, err)

			// Verify chunk are unique
			seen := make(map[string]bool)
			for _, chunk := range serialized {
				require.False(t, seen[chunk.Tx])
				seen[chunk.Tx] = true
			}

			// Verify the deserialization roundtrip
			deserialized, err := tree.NewTxGraph(serialized)
			require.NoError(t, err)
			require.NotNil(t, deserialized)

			err = deserialized.Validate()
			require.NoError(t, err)

			requireGraphEqual(t, vtxoTree, deserialized)

			// shuffle randomly the serialized chunks
			shuffled := make([]tree.TxGraphChunk, len(serialized))
			copy(shuffled, serialized)
			rand.Shuffle(len(shuffled), func(i, j int) {
				shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
			})

			deserializedShuffled, err := tree.NewTxGraph(shuffled)
			require.NoError(t, err)
			require.NotNil(t, deserializedShuffled)

			err = deserializedShuffled.Validate()
			require.NoError(t, err)

			requireGraphEqual(t, vtxoTree, deserializedShuffled)
			requireGraphEqual(t, deserialized, deserializedShuffled)
		})
	}
}

func TestTxGraphSubGraph(t *testing.T) {
	t.Parallel()

	testVectors, err := makeTestVectors()
	require.NoError(t, err)
	require.NotEmpty(t, testVectors)

	for _, v := range testVectors {
		t.Run(v.name, func(t *testing.T) {
			sharedOutScript, sharedOutAmount, err := tree.BuildBatchOutput(
				v.receivers, sweepRoot[:],
			)
			require.NoError(t, err)
			require.NotNil(t, sharedOutScript)
			require.NotZero(t, sharedOutAmount)

			vtxoTree, err := tree.BuildVtxoTree(
				rootInput, v.receivers, sweepRoot[:], vtxoTreeExpiry,
			)
			require.NoError(t, err)
			require.NotNil(t, vtxoTree)

			rootTxid := vtxoTree.Root.UnsignedTx.TxID()

			// Test 1: SubGraph with root txid should return the root only
			subGraph, err := vtxoTree.SubGraph([]string{rootTxid})
			require.NoError(t, err)
			require.NotNil(t, subGraph)
			require.Equal(t, rootTxid, subGraph.Root.UnsignedTx.TxID())
			require.Empty(t, subGraph.Children)

			// Test 2: SubGraph with empty txids should return error
			subGraph, err = vtxoTree.SubGraph([]string{})
			require.Error(t, err)
			require.Nil(t, subGraph)
			require.Contains(t, err.Error(), "no txids provided")

			// Test 3: SubGraph with non-existent txid should return nil (no path to target)
			nonExistentTxid := "0000000000000000000000000000000000000000000000000000000000000000"
			subGraph, err = vtxoTree.SubGraph([]string{nonExistentTxid})
			require.NoError(t, err)
			require.Nil(t, subGraph)

			// Test 4: SubGraph with leaf txids should return paths from root to leaves
			leaves := vtxoTree.Leaves()
			require.NotEmpty(t, leaves)

			for _, leaf := range leaves {
				leafTxid := leaf.UnsignedTx.TxID()
				subGraph, err := vtxoTree.SubGraph([]string{leafTxid})
				require.NoError(t, err)
				require.NotNil(t, subGraph)

				// Verify the subgraph contains the root and the leaf
				allTxids := make([]string, 0)
				err = subGraph.Apply(func(tx *tree.TxGraph) (bool, error) {
					allTxids = append(allTxids, tx.Root.UnsignedTx.TxID())
					return true, nil
				})
				require.NoError(t, err)

				require.Contains(t, allTxids, rootTxid)
				require.Contains(t, allTxids, leafTxid)

				// Verify the subgraph is a valid tree (all paths lead to the target)
				err = subGraph.Validate()
				require.NoError(t, err)

				// Verify the subgraph contains exactly the path from root to leaf
				// Check that the subgraph contains the expected txids
				expectedTxids := []string{rootTxid, leafTxid}
				for _, expectedTxid := range expectedTxids {
					require.Contains(t, allTxids, expectedTxid)
				}

				// Verify serialization roundtrip
				serialized, err := subGraph.Serialize()
				require.NoError(t, err)
				deserialized, err := tree.NewTxGraph(serialized)
				require.NoError(t, err)
				requireGraphEqual(t, subGraph, deserialized)
			}

			// Test 5: SubGraph with leaf txids should return paths should be equal to root graph
			leavesTxids := make([]string, 0)
			for _, leaf := range leaves {
				leavesTxids = append(leavesTxids, leaf.UnsignedTx.TxID())
			}
			subGraph, err = vtxoTree.SubGraph(leavesTxids)
			require.NoError(t, err)
			require.NotNil(t, subGraph)
			requireGraphEqual(t, vtxoTree, subGraph)

			// Test 6: SubGraph with multiple leaf txids should return union of all paths
			if len(leaves) > 1 {
				leafTxids := make([]string, 0)
				for _, leaf := range leaves {
					leafTxids = append(leafTxids, leaf.UnsignedTx.TxID())
				}

				// Take first two leaves for testing
				testLeafTxids := leafTxids[:2]
				subGraph, err := vtxoTree.SubGraph(testLeafTxids)
				require.NoError(t, err)
				require.NotNil(t, subGraph)

				// Verify the subgraph contains all target txids
				allTxids := make([]string, 0)
				err = subGraph.Apply(func(tx *tree.TxGraph) (bool, error) {
					allTxids = append(allTxids, tx.Root.UnsignedTx.TxID())
					return true, nil
				})
				require.NoError(t, err)

				for _, targetTxid := range testLeafTxids {
					require.Contains(t, allTxids, targetTxid)
				}

				// Verify the subgraph contains the root
				require.Contains(t, allTxids, rootTxid)

				// Verify the subgraph is a valid tree
				err = subGraph.Validate()
				require.NoError(t, err)
			}

		})
	}
}

func requireGraphEqual(t *testing.T, a, b *tree.TxGraph) {
	require.Equal(t, a.Root.UnsignedTx.TxID(), b.Root.UnsignedTx.TxID())

	txids := make([]string, 0)
	err := a.Apply(func(tx *tree.TxGraph) (bool, error) {
		txids = append(txids, tx.Root.UnsignedTx.TxID())
		return true, nil
	})
	require.NoError(t, err)

	txidsB := make([]string, 0)
	err = b.Apply(func(tx *tree.TxGraph) (bool, error) {
		txidsB = append(txidsB, tx.Root.UnsignedTx.TxID())
		return true, nil
	})
	require.NoError(t, err)

	sort.Strings(txids)
	sort.Strings(txidsB)

	require.Equal(t, len(txids), len(txidsB))

	require.Equal(t, txids, txidsB)
}
