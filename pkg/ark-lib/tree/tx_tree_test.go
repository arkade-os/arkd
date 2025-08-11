package tree_test

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/stretchr/testify/require"
)

func TestTxTreeSerialization(t *testing.T) {
	testVectors, err := makeTestVectors()
	require.NoError(t, err)
	require.NotEmpty(t, testVectors)

	for _, v := range testVectors {
		t.Run(v.name, func(t *testing.T) {
			batchOutScript, batchOutAmount, err := tree.BuildBatchOutput(
				v.receivers, batchOutSweepClosure[:],
			)
			require.NoError(t, err)
			require.NotNil(t, batchOutScript)
			require.NotZero(t, batchOutAmount)

			vtxoTree, err := tree.BuildVtxoTree(
				rootInput, v.receivers, batchOutSweepClosure[:], vtxoTreeExpiry,
			)
			require.NoError(t, err)
			require.NotNil(t, vtxoTree)

			serialized, err := vtxoTree.Serialize()
			require.NoError(t, err)
			require.NotNil(t, serialized)

			err = vtxoTree.Validate()
			require.NoError(t, err)

			// Verify nodes are unique
			seen := make(map[string]bool)
			for _, node := range serialized {
				require.False(t, seen[node.Tx])
				seen[node.Tx] = true
			}

			// Verify the deserialization roundtrip
			deserialized, err := tree.NewTxTree(serialized)
			require.NoError(t, err)
			require.NotNil(t, deserialized)

			err = deserialized.Validate()
			require.NoError(t, err)

			checkTxTree(t, vtxoTree, deserialized)

			// shuffle randomly the serialized tree
			shuffled := make(tree.FlatTxTree, len(serialized))
			copy(shuffled, serialized)
			rand.Shuffle(len(shuffled), func(i, j int) {
				shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
			})

			deserializedShuffled, err := tree.NewTxTree(shuffled)
			require.NoError(t, err)
			require.NotNil(t, deserializedShuffled)

			err = deserializedShuffled.Validate()
			require.NoError(t, err)

			checkTxTree(t, vtxoTree, deserializedShuffled)
			checkTxTree(t, deserialized, deserializedShuffled)
		})
	}
}

func TestTxTreeSubTree(t *testing.T) {
	testVectors, err := makeTestVectors()
	require.NoError(t, err)
	require.NotEmpty(t, testVectors)

	for _, v := range testVectors {
		t.Run(v.name, func(t *testing.T) {
			batchOutScript, batchOutAmount, err := tree.BuildBatchOutput(
				v.receivers, batchOutSweepClosure[:],
			)
			require.NoError(t, err)
			require.NotNil(t, batchOutScript)
			require.NotZero(t, batchOutAmount)

			vtxoTree, err := tree.BuildVtxoTree(
				rootInput, v.receivers, batchOutSweepClosure[:], vtxoTreeExpiry,
			)
			require.NoError(t, err)
			require.NotNil(t, vtxoTree)

			rootTxid := vtxoTree.Root.UnsignedTx.TxID()

			// Test 1: SubTree(root) should return 1 node.
			subTree, err := vtxoTree.SubTree([]string{rootTxid})
			require.NoError(t, err)
			require.NotNil(t, subTree)
			require.Equal(t, rootTxid, subTree.Root.UnsignedTx.TxID())
			require.Empty(t, subTree.Children)

			// Test 2: SubTree(nil) should return error.
			subTree, err = vtxoTree.SubTree([]string{})
			require.Error(t, err)
			require.Nil(t, subTree)
			require.Contains(t, err.Error(), "no txids provided")

			// Test 3: SubTree(nonExistinTxid) should return an empty sub-tree.
			nonExistentTxid := "0000000000000000000000000000000000000000000000000000000000000000"
			subTree, err = vtxoTree.SubTree([]string{nonExistentTxid})
			require.NoError(t, err)
			require.Nil(t, subTree)

			// Test 4: SubTree(leaf) should return the full branch from root to leaf.
			leaves := vtxoTree.Leaves()
			require.NotEmpty(t, leaves)

			for _, leaf := range leaves {
				leafTxid := leaf.UnsignedTx.TxID()
				subTree, err := vtxoTree.SubTree([]string{leafTxid})
				require.NoError(t, err)
				require.NotNil(t, subTree)

				// Verify the sub-tree contains the root and the leaf
				allTxids := make([]string, 0)
				err = subTree.Apply(func(tx *tree.TxTree) (bool, error) {
					allTxids = append(allTxids, tx.Root.UnsignedTx.TxID())
					return true, nil
				})
				require.NoError(t, err)

				require.Contains(t, allTxids, rootTxid)
				require.Contains(t, allTxids, leafTxid)

				// Verify the sub-tree is a valid tree (all paths lead to the target)
				err = subTree.Validate()
				require.NoError(t, err)

				// Verify the sub-tree contains exactly the path from root to leaf
				// Check that the sub-tree contains the expected txids
				expectedTxids := []string{rootTxid, leafTxid}
				for _, expectedTxid := range expectedTxids {
					require.Contains(t, allTxids, expectedTxid)
				}

				// Verify serialization roundtrip
				serialized, err := subTree.Serialize()
				require.NoError(t, err)
				deserialized, err := tree.NewTxTree(serialized)
				require.NoError(t, err)
				checkTxTree(t, subTree, deserialized)
			}

			// Test 5: SubTree(allLeaves) whould return the whole tree.
			leavesTxids := make([]string, 0)
			for _, leaf := range leaves {
				leavesTxids = append(leavesTxids, leaf.UnsignedTx.TxID())
			}
			subTree, err = vtxoTree.SubTree(leavesTxids)
			require.NoError(t, err)
			require.NotNil(t, subTree)
			checkTxTree(t, vtxoTree, subTree)

			// Test 6: SubTree(someLeaves) should return all requested branches under the same root.
			if len(leaves) > 1 {
				leafTxids := make([]string, 0)
				for _, leaf := range leaves {
					leafTxids = append(leafTxids, leaf.UnsignedTx.TxID())
				}

				// Take first two leaves for testing
				testLeafTxids := leafTxids[:2]
				subTree, err := vtxoTree.SubTree(testLeafTxids)
				require.NoError(t, err)
				require.NotNil(t, subTree)

				// Verify the sub-tree contains all target txids
				allTxids := make([]string, 0)
				err = subTree.Apply(func(tx *tree.TxTree) (bool, error) {
					allTxids = append(allTxids, tx.Root.UnsignedTx.TxID())
					return true, nil
				})
				require.NoError(t, err)

				for _, targetTxid := range testLeafTxids {
					require.Contains(t, allTxids, targetTxid)
				}

				// Verify the sub-tree contains the root
				require.Contains(t, allTxids, rootTxid)

				// Verify the sub-tree is a valid tree
				err = subTree.Validate()
				require.NoError(t, err)
			}

		})
	}
}

func checkTxTree(t *testing.T, expected, got *tree.TxTree) {
	require.Equal(t, expected.Root.UnsignedTx.TxID(), got.Root.UnsignedTx.TxID())

	expectedTxids := make([]string, 0)
	err := expected.Apply(func(tx *tree.TxTree) (bool, error) {
		expectedTxids = append(expectedTxids, tx.Root.UnsignedTx.TxID())
		return true, nil
	})
	require.NoError(t, err)

	gotTxids := make([]string, 0)
	err = got.Apply(func(tx *tree.TxTree) (bool, error) {
		gotTxids = append(gotTxids, tx.Root.UnsignedTx.TxID())
		return true, nil
	})
	require.NoError(t, err)

	sort.Strings(expectedTxids)
	sort.Strings(gotTxids)

	require.Equal(t, len(expectedTxids), len(gotTxids))

	require.Equal(t, expectedTxids, gotTxids)
}
