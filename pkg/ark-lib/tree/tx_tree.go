package tree

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

// Leaf represents the output of a leaf transaction.
type Leaf struct {
	Script              string
	Amount              uint64
	CosignersPublicKeys []string
}

// TxTree is the recursive reprensation of tree of transactions.
// It is used to represent the vtxo and connector trees.
type TxTree struct {
	Root     *psbt.Packet
	Children map[uint32]*TxTree // output index -> sub-tree
}

// TxTreeNode is a flat represenation of a node of tx tree.
// The purpose of this struct is to facilitate the persistance of the tx tree in storage services.
type TxTreeNode struct {
	Txid string
	// Tx is the base64 encoded root PSBT
	Tx string
	// Children maps root output index to child txid
	Children map[uint32]string
}

// FlatTxTree is the flat representation of a tx tree.
// The purpose of this struct is to facilitate the persistance of the tx tree in storage services.
type FlatTxTree []TxTreeNode

func (c FlatTxTree) Leaves() []TxTreeNode {
	leaves := make([]TxTreeNode, 0)
	for _, child := range c {
		if len(child.Children) == 0 {
			leaves = append(leaves, child)
		}
	}
	return leaves
}

// NewTxTree converts a flat list of nodes to a tree of transactions.
func NewTxTree(flatTxTree FlatTxTree) (*TxTree, error) {
	if len(flatTxTree) == 0 {
		return nil, fmt.Errorf("missing serialized tx tree")
	}

	// Create a map to store all nodes by their txid for easy lookup
	nodesByTxid := make(map[string]decodedTxTreeNode)
	for _, node := range flatTxTree {
		packet, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			return nil, fmt.Errorf("failed to decode PSBT: %w", err)
		}
		txid := packet.UnsignedTx.TxID()
		nodesByTxid[txid] = decodedTxTreeNode{
			Tx:       packet,
			Children: node.Children,
		}
	}

	// Find the root of the tree.
	rootTxids := make([]string, 0)
	for txid := range nodesByTxid {
		isChild := false
		for nodeTxid, node := range nodesByTxid {
			if nodeTxid == txid {
				// Skip self
				continue
			}

			// Check if the current node is a child of another one.
			isChild = node.hasChild(txid)
			if isChild {
				break
			}
		}

		if !isChild {
			rootTxids = append(rootTxids, txid)
			continue
		}
	}

	if len(rootTxids) == 0 {
		return nil, fmt.Errorf("no root found")
	}

	if len(rootTxids) > 1 {
		return nil, fmt.Errorf("multiple roots found %d: %v", len(rootTxids), rootTxids)
	}

	txTree := buildTree(rootTxids[0], nodesByTxid)
	if txTree == nil {
		return nil, fmt.Errorf("subtree not found for root %s", rootTxids[0])
	}

	// Ensure the number of nodes of the tree and serialized version match.
	if txTree.countNodes() != len(flatTxTree) {
		return nil, fmt.Errorf(
			"the resulting tree doesn't match the number of nodes of the given serialized "+
				"version: expected %d, got %d", len(flatTxTree), txTree.countNodes(),
		)
	}

	return txTree, nil
}

func (t *TxTree) countNodes() int {
	nb := 1
	for _, child := range t.Children {
		nb += child.countNodes()
	}
	return nb
}

// Serialize converts the tx tree into a flat list of nodes.
func (t *TxTree) Serialize() (FlatTxTree, error) {
	if t == nil {
		return make(FlatTxTree, 0), nil
	}

	nodes := make(FlatTxTree, 0)
	for _, child := range t.Children {
		childrenNodes, err := child.Serialize()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, childrenNodes...)
	}

	node, err := t.SerializeNode()
	if err != nil {
		return nil, err
	}

	nodes = append(nodes, *node)
	return nodes, nil
}

// SerializeNode converts the node of a tx tree into its flat representation.
func (t *TxTree) SerializeNode() (*TxTreeNode, error) {
	if t == nil {
		return nil, fmt.Errorf("missing tx tree node")
	}

	serializedTx, err := t.Root.B64Encode()
	if err != nil {
		return nil, err
	}

	// create a map of child txids
	childTxids := make(map[uint32]string)
	for outputIndex, child := range t.Children {
		childTxids[outputIndex] = child.Root.UnsignedTx.TxID()
	}

	return &TxTreeNode{
		Txid:     t.Root.UnsignedTx.TxID(),
		Tx:       serializedTx,
		Children: childTxids,
	}, nil
}

// Validate verifies the validity of the tx tree.
// It verifies :
// - every tx is a valid partial transaction.
// - every tx has exactly one input.
// - the child txs spend the right parent's output
// - the sum of the child txs' output amounts matches the parent tx input amount
func (t *TxTree) Validate() error {
	if t.Root == nil {
		return fmt.Errorf("unexpected nil root")
	}

	if t.Root.UnsignedTx.Version != 3 {
		return fmt.Errorf("unexpected version: %d, expected 3", t.Root.UnsignedTx.Version)
	}

	nbOfOutputs := uint32(len(t.Root.UnsignedTx.TxOut))
	nbOfInputs := uint32(len(t.Root.UnsignedTx.TxIn))

	if nbOfInputs != 1 {
		return fmt.Errorf("unexpected number of inputs: %d, expected 1", nbOfInputs)
	}

	// The children map can't be bigger than the number of outputs (excluding the P2A).
	// A tx tree can be "partial" and specify only some of the outputs as children,
	// that's why we allow len(g.Children) to be less than nbOfOutputs-1
	if len(t.Children) > int(nbOfOutputs-1) {
		return fmt.Errorf(
			"unexpected number of children: %d, expected maximum %d",
			len(t.Children), nbOfOutputs-1,
		)
	}

	// nbOfOutputs <= len(g.Children)
	for outputIndex, child := range t.Children {
		if outputIndex >= nbOfOutputs {
			return fmt.Errorf(
				"output index %d is out of bounds (nb of outputs: %d)", outputIndex, nbOfOutputs,
			)
		}

		if err := child.Validate(); err != nil {
			return err
		}

		childPreviousOutpoint := child.Root.UnsignedTx.TxIn[0].PreviousOutPoint

		// verify the input of the child is the output of the parent
		if childPreviousOutpoint.Hash.String() != t.Root.UnsignedTx.TxID() ||
			childPreviousOutpoint.Index != outputIndex {
			return fmt.Errorf("input of child %d is not the output of the parent", outputIndex)
		}

		// verify the sum of the child's outputs is equal to the output of the parent
		childOutputsSum := int64(0)
		for _, output := range child.Root.UnsignedTx.TxOut {
			childOutputsSum += output.Value
		}

		if childOutputsSum != t.Root.UnsignedTx.TxOut[outputIndex].Value {
			return fmt.Errorf(
				"sum of child's outputs is not equal to the output of the parent: %d != %d",
				childOutputsSum, t.Root.UnsignedTx.TxOut[outputIndex].Value,
			)
		}
	}

	return nil
}

// Leaves returns the leaves of the tx tree, ie. the nodes that don't have any children.
func (t *TxTree) Leaves() []*psbt.Packet {
	if len(t.Children) == 0 {
		return []*psbt.Packet{t.Root}
	}

	leaves := make([]*psbt.Packet, 0)

	for _, child := range t.Children {
		leaves = append(leaves, child.Leaves()...)
	}

	return leaves
}

// Find returns the tx in the tree that matches the provided txid.
func (t *TxTree) Find(txid string) *TxTree {
	if t.Root.UnsignedTx.TxID() == txid {
		return t
	}

	for _, child := range t.Children {
		if f := child.Find(txid); f != nil {
			return f
		}
	}

	return nil
}

// Apply executes the given function to all txs in the tx tree.
// The function returns a boolean to indicate whether it should continue applying to the children.
func (t *TxTree) Apply(fn func(tx *TxTree) (bool, error)) error {
	shouldContinue, err := fn(t)
	if err != nil {
		return err
	}

	if !shouldContinue {
		return nil
	}

	for _, child := range t.Children {
		if err := child.Apply(fn); err != nil {
			return err
		}
	}

	return nil
}

// SubTree returns the sub-tree that contains the given txs, ie all paths from root to the given
// txids, if they exist in the tree.
func (t *TxTree) SubTree(txids []string) (*TxTree, error) {
	if len(txids) == 0 {
		return nil, fmt.Errorf("no txids provided")
	}

	txidSet := make(map[string]bool)
	for _, txid := range txids {
		txidSet[txid] = true
	}

	return t.buildSubTree(txidSet)
}

// buildSubTree recursively builds a sub-tree that includes all paths from root to the given txids.
func (t *TxTree) buildSubTree(targetTxids map[string]bool) (*TxTree, error) {
	subTree := &TxTree{
		Root:     t.Root,
		Children: make(map[uint32]*TxTree),
	}

	currentTxid := t.Root.UnsignedTx.TxID()

	// the current node is a target, return just this node
	if targetTxids[currentTxid] {
		return subTree, nil
	}

	// recursively process children
	for outputIndex, child := range t.Children {
		subSubTree, err := child.buildSubTree(targetTxids)
		if err != nil {
			return nil, err
		}

		// If the child sub-tree is not empty, it means it contains a target, add it as a child.
		if subSubTree != nil {
			subTree.Children[outputIndex] = subSubTree
		}
	}

	// if we have no children and we're not a target, this path doesn't lead to any target
	if len(subTree.Children) == 0 && !targetTxids[currentTxid] {
		return nil, nil
	}

	return subTree, nil
}

// buildTree recursively builds the tree of txs for the given root and list of nodes (indexed by txid).
func buildTree(rootTxid string, nodesByTxid map[string]decodedTxTreeNode) *TxTree {
	node, exists := nodesByTxid[rootTxid]
	if !exists {
		return nil
	}

	txTree := &TxTree{
		Root:     node.Tx,
		Children: make(map[uint32]*TxTree),
	}

	// recursively build children tx tree
	for outputIndex, childTxid := range node.Children {
		subTree := buildTree(childTxid, nodesByTxid)
		if subTree != nil {
			txTree.Children[outputIndex] = subTree
		}
	}

	return txTree
}

// Internal type to build the tx tree.
type decodedTxTreeNode struct {
	Tx       *psbt.Packet
	Children map[uint32]string // output index -> child txid
}

func (c *decodedTxTreeNode) hasChild(txid string) bool {
	for _, childTxid := range c.Children {
		if childTxid == txid {
			return true
		}
	}
	return false
}
