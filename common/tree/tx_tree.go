package tree

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

// TxTree is the reprensation of a directed graph of psbt packets
// It is used to represent the vtxo and connector trees.
type TxTree struct {
	Root     *psbt.Packet
	Children map[uint32]*TxTree // output index -> child graph
}

// TxTreeNode is a node of tree of tx.
// The purpose of this struct is to facilitate the persistance of the tree of txs in storage.
type TxTreeNode struct {
	Txid string
	// Tx is the base64 encoded root PSBT
	Tx string
	// Children maps root output index to child txid
	Children map[uint32]string
}

// Leaf represents the output of a leaf transaction.
type Leaf struct {
	Script              string
	Amount              uint64
	CosignersPublicKeys []string
}

// FlatVtxoTree can be used to persist a tree in storage.
// It has methods to serialize to and deserialize from the recursive representation.
type FlatVtxoTree []TxTreeNode

func (c FlatVtxoTree) Leaves() []TxTreeNode {
	leaves := make([]TxTreeNode, 0)
	for _, child := range c {
		if len(child.Children) == 0 {
			leaves = append(leaves, child)
		}
	}
	return leaves
}

// NewTxTree creates a new TxGraph from a list of nodes.
func NewTxTree(flatTxTree FlatVtxoTree) (*TxTree, error) {
	if len(flatTxTree) == 0 {
		return nil, fmt.Errorf("empty chunks")
	}

	// Create a map to store all chunks by their txid for easy lookup
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
		for otherTxid, otherChunk := range nodesByTxid {
			if otherTxid == txid {
				// Skip self
				continue
			}

			// Check if the current node is a child of another one.
			isChild = otherChunk.hasChild(txid)
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

	txTree := buildGraph(rootTxids[0], nodesByTxid)
	if txTree == nil {
		return nil, fmt.Errorf("subtree not found for root %s", rootTxids[0])
	}

	// verify that the number of chunks is equal to the number node in the graph
	if txTree.countNodes() != len(flatTxTree) {
		return nil, fmt.Errorf(
			"built tree doesn't match the number of give nodes, expected %d got %d",
			len(flatTxTree), txTree.countNodes(),
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

// Serialize serializes the tree into a FlatVtxoTree in a recursive way.
func (t *TxTree) Serialize() (FlatVtxoTree, error) {
	if t == nil {
		return make([]TxTreeNode, 0), nil
	}

	nodes := make([]TxTreeNode, 0)
	for _, child := range t.Children {
		childrenNodes, err := child.Serialize()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, childrenNodes...)
	}

	rootChunk, err := t.RootChunk()
	if err != nil {
		return nil, err
	}

	nodes = append(nodes, rootChunk)
	return nodes, nil
}

func (t *TxTree) RootChunk() (TxTreeNode, error) {
	if t == nil {
		return TxTreeNode{}, fmt.Errorf("unexpected nil graph")
	}

	serializedTx, err := t.Root.B64Encode()
	if err != nil {
		return TxTreeNode{}, err
	}

	// create a map of child txids
	childTxids := make(map[uint32]string)
	for outputIndex, child := range t.Children {
		childTxids[outputIndex] = child.Root.UnsignedTx.TxID()
	}

	return TxTreeNode{
		Txid:     t.Root.UnsignedTx.TxID(),
		Tx:       serializedTx,
		Children: childTxids,
	}, nil
}

// Validate checks if the graph is coherent
// it verifies :
// - the root is a valid psbt
// - the root has exactly one input
// - the children are valid
// - the chilren's input is the output of the parent
// - the sum of the children's outputs is equal to the output of the parent
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

	// the children map can't be bigger than the number of outputs (excluding the P2A)
	// a graph can be "partial" and specify only some of the outputs as children,
	// that's why we allow len(g.Children) to be less than nbOfOutputs-1
	if len(t.Children) > int(nbOfOutputs-1) {
		return fmt.Errorf("unexpected number of children: %d, expected maximum %d", len(t.Children), nbOfOutputs-1)
	}

	// nbOfOutputs <= len(g.Children)
	for outputIndex, child := range t.Children {
		if outputIndex >= nbOfOutputs {
			return fmt.Errorf("output index %d is out of bounds (nb of outputs: %d)", outputIndex, nbOfOutputs)
		}

		if err := child.Validate(); err != nil {
			return err
		}

		childPreviousOutpoint := child.Root.UnsignedTx.TxIn[0].PreviousOutPoint

		// verify the input of the child is the output of the parent
		if childPreviousOutpoint.Hash.String() != t.Root.UnsignedTx.TxID() || childPreviousOutpoint.Index != outputIndex {
			return fmt.Errorf("input of child %d is not the output of the parent", outputIndex)
		}

		// verify the sum of the child's outputs is equal to the output of the parent
		childOutputsSum := int64(0)
		for _, output := range child.Root.UnsignedTx.TxOut {
			childOutputsSum += output.Value
		}

		if childOutputsSum != t.Root.UnsignedTx.TxOut[outputIndex].Value {
			return fmt.Errorf("sum of child's outputs is not equal to the output of the parent: %d != %d", childOutputsSum, t.Root.UnsignedTx.TxOut[outputIndex].Value)
		}
	}

	return nil
}

// Leaves return all txs of the graph without children
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

// Find returns the tx in the graph that matches the provided txid
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

// Apply executes the given function to all txs in the graph
// the function returns a boolean to indicate whether we should continue the Apply on the children
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

// SubGraph returns the subgraph starting from the root until the given txids
func (t *TxTree) SubGraph(txids []string) (*TxTree, error) {
	if len(txids) == 0 {
		return nil, fmt.Errorf("no txids provided")
	}

	txidSet := make(map[string]bool)
	for _, txid := range txids {
		txidSet[txid] = true
	}

	return t.buildSubGraph(txidSet)
}

// buildSubGraph recursively builds a subgraph that includes all paths from root to the given txids
func (t *TxTree) buildSubGraph(targetTxids map[string]bool) (*TxTree, error) {
	subGraph := &TxTree{
		Root:     t.Root,
		Children: make(map[uint32]*TxTree),
	}

	currentTxid := t.Root.UnsignedTx.TxID()

	// the current node is a target, return just this node
	if targetTxids[currentTxid] {
		return subGraph, nil
	}

	// recursively process children
	for outputIndex, child := range t.Children {
		childSubGraph, err := child.buildSubGraph(targetTxids)
		if err != nil {
			return nil, err
		}

		// if the child subgraph is not empty, it means it contains a target, add it as a child
		if childSubGraph != nil {
			subGraph.Children[outputIndex] = childSubGraph
		}
	}

	// if we have no children and we're not a target, this path doesn't lead to any target
	if len(subGraph.Children) == 0 && !targetTxids[currentTxid] {
		return nil, nil
	}

	return subGraph, nil
}

// buildGraph recursively builds the TxGraph starting from the given txid
func buildGraph(rootTxid string, chunksByTxid map[string]decodedTxTreeNode) *TxTree {
	chunk, exists := chunksByTxid[rootTxid]
	if !exists {
		return nil
	}

	graph := &TxTree{
		Root:     chunk.Tx,
		Children: make(map[uint32]*TxTree),
	}

	// recursively build children graphs
	for outputIndex, childTxid := range chunk.Children {
		childGraph := buildGraph(childTxid, chunksByTxid)
		if childGraph != nil {
			graph.Children[outputIndex] = childGraph
		}
	}

	return graph
}

// internal type to build the graph
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
