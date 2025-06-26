package tree

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

// TxGraph is the reprensation of a directed graph of psbt packets
// it is used to represent the batch tree
type TxGraph struct {
	Root     *psbt.Packet
	Children map[uint32]*TxGraph // output index -> child graph
}

// TxGraphChunk is a chunk of TxGraph
// it is used to serialize and deserialize the graph because TxGraph is recursive
// a list of TxGraphChunk can be used to reconstruct the TxGraph
type TxGraphChunk struct {
	Txid string
	// Tx is the base64 encoded root PSBT
	Tx string
	// Children maps root output index to child txid
	Children map[uint32]string
}

type TxGraphChunkList []TxGraphChunk

func (c TxGraphChunkList) Leaves() []TxGraphChunk {
	leaves := make([]TxGraphChunk, 0)
	for _, child := range c {
		if len(child.Children) == 0 {
			leaves = append(leaves, child)
		}
	}
	return leaves
}

// NewTxGraph creates a new TxGraph from a list of TxGraphChunk
func NewTxGraph(chunks []TxGraphChunk) (*TxGraph, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("empty chunks")
	}

	// Create a map to store all chunks by their txid for easy lookup
	chunksByTxid := make(map[string]decodedTxGraphChunk)

	for _, chunk := range chunks {
		packet, err := psbt.NewFromRawBytes(strings.NewReader(chunk.Tx), true)
		if err != nil {
			return nil, fmt.Errorf("failed to decode PSBT: %w", err)
		}
		txid := packet.UnsignedTx.TxID()
		chunksByTxid[txid] = decodedTxGraphChunk{
			Tx:       packet,
			Children: chunk.Children,
		}
	}

	// Find the root chunks (the ones that aren't referenced as a child)
	rootTxids := make([]string, 0)
	for txid := range chunksByTxid {
		isChild := false
		for otherTxid, otherChunk := range chunksByTxid {
			if otherTxid == txid {
				// skip self
				continue
			}

			// check if the current chunk is a child of the other chunk
			isChild = otherChunk.hasChild(txid)
			if isChild {
				break
			}
		}

		// if the chunk is not a child of any other chunk, it is a root
		if !isChild {
			rootTxids = append(rootTxids, txid)
			continue
		}
	}

	if len(rootTxids) == 0 {
		return nil, fmt.Errorf("no root chunk found")
	}

	if len(rootTxids) > 1 {
		return nil, fmt.Errorf("multiple root chunks found: %v", rootTxids)
	}

	graph := buildGraph(rootTxids[0], chunksByTxid)
	if graph == nil {
		return nil, fmt.Errorf("chunk not found for root txid: %s", rootTxids[0])
	}

	// verify that the number of chunks is equal to the number node in the graph
	if graph.nbOfNodes() != len(chunks) {
		return nil, fmt.Errorf("number of chunks (%d) is not equal to the number of nodes in the graph (%d)", len(chunks), graph.nbOfNodes())
	}

	return graph, nil
}

func (g *TxGraph) nbOfNodes() int {
	nb := 1
	for _, child := range g.Children {
		nb += child.nbOfNodes()
	}
	return nb
}

// Serialize serializes the graph to a list of TxGraphChunk
func (g *TxGraph) Serialize() ([]TxGraphChunk, error) {
	if g == nil {
		return make([]TxGraphChunk, 0), nil
	}
	chunks := make([]TxGraphChunk, 0)

	// recursively serialize the graph
	for _, child := range g.Children {
		childChunks, err := child.Serialize()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, childChunks...)
	}

	rootChunk, err := g.RootChunk()
	if err != nil {
		return nil, err
	}

	chunks = append(chunks, rootChunk)
	return chunks, nil
}

func (g *TxGraph) RootChunk() (TxGraphChunk, error) {
	if g == nil {
		return TxGraphChunk{}, fmt.Errorf("unexpected nil graph")
	}

	serializedTx, err := g.Root.B64Encode()
	if err != nil {
		return TxGraphChunk{}, err
	}

	// create a map of child txids
	childTxids := make(map[uint32]string)
	for outputIndex, child := range g.Children {
		childTxids[outputIndex] = child.Root.UnsignedTx.TxID()
	}

	return TxGraphChunk{
		Txid:     g.Root.UnsignedTx.TxID(),
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
func (g *TxGraph) Validate() error {
	if g.Root == nil {
		return fmt.Errorf("unexpected nil root")
	}

	if g.Root.UnsignedTx.Version != 3 {
		return fmt.Errorf("unexpected version: %d, expected 3", g.Root.UnsignedTx.Version)
	}

	nbOfOutputs := uint32(len(g.Root.UnsignedTx.TxOut))
	nbOfInputs := uint32(len(g.Root.UnsignedTx.TxIn))

	if nbOfInputs != 1 {
		return fmt.Errorf("unexpected number of inputs: %d, expected 1", nbOfInputs)
	}

	// the children map can't be bigger than the number of outputs (excluding the P2A)
	// a graph can be "partial" and specify only some of the outputs as children,
	// that's why we allow len(g.Children) to be less than nbOfOutputs-1
	if len(g.Children) > int(nbOfOutputs-1) {
		return fmt.Errorf("unexpected number of children: %d, expected maximum %d", len(g.Children), nbOfOutputs-1)
	}

	// nbOfOutputs <= len(g.Children)
	for outputIndex, child := range g.Children {
		if outputIndex >= nbOfOutputs {
			return fmt.Errorf("output index %d is out of bounds (nb of outputs: %d)", outputIndex, nbOfOutputs)
		}

		if err := child.Validate(); err != nil {
			return err
		}

		childPreviousOutpoint := child.Root.UnsignedTx.TxIn[0].PreviousOutPoint

		// verify the input of the child is the output of the parent
		if childPreviousOutpoint.Hash.String() != g.Root.UnsignedTx.TxID() || childPreviousOutpoint.Index != outputIndex {
			return fmt.Errorf("input of child %d is not the output of the parent", outputIndex)
		}

		// verify the sum of the child's outputs is equal to the output of the parent
		childOutputsSum := int64(0)
		for _, output := range child.Root.UnsignedTx.TxOut {
			childOutputsSum += output.Value
		}

		if childOutputsSum != g.Root.UnsignedTx.TxOut[outputIndex].Value {
			return fmt.Errorf("sum of child's outputs is not equal to the output of the parent: %d != %d", childOutputsSum, g.Root.UnsignedTx.TxOut[outputIndex].Value)
		}
	}

	return nil
}

// Leaves return all txs of the graph without children
func (g *TxGraph) Leaves() []*psbt.Packet {
	if len(g.Children) == 0 {
		return []*psbt.Packet{g.Root}
	}

	leaves := make([]*psbt.Packet, 0)

	for _, child := range g.Children {
		leaves = append(leaves, child.Leaves()...)
	}

	return leaves
}

// Find returns the tx in the graph that matches the provided txid
func (g *TxGraph) Find(txid string) *TxGraph {
	if g.Root.UnsignedTx.TxID() == txid {
		return g
	}

	for _, child := range g.Children {
		if f := child.Find(txid); f != nil {
			return f
		}
	}

	return nil
}

// Apply executes the given function to all txs in the graph
// the function returns a boolean to indicate whether we should continue the Apply on the children
func (g *TxGraph) Apply(fn func(tx *TxGraph) (bool, error)) error {
	shouldContinue, err := fn(g)
	if err != nil {
		return err
	}

	if !shouldContinue {
		return nil
	}

	for _, child := range g.Children {
		if err := child.Apply(fn); err != nil {
			return err
		}
	}

	return nil
}

// SubGraph returns the subgraph starting from the root until the given txids
func (g *TxGraph) SubGraph(txids []string) (*TxGraph, error) {
	if len(txids) == 0 {
		return nil, fmt.Errorf("no txids provided")
	}

	txidSet := make(map[string]bool)
	for _, txid := range txids {
		txidSet[txid] = true
	}

	return g.buildSubGraph(txidSet)
}

// buildSubGraph recursively builds a subgraph that includes all paths from root to the given txids
func (g *TxGraph) buildSubGraph(targetTxids map[string]bool) (*TxGraph, error) {
	subGraph := &TxGraph{
		Root:     g.Root,
		Children: make(map[uint32]*TxGraph),
	}

	currentTxid := g.Root.UnsignedTx.TxID()

	// the current node is a target, return just this node
	if targetTxids[currentTxid] {
		return subGraph, nil
	}

	// recursively process children
	for outputIndex, child := range g.Children {
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
func buildGraph(rootTxid string, chunksByTxid map[string]decodedTxGraphChunk) *TxGraph {
	chunk, exists := chunksByTxid[rootTxid]
	if !exists {
		return nil
	}

	graph := &TxGraph{
		Root:     chunk.Tx,
		Children: make(map[uint32]*TxGraph),
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
type decodedTxGraphChunk struct {
	Tx       *psbt.Packet
	Children map[uint32]string // output index -> child txid
}

func (c *decodedTxGraphChunk) hasChild(txid string) bool {
	for _, childTxid := range c.Children {
		if childTxid == txid {
			return true
		}
	}
	return false
}
