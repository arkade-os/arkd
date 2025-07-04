package tree

import (
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	vtxoTreeRadix       = 2
	connectorsTreeRadix = 4
)

// BuildBatchOutput returns the taproot script and amount of a batch output of the commiment tx.
// The radix of the vtxo tree is hardcoded to 2.
func BuildBatchOutput(receivers []Leaf, sweepTapTreeRoot []byte) ([]byte, int64, error) {
	root, err := createTxTree(receivers, sweepTapTreeRoot, vtxoTreeRadix)
	if err != nil {
		return nil, 0, err
	}

	amount := root.getAmount() + txutils.ANCHOR_VALUE

	aggregatedKey, err := AggregateKeys(root.getCosigners(), sweepTapTreeRoot)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to aggregate keys: %w", err)
	}

	scriptPubkey, err := script.P2TRScript(aggregatedKey.FinalKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create script pubkey: %w", err)
	}

	return scriptPubkey, amount, nil
}

// BuildVtxoTree creates the vtxo tree, ie. the tree of transactions from the one spending the
// batch output to those creating the vtxos (the leaves of the tree).
// The radix of the tree is hardcoded to 2.
func BuildVtxoTree(
	rootInput *wire.OutPoint, receivers []Leaf,
	sweepTapTreeRoot []byte, vtxoTreeExpiry arklib.RelativeLocktime,
) (*TxTree, error) {
	root, err := createTxTree(receivers, sweepTapTreeRoot, vtxoTreeRadix)
	if err != nil {
		return nil, err
	}

	return root.tree(rootInput, &vtxoTreeExpiry)
}

// BuildConnectorOutput returns the taproot script and amount of a connector output of the
// commitment tx.
// The radix of the connector tree is hardcoded to 4.
func BuildConnectorOutput(receivers []Leaf) ([]byte, int64, error) {
	root, err := createTxTree(receivers, nil, connectorsTreeRadix)
	if err != nil {
		return nil, 0, err
	}

	amount := root.getAmount() + txutils.ANCHOR_VALUE

	aggregatedKey, err := AggregateKeys(root.getCosigners(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to aggregate keys: %w", err)
	}

	scriptPubkey, err := script.P2TRScript(aggregatedKey.FinalKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create script pubkey: %w", err)
	}

	return scriptPubkey, amount, nil
}

// BuildConnectorTree creates the connector tree, ie the tree of transactions from the one spending
// the connector output to those creating the connectors used to forfeit vtxos in the batch process.
// The radix of the tree is hardcoded to 4.
func BuildConnectorTree(rootInput *wire.OutPoint, receivers []Leaf) (*TxTree, error) {
	root, err := createTxTree(receivers, nil, connectorsTreeRadix)
	if err != nil {
		return nil, err
	}

	return root.tree(rootInput, nil)
}

type node interface {
	getAmount() int64 // returns the input amount of the node = sum of all receivers' amounts
	getOutputs() ([]*wire.TxOut, error)
	getChildren() []node
	getCosigners() []*btcec.PublicKey
	getInputScript() []byte
	tree(input *wire.OutPoint, expiry *arklib.RelativeLocktime) (*TxTree, error)
}

type leaf struct {
	output      *wire.TxOut
	inputScript []byte
	cosigners   []*btcec.PublicKey
}

func (l *leaf) getInputScript() []byte {
	return l.inputScript
}

func (l *leaf) getCosigners() []*btcec.PublicKey {
	return l.cosigners
}

func (l *leaf) getChildren() []node {
	return []node{}
}

func (l *leaf) getAmount() int64 {
	return l.output.Value
}

func (l *leaf) getOutputs() ([]*wire.TxOut, error) {
	return []*wire.TxOut{l.output, txutils.AnchorOutput()}, nil
}

func (l *leaf) tree(
	initialInput *wire.OutPoint, expiry *arklib.RelativeLocktime,
) (*TxTree, error) {
	tx, err := getTx(l, initialInput, expiry)
	if err != nil {
		return nil, err
	}

	return &TxTree{Root: tx}, nil
}

type branch struct {
	inputScript []byte
	cosigners   []*btcec.PublicKey
	children    []node
}

func (b *branch) getInputScript() []byte {
	return b.inputScript
}

func (b *branch) getCosigners() []*btcec.PublicKey {
	return b.cosigners
}

func (b *branch) getChildren() []node {
	return b.children
}

func (b *branch) getAmount() int64 {
	amount := int64(0)
	for _, child := range b.children {
		amount += child.getAmount()
		amount += txutils.ANCHOR_VALUE
	}

	return amount
}

func (b *branch) getOutputs() ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0)

	for _, child := range b.children {
		outputs = append(outputs, &wire.TxOut{
			Value:    child.getAmount(),
			PkScript: child.getInputScript(),
		})
	}

	return append(outputs, txutils.AnchorOutput()), nil
}

func (b *branch) tree(
	initialInput *wire.OutPoint, expiry *arklib.RelativeLocktime,
) (*TxTree, error) {
	tx, err := getTx(b, initialInput, expiry)
	if err != nil {
		return nil, err
	}

	txTree := &TxTree{
		Root:     tx,
		Children: make(map[uint32]*TxTree),
	}

	children := b.getChildren()
	for i, child := range children {
		subTree, err := child.tree(&wire.OutPoint{
			Hash:  tx.UnsignedTx.TxHash(),
			Index: uint32(i),
		}, expiry)
		if err != nil {
			return nil, err
		}

		txTree.Children[uint32(i)] = subTree
	}

	return txTree, nil
}

func getTx(n node, input *wire.OutPoint, expiry *arklib.RelativeLocktime) (*psbt.Packet, error) {
	outputs, err := n.getOutputs()
	if err != nil {
		return nil, err
	}

	tx, err := psbt.New([]*wire.OutPoint{input}, outputs, 3, 0, []uint32{wire.MaxTxInSequenceNum})
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(tx)
	if err != nil {
		return nil, err
	}

	if err := updater.AddInSighashType(0, int(txscript.SigHashDefault)); err != nil {
		return nil, err
	}

	for _, cosigner := range n.getCosigners() {
		if err := txutils.AddCosignerKey(0, tx, cosigner); err != nil {
			return nil, err
		}
	}

	if expiry != nil {
		if err := txutils.AddVtxoTreeExpiry(0, tx, *expiry); err != nil {
			return nil, err
		}
	}

	return tx, nil
}

// createTxTree is a recursive function that creates a tree of transactions from the leaves up to
// the root.
func createTxTree(receivers []Leaf, tapTreeRoot []byte, radix int) (root node, err error) {
	if len(receivers) == 0 {
		return nil, fmt.Errorf("no receivers provided")
	}

	nodes := make([]node, 0, len(receivers))
	for _, r := range receivers {
		pkScript, err := hex.DecodeString(r.Script)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cosigner pubkey: %w", err)
		}

		cosigners := make([]*btcec.PublicKey, 0)

		for _, cosigner := range r.CosignersPublicKeys {
			pubkeyBytes, err := hex.DecodeString(cosigner)
			if err != nil {
				return nil, fmt.Errorf("failed to decode cosigner pubkey: %w", err)
			}

			pubkey, err := btcec.ParsePubKey(pubkeyBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cosigner pubkey: %w", err)
			}

			cosigners = append(cosigners, pubkey)
		}
		cosigners = uniqueCosigners(cosigners)

		if len(cosigners) == 0 {
			return nil, fmt.Errorf("no cosigners for %s", r.Script)
		}

		aggregatedKey, err := AggregateKeys(cosigners, tapTreeRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to aggregate keys: %w", err)
		}

		inputScript, err := script.P2TRScript(aggregatedKey.FinalKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create script pubkey: %w", err)
		}

		leafNode := &leaf{
			output:      &wire.TxOut{Value: int64(r.Amount), PkScript: pkScript},
			inputScript: inputScript,
			cosigners:   cosigners,
		}
		nodes = append(nodes, leafNode)
	}

	for len(nodes) > 1 {
		nodes, err = createUpperLevel(nodes, tapTreeRoot, radix)
		if err != nil {
			return nil, fmt.Errorf("failed to create tx tree: %w", err)
		}
	}

	return nodes[0], nil
}

func createUpperLevel(nodes []node, tapTreeRoot []byte, radix int) ([]node, error) {
	if len(nodes) <= 1 {
		return nodes, nil
	}

	if len(nodes) < radix {
		return createUpperLevel(nodes, tapTreeRoot, len(nodes))
	}

	remainder := len(nodes) % radix
	if remainder != 0 {
		// Handle nodes that don't form a complete group
		last := nodes[len(nodes)-remainder:]
		groups, err := createUpperLevel(nodes[:len(nodes)-remainder], tapTreeRoot, radix)
		if err != nil {
			return nil, err
		}

		return append(groups, last...), nil
	}

	groups := make([]node, 0, len(nodes)/radix)
	for i := 0; i < len(nodes); i += radix {
		children := nodes[i : i+radix]

		var cosigners []*btcec.PublicKey
		for _, child := range children {
			cosigners = append(cosigners, child.getCosigners()...)
		}
		cosigners = uniqueCosigners(cosigners)

		aggregatedKey, err := AggregateKeys(cosigners, tapTreeRoot)
		if err != nil {
			return nil, err
		}

		inputPkScript, err := script.P2TRScript(aggregatedKey.FinalKey)
		if err != nil {
			return nil, err
		}

		branchNode := &branch{
			inputScript: inputPkScript,
			cosigners:   cosigners,
			children:    children,
		}

		groups = append(groups, branchNode)
	}
	return groups, nil
}

// uniqueCosigners removes duplicate cosigner keys while preserving order
func uniqueCosigners(cosigners []*btcec.PublicKey) []*btcec.PublicKey {
	seen := make(map[string]struct{})
	unique := make([]*btcec.PublicKey, 0, len(cosigners))

	for _, cosigner := range cosigners {
		keyStr := hex.EncodeToString(schnorr.SerializePubKey(cosigner))
		if _, exists := seen[keyStr]; !exists {
			seen[keyStr] = struct{}{}
			unique = append(unique, cosigner)
		}
	}
	return unique
}
