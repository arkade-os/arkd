package unroll

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	log "github.com/sirupsen/logrus"
)

// UnrollArgs configures Unroll: builds 1C1P bump packages for each given
// vtxo's next branch tx and broadcasts each parent+child pair.
type UnrollArgs struct {
	Explorer   clientlib.Explorer
	Indexer    clientlib.Indexer
	SignTx     clientlib.SignFn
	ServerInfo clientlib.Info
	Vtxos      []clientlib.Vtxo
	BumpAddr   string
	BumpPubKey *btcec.PublicKey
}

func (a UnrollArgs) validate() error {
	if a.Explorer == nil {
		return fmt.Errorf("missing explorer")
	}
	if a.Indexer == nil {
		return fmt.Errorf("missing indexer")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx function")
	}
	if a.BumpPubKey == nil {
		return fmt.Errorf("missing bump pub key")
	}
	if len(a.ServerInfo.Network) <= 0 {
		return fmt.Errorf("missing server info")
	}
	if len(a.Vtxos) <= 0 {
		return fmt.Errorf("missing vtxos to unroll")
	}
	if len(a.BumpAddr) <= 0 {
		return fmt.Errorf("missing bump address")
	}
	netParams := clientlib.ToBitcoinNetwork(clientlib.NetworkFromString(a.ServerInfo.Network))
	if _, err := btcutil.DecodeAddress(a.BumpAddr, &netParams); err != nil {
		return fmt.Errorf("invalid bump address")
	}
	return nil
}

// Unroll iterates over each vtxo's redeem branch, builds a 1C1P bump package
// (parent branch tx + child anchor-bumping tx) and broadcasts the package.
func Unroll(ctx context.Context, args UnrollArgs) ([]UnrollRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	vtxos := args.Vtxos

	totalVtxosAmount := uint64(0)
	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.Amount
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	branches, err := getBranchesToUnroll(ctx, args.Explorer, args.Indexer, vtxos)
	if err != nil {
		return nil, err
	}

	isWaitingForConfirmation := false

	for _, branch := range branches {
		nextTx, err := branch.NextRedeemTx()
		if err != nil {
			if err, ok := err.(ErrPendingConfirmation); ok {
				// the branch tx is in the mempool, we must wait for confirmation
				// print only, do not make the function to fail
				// continue to try other branches
				log.Debug(err.Error())
				isWaitingForConfirmation = true
				continue
			}

			return nil, err
		}

		if _, ok := transactionsMap[nextTx]; !ok {
			transactions = append(transactions, nextTx)
			transactionsMap[nextTx] = struct{}{}
		}
	}

	if len(transactions) == 0 {
		if isWaitingForConfirmation {
			return nil, ErrWaitingForConfirmation
		}

		return nil, nil
	}

	res := make([]UnrollRes, 0, len(transactions))
	for _, parent := range transactions {
		var parentTx wire.MsgTx
		if err := parentTx.Deserialize(hex.NewDecoder(strings.NewReader(parent))); err != nil {
			return nil, err
		}

		childTxid, child, err := bumpAnchorTx(ctx, args, &parentTx)
		if err != nil {
			return nil, err
		}

		// broadcast the package (parent + child)
		packageResponse, err := args.Explorer.Broadcast(parent, child)
		if err != nil {
			return nil, err
		}

		res = append(res, UnrollRes{
			ParentTx:   parent,
			ParentTxid: parentTx.TxID(),
			ChildTx:    child,
			ChildTxid:  childTxid,
		})
		log.Debugf("package broadcasted: %s", packageResponse)
	}

	return res, nil
}

// bumpAnchorTx builds and signs a transaction bumping the fees for a given tx with P2A output.
// Makes use of args.BumpAddr/args.BumpPubKey to select UTXOs to pay fees for parent.
func bumpAnchorTx(
	ctx context.Context, args UnrollArgs, parent *wire.MsgTx,
) (string, string, error) {
	anchor, err := txutils.FindAnchorOutpoint(parent)
	if err != nil {
		return "", "", err
	}

	// estimate for the size of the bump transaction
	weightEstimator := input.TxWeightEstimator{}

	// WeightEstimator doesn't support P2A size, using P2WSH will lead to a small overestimation
	// TODO use the exact P2A size
	weightEstimator.AddNestedP2WSHInput(lntypes.VByte(3).ToWU())

	// We assume only one UTXO will be selected to have a correct estimation
	weightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault)
	weightEstimator.AddP2TROutput()

	childVSize := weightEstimator.Weight().ToVB()

	packageSize := childVSize + computeVSize(parent)
	feeRate, err := args.Explorer.GetFeeRate()
	if err != nil {
		return "", "", err
	}

	fees := uint64(math.Ceil(float64(packageSize) * feeRate))

	addr := args.BumpAddr
	pkScript, err := toOutputScript(addr, clientlib.NetworkFromString(args.ServerInfo.Network))
	if err != nil {
		return "", "", err
	}

	selectedCoins := make([]clientlib.ExplorerUtxo, 0)
	selectedAmount := uint64(0)
	amountToSelect := int64(fees) - txutils.ANCHOR_VALUE

	utxos, err := args.Explorer.GetUtxos([]string{addr})
	if err != nil {
		return "", "", err
	}

	for _, utxo := range utxos {
		selectedCoins = append(selectedCoins, utxo)
		selectedAmount += utxo.Amount
		amountToSelect -= int64(utxo.Amount)
		if amountToSelect <= 0 {
			break
		}
	}

	if amountToSelect > 0 {
		return "", "", fmt.Errorf("not enough funds to select %d", amountToSelect)
	}

	changeAmount := selectedAmount - fees

	inputs := []*wire.OutPoint{anchor}
	sequences := []uint32{
		wire.MaxTxInSequenceNum,
	}
	outputs := []*wire.TxOut{
		{
			Value:    int64(changeAmount),
			PkScript: pkScript,
		},
	}

	for _, utxo := range selectedCoins {
		txid, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return "", "", err
		}
		inputs = append(inputs, &wire.OutPoint{
			Hash:  *txid,
			Index: utxo.Vout,
		})
		sequences = append(sequences, wire.MaxTxInSequenceNum)
	}

	ptx, err := psbt.New(inputs, outputs, 3, 0, sequences)
	if err != nil {
		return "", "", err
	}

	ptx.Inputs[0].WitnessUtxo = txutils.AnchorOutput()

	for i, utxo := range selectedCoins {
		pkScript, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return "", "", err
		}

		ptx.Inputs[i+1].WitnessUtxo = &wire.TxOut{
			Value:    int64(utxo.Amount),
			PkScript: pkScript,
		}
		ptx.Inputs[i+1].TaprootInternalKey = schnorr.SerializePubKey(args.BumpPubKey)
	}

	b64, err := ptx.B64Encode()
	if err != nil {
		return "", "", err
	}

	tx, err := args.SignTx(ctx, b64)
	if err != nil {
		return "", "", err
	}

	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", "", err
	}

	for inIndex := range signedPtx.Inputs[1:] {
		if _, err := psbt.MaybeFinalize(signedPtx, inIndex+1); err != nil {
			return "", "", err
		}
	}

	childTx, err := txutils.ExtractWithAnchors(signedPtx)
	if err != nil {
		return "", "", err
	}

	var serializedTx bytes.Buffer
	if err := childTx.Serialize(&serializedTx); err != nil {
		return "", "", err
	}

	return childTx.TxID(), hex.EncodeToString(serializedTx.Bytes()), nil
}
