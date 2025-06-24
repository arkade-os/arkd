package arksdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/indexer"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/lntypes"
)

func findVtxosSpent(vtxos []types.Vtxo, id string) []types.Vtxo {
	var result []types.Vtxo
	leftVtxos := make([]types.Vtxo, 0)
	for _, v := range vtxos {
		if v.SpentBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func findVtxosSpentInSettlement(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSpent(vtxos, vtxo.CommitmentTxid)
}

func findVtxosSpentInPayment(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSpentBy(vtxos []types.Vtxo, spentByTxid string) []types.Vtxo {
	var result []types.Vtxo
	for _, v := range vtxos {
		if !v.Preconfirmed && v.CommitmentTxid == spentByTxid {
			result = append(result, v)
			break
		}
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func reduceVtxosAmount(vtxos []types.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func getVtxo(usedVtxos []types.Vtxo, spentByVtxos []types.Vtxo) types.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	}
	if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return types.Vtxo{}
}

func vtxosToTxHistory(
	spendable, spent []types.Vtxo, boardingRounds map[string]struct{}, indexerSvc indexer.Indexer,
) ([]types.Transaction, error) {
	txs := make([]types.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx
	vtxosLeftToCheck := append([]types.Vtxo{}, spent...)
	for _, vtxo := range append(spendable, spent...) {
		if _, ok := boardingRounds[vtxo.CommitmentTxid]; !vtxo.Preconfirmed && ok {
			continue
		}
		settleVtxos := findVtxosSpentInSettlement(vtxosLeftToCheck, vtxo)
		settleAmount := reduceVtxosAmount(settleVtxos)
		if vtxo.Amount <= settleAmount {
			continue // settlement or change, ignore
		}

		spentVtxos := findVtxosSpentInPayment(vtxosLeftToCheck, vtxo)
		spentAmount := reduceVtxosAmount(spentVtxos)
		if vtxo.Amount <= spentAmount {
			continue // settlement or change, ignore
		}

		txKey := types.TransactionKey{
			CommitmentTxid: vtxo.CommitmentTxid,
		}
		settled := !vtxo.Preconfirmed
		if vtxo.Preconfirmed {
			txKey = types.TransactionKey{
				ArkTxid: vtxo.Txid,
			}
			settled = vtxo.SpentBy != ""
		}

		txs = append(txs, types.Transaction{
			TransactionKey: txKey,
			Amount:         vtxo.Amount - settleAmount - spentAmount,
			Type:           types.TxReceived,
			CreatedAt:      vtxo.CreatedAt,
			Settled:        settled,
		})
	}

	// Sendings

	// All "spentBy" vtxos are payments unless:
	// - they are settlements

	// aggregate spent by spentId
	vtxosBySpentBy := make(map[string][]types.Vtxo)
	for _, v := range spent {
		if len(v.SpentBy) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.SpentBy]; !ok {
			vtxosBySpentBy[v.SpentBy] = make([]types.Vtxo, 0)
		}
		vtxosBySpentBy[v.SpentBy] = append(vtxosBySpentBy[v.SpentBy], v)
	}

	for sb := range vtxosBySpentBy {
		resultedVtxos := findVtxosResultedFromSpentBy(append(spendable, spent...), sb)
		resultedAmount := reduceVtxosAmount(resultedVtxos)
		spentAmount := reduceVtxosAmount(vtxosBySpentBy[sb])
		if spentAmount <= resultedAmount {
			continue // settlement, ignore
		}
		vtxo := getVtxo(resultedVtxos, vtxosBySpentBy[sb])
		if resultedAmount == 0 {
			// send all: fetch the created vtxo (not belong to us) to source
			// creation and expiration timestamps
			opts := &indexer.GetVtxosRequestOption{}
			// nolint:all
			opts.WithOutpoints([]indexer.Outpoint{{Txid: sb, VOut: 0}})
			resp, err := indexerSvc.GetVtxos(context.Background(), *opts)
			if err != nil {
				return nil, err
			}
			vtxo = types.Vtxo{
				VtxoKey: types.VtxoKey{
					Txid: sb,
					VOut: 0,
				},
				CommitmentTxid: resp.Vtxos[0].CommitmentTxid,
				ExpiresAt:      resp.Vtxos[0].ExpiresAt,
				CreatedAt:      resp.Vtxos[0].CreatedAt,
				Preconfirmed:   resp.Vtxos[0].Preconfirmed,
			}
		}

		txKey := types.TransactionKey{
			CommitmentTxid: vtxo.CommitmentTxid,
		}
		if vtxo.Preconfirmed {
			txKey = types.TransactionKey{
				ArkTxid: vtxo.Txid,
			}
		}

		txs = append(txs, types.Transaction{
			TransactionKey: txKey,
			Amount:         spentAmount - resultedAmount,
			Type:           types.TxSent,
			CreatedAt:      vtxo.CreatedAt,
			Settled:        true,
		})

	}

	sort.SliceStable(txs, func(i, j int) bool {
		return txs[i].CreatedAt.After(txs[j].CreatedAt)
	})

	return txs, nil
}

type arkTxInput struct {
	client.TapscriptsVtxo
	ForfeitLeafHash chainhash.Hash
}

func buildOffchainTx(
	vtxos []arkTxInput, receivers []types.Receiver,
	serverUnrollScript *tree.CSVMultisigClosure, dustLimit uint64,
) (string, []string, error) {
	if len(vtxos) <= 0 {
		return "", nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]common.VtxoInput, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := tree.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", nil, err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", nil, err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", nil, err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", nil, err
		}

		tapscript := &waddrmgr.Tapscript{
			RevealedScript: leafProof.Script,
			ControlBlock:   ctrlBlock,
		}

		ins = append(ins, common.VtxoInput{
			Outpoint:           vtxoOutpoint,
			Tapscript:          tapscript,
			Amount:             int64(vtxo.Amount),
			RevealedTapscripts: vtxo.Tapscripts,
		})
	}

	outs := make([]*wire.TxOut, 0, len(receivers))

	for i, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", nil, fmt.Errorf("receiver %d is onchain", i)
		}

		addr, err := common.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, err
		}

		var newVtxoScript []byte

		if receiver.Amount < dustLimit {
			newVtxoScript, err = common.SubDustScript(addr.VtxoTapKey)
		} else {
			newVtxoScript, err = common.P2TRScript(addr.VtxoTapKey)
		}
		if err != nil {
			return "", nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: newVtxoScript,
		})
	}

	arkPtx, checkpointPtxs, err := tree.BuildOffchainTx(ins, outs, serverUnrollScript)
	if err != nil {
		return "", nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, err
	}

	checkpointTxs := make([]string, 0, len(checkpointPtxs))
	for _, ptx := range checkpointPtxs {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", nil, err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	return arkTx, checkpointTxs, nil
}

func inputsToDerivationPath(inputs []types.VtxoKey, notesInputs []string) string {
	// sort arknotes
	slices.SortStableFunc(notesInputs, func(i, j string) int {
		return strings.Compare(i, j)
	})

	// sort outpoints
	slices.SortStableFunc(inputs, func(i, j types.VtxoKey) int {
		txidCmp := strings.Compare(i.Txid, j.Txid)
		if txidCmp != 0 {
			return txidCmp
		}
		return int(i.VOut - j.VOut)
	})

	// serialize outpoints and arknotes

	var buf bytes.Buffer

	for _, input := range inputs {
		buf.WriteString(input.Txid)
		buf.WriteString(strconv.Itoa(int(input.VOut)))
	}

	for _, note := range notesInputs {
		buf.WriteString(note)
	}

	// hash the serialized data
	hash := sha256.Sum256(buf.Bytes())

	// convert hash to bip32 derivation path
	// split the 32-byte hash into 8 uint32 values (4 bytes each)
	path := "m"
	for i := 0; i < 8; i++ {
		// Convert 4 bytes to uint32 using big-endian encoding
		segment := binary.BigEndian.Uint32(hash[i*4 : (i+1)*4])
		path += fmt.Sprintf("/%d'", segment)
	}

	return path
}

func extractExitPath(tapscripts []string) ([]byte, *common.TaprootMerkleProof, uint32, error) {
	vtxoScript, err := tree.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, 0, err
	}

	exitClosures := vtxoScript.ExitClosures()
	if len(exitClosures) <= 0 {
		return nil, nil, 0, fmt.Errorf("no exit closures found")
	}

	exitClosure := exitClosures[0].(*tree.CSVMultisigClosure)

	exitScript, err := exitClosure.Script()
	if err != nil {
		return nil, nil, 0, err
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, 0, err
	}

	exitLeaf := txscript.NewBaseTapLeaf(exitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(exitLeaf.TapHash())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get taproot merkle proof: %s", err)
	}

	sequence, err := common.BIP68Sequence(exitClosure.Locktime)
	if err != nil {
		return nil, nil, 0, err
	}

	pkScript, err := common.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, 0, err
	}

	return pkScript, leafProof, sequence, nil
}

// convert inputs to BIP322 inputs and return all the data needed to sign and proof PSBT
func toBIP322Inputs(
	boardingUtxos []types.Utxo, vtxos []client.TapscriptsVtxo, notes []string,
) ([]bip322.Input, []*common.TaprootMerkleProof, map[string][]string, map[int][]byte, error) {
	inputs := make([]bip322.Input, 0, len(boardingUtxos)+len(vtxos))
	exitLeaves := make([]*common.TaprootMerkleProof, 0, len(boardingUtxos)+len(vtxos))
	tapscripts := make(map[string][]string)
	notesWitnesses := make(map[int][]byte)

	for _, coin := range vtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		tapscripts[outpoint.String()] = coin.Tapscripts

		pkScript, leafProof, vtxoSequence, err := extractExitPath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		exitLeaves = append(exitLeaves, leafProof)

		inputs = append(inputs, bip322.Input{
			OutPoint: outpoint,
			Sequence: vtxoSequence,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})
	}

	for _, coin := range boardingUtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		tapscripts[outpoint.String()] = coin.Tapscripts

		pkScript, leafProof, vtxoSequence, err := extractExitPath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		exitLeaves = append(exitLeaves, leafProof)

		inputs = append(inputs, bip322.Input{
			OutPoint: outpoint,
			Sequence: vtxoSequence,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})
	}

	nextInputIndex := len(inputs)
	if nextInputIndex > 0 {
		// if there is non-notes inputs, count the extra bip322 input
		nextInputIndex++
	}

	for _, n := range notes {
		parsedNote, err := note.NewFromString(n)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		input, err := parsedNote.BIP322Input()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		inputs = append(inputs, *input)

		vtxoScript := parsedNote.VtxoScript()

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		exitScript, err := vtxoScript.Closures[0].Script()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		exitLeaf := txscript.NewBaseTapLeaf(exitScript)
		leafProof, err := taprootTree.GetTaprootMerkleProof(exitLeaf.TapHash())
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		witness, err := vtxoScript.Closures[0].Witness(leafProof.ControlBlock, map[string][]byte{
			"preimage": parsedNote.Preimage[:],
		})
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to get witness: %s", err)
		}

		var witnessBuf bytes.Buffer
		if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to write witness: %s", err)
		}

		notesWitnesses[nextInputIndex] = witnessBuf.Bytes()
		nextInputIndex++
		// if the note vtxo is the first input, it will be used twice
		if nextInputIndex == 1 {
			notesWitnesses[nextInputIndex] = witnessBuf.Bytes()
			nextInputIndex++
		}

		exitLeaves = append(exitLeaves, leafProof)
		encodedVtxoScript, err := vtxoScript.Encode()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tapscripts[input.OutPoint.String()] = encodedVtxoScript
	}

	return inputs, exitLeaves, tapscripts, notesWitnesses, nil
}
func getOffchainBalanceDetails(amountByExpiration map[int64]uint64) (int64, []VtxoDetails) {
	nextExpiration := int64(0)
	details := make([]VtxoDetails, 0)
	for timestamp, amount := range amountByExpiration {
		if nextExpiration == 0 || timestamp < nextExpiration {
			nextExpiration = timestamp
		}

		fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
		details = append(
			details,
			VtxoDetails{
				ExpiryTime: fancyTime,
				Amount:     amount,
			},
		)
	}
	return nextExpiration, details
}

func getFancyTimeExpiration(nextExpiration int64) string {
	if nextExpiration == 0 {
		return ""
	}

	fancyTimeExpiration := ""
	t := time.Unix(nextExpiration, 0)
	if t.Before(time.Now().Add(48 * time.Hour)) {
		// print the duration instead of the absolute time
		until := time.Until(t)
		seconds := math.Abs(until.Seconds())
		minutes := math.Abs(until.Minutes())
		hours := math.Abs(until.Hours())

		if hours < 1 {
			if minutes < 1 {
				fancyTimeExpiration = fmt.Sprintf("%d seconds", int(seconds))
			} else {
				fancyTimeExpiration = fmt.Sprintf("%d minutes", int(minutes))
			}
		} else {
			fancyTimeExpiration = fmt.Sprintf("%d hours", int(hours))
		}
	} else {
		fancyTimeExpiration = t.Format(time.RFC3339)
	}
	return fancyTimeExpiration
}

func computeVSize(tx *wire.MsgTx) lntypes.VByte {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize() // including witness
	weight := totalSize + baseSize*3
	return lntypes.WeightUnit(uint64(weight)).ToVB()
}

// custom BIP322 finalizer function handling note vtxo inputs
func finalizeWithNotes(notesWitnesses map[int][]byte) func(ptx *psbt.Packet) error {
	return func(ptx *psbt.Packet) error {
		for i, input := range ptx.Inputs {
			witness, isNote := notesWitnesses[i]
			if !isNote {
				ok, err := psbt.MaybeFinalize(ptx, i)
				if err != nil {
					return fmt.Errorf("failed to finalize input %d: %s", i, err)
				}
				if !ok {
					return fmt.Errorf("failed to finalize input %d", i)
				}
				continue
			}

			newInput := psbt.NewPsbtInput(nil, input.WitnessUtxo)
			newInput.FinalScriptWitness = witness
			ptx.Inputs[i] = *newInput
		}

		return nil
	}
}

func handleBatchTreeSignature(
	event client.TreeSignatureEvent, graph *tree.TxGraph,
) error {
	if event.BatchIndex != 0 {
		return fmt.Errorf("batch index %d is not 0", event.BatchIndex)
	}

	decodedSig, err := hex.DecodeString(event.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %s", err)
	}

	sig, err := schnorr.ParseSignature(decodedSig)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %s", err)
	}

	return graph.Apply(func(g *tree.TxGraph) (bool, error) {
		if g.Root.UnsignedTx.TxID() != event.Txid {
			return true, nil
		}

		g.Root.Inputs[0].TaprootKeySpendSig = sig.Serialize()
		return false, nil
	})
}

func checkSettleOptionsType(o interface{}) (*SettleOptions, error) {
	opts, ok := o.(*SettleOptions)
	if !ok {
		return nil, fmt.Errorf("invalid options type")
	}

	return opts, nil
}

func registerIntentMessage(
	inputs []bip322.Input, outputs []types.Receiver, tapscripts map[string][]string,
	cosignersPublicKeys []string,
) (string, []*wire.TxOut, error) {
	validAt := time.Now()
	expireAt := validAt.Add(2 * time.Minute).Unix()
	outputsTxOut := make([]*wire.TxOut, 0)
	onchainOutputsIndexes := make([]int, 0)
	inputTapTrees := make([]string, 0)

	for _, input := range inputs {
		outpointStr := input.OutPoint.String()
		tapscripts, ok := tapscripts[outpointStr]
		if !ok {
			return "", nil, fmt.Errorf("no tapscripts found for input %s", outpointStr)
		}

		encodedTapTree, err := tree.TapTree(tapscripts).Encode()
		if err != nil {
			return "", nil, err
		}

		inputTapTrees = append(inputTapTrees, hex.EncodeToString(encodedTapTree))
	}

	for i, output := range outputs {
		txOut, isOnchain, err := output.ToTxOut()
		if err != nil {
			return "", nil, err
		}

		if isOnchain {
			onchainOutputsIndexes = append(onchainOutputsIndexes, i)
		}

		outputsTxOut = append(outputsTxOut, txOut)
	}

	message, err := tree.IntentMessage{
		BaseIntentMessage: tree.BaseIntentMessage{
			Type: tree.IntentMessageTypeRegister,
		},
		InputTapTrees:        inputTapTrees,
		OnchainOutputIndexes: onchainOutputsIndexes,
		ExpireAt:             expireAt,
		ValidAt:              validAt.Unix(),
		CosignersPublicKeys:  cosignersPublicKeys,
	}.Encode()
	if err != nil {
		return "", nil, err
	}

	return message, outputsTxOut, nil
}
