package arksdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey"
	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
	filestore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/file"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/lntypes"
)

func getClient(
	supportedClients utils.SupportedType[utils.ClientFactory],
	clientType, serverUrl string, withMonitorConn bool,
) (client.TransportClient, error) {
	factory := supportedClients[clientType]
	return factory(serverUrl, withMonitorConn)
}

func getIndexer(
	supportedIndexers utils.SupportedType[utils.IndexerFactory],
	clientType, serverUrl string, withMonitorConn bool,
) (indexer.Indexer, error) {
	factory := supportedIndexers[clientType]
	return factory(serverUrl, withMonitorConn)
}

func getWallet(
	configStore types.ConfigStore, walletType string,
	supportedWallets utils.SupportedType[struct{}],
) (wallet.WalletService, error) {
	switch walletType {
	case wallet.SingleKeyWallet:
		return getSingleKeyWallet(configStore)
	default:
		return nil, fmt.Errorf(
			"unsupported wallet type '%s', please select one of: %s", walletType, supportedWallets,
		)
	}
}

func getSingleKeyWallet(configStore types.ConfigStore) (wallet.WalletService, error) {
	walletStore, err := getWalletStore(configStore.GetType(), configStore.GetDatadir())
	if err != nil {
		return nil, err
	}

	return singlekeywallet.NewBitcoinWallet(configStore, walletStore)
}

func getWalletStore(storeType, datadir string) (walletstore.WalletStore, error) {
	switch storeType {
	case types.InMemoryStore:
		return inmemorystore.NewWalletStore()
	case types.FileStore:
		return filestore.NewWalletStore(datadir)
	default:
		return nil, fmt.Errorf("unknown wallet store type")
	}
}

func filterByOutpoints(vtxos []types.Vtxo, outpoints []types.Outpoint) []types.Vtxo {
	filtered := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		for _, outpoint := range outpoints {
			if vtxo.Outpoint == outpoint {
				filtered = append(filtered, vtxo)
			}
		}
	}
	return filtered
}

type arkTxInput struct {
	types.VtxoWithTapTree
	ForfeitLeafHash chainhash.Hash
}

func validateReceivers(
	network arklib.Network, ptx *psbt.Packet, receivers []types.Receiver, vtxoTree *tree.TxTree,
) error {
	netParams := utils.ToBitcoinNetwork(network)
	for _, receiver := range receivers {
		isOnChain, onchainScript, err := utils.ParseBitcoinAddress(receiver.To, netParams)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s err = %s", receiver.To, err)
		}

		if isOnChain {
			if err := validateOnchainReceiver(ptx, receiver, onchainScript); err != nil {
				return err
			}
		} else {
			if err := validateOffchainReceiver(vtxoTree, receiver); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOnchainReceiver(
	ptx *psbt.Packet, receiver types.Receiver, onchainScript []byte,
) error {
	found := false
	for _, output := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(output.PkScript, onchainScript) {
			if output.Value != int64(receiver.Amount) {
				return fmt.Errorf(
					"invalid collaborative exit output amount: got %d, want %d",
					output.Value, receiver.Amount,
				)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("collaborative exit output not found: %s", receiver.To)
	}
	return nil
}

func validateOffchainReceiver(vtxoTree *tree.TxTree, receiver types.Receiver) error {
	found := false

	rcvAddr, err := arklib.DecodeAddressV0(receiver.To)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(rcvAddr.VtxoTapKey)

	leaves := vtxoTree.Leaves()
	for _, leaf := range leaves {
		for _, output := range leaf.UnsignedTx.TxOut {
			if len(output.PkScript) == 0 {
				continue
			}

			if bytes.Equal(output.PkScript[2:], vtxoTapKey) {
				if output.Value != int64(receiver.Amount) {
					continue
				}

				found = true
				break
			}
		}

		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf("offchain send output not found: %s", receiver.To)
	}

	return nil
}

func buildOffchainTx(
	vtxos []arkTxInput, receivers []types.Receiver, serverUnrollScript []byte, dustLimit uint64,
) (string, []string, error) {
	if len(vtxos) <= 0 {
		return "", nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(vtxos))
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

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
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

		ins = append(ins, offchain.VtxoInput{
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

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, err
		}

		var newVtxoScript []byte

		if receiver.Amount < dustLimit {
			newVtxoScript, err = script.SubDustScript(addr.VtxoTapKey)
		} else {
			newVtxoScript, err = script.P2TRScript(addr.VtxoTapKey)
		}
		if err != nil {
			return "", nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: newVtxoScript,
		})
	}

	arkPtx, checkpointPtxs, err := offchain.BuildTxs(ins, outs, serverUnrollScript)
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

func inputsToDerivationPath(inputs []types.Outpoint, notesInputs []string) string {
	// sort arknotes
	slices.SortStableFunc(notesInputs, func(i, j string) int {
		return strings.Compare(i, j)
	})

	// sort outpoints
	slices.SortStableFunc(inputs, func(i, j types.Outpoint) int {
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

func extractCollaborativePath(tapscripts []string) ([]byte, *arklib.TaprootMerkleProof, error) {
	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, err
	}

	forfeitClosures := vtxoScript.ForfeitClosures()
	if len(forfeitClosures) <= 0 {
		return nil, nil, fmt.Errorf("no exit closures found")
	}

	forfeitClosure := forfeitClosures[0]
	forfeitScript, err := forfeitClosure.Script()
	if err != nil {
		return nil, nil, err
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get taproot merkle proof: %s", err)
	}
	pkScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return pkScript, leafProof, nil
}

// convert regular coins (boarding, vtxos or notes) to intent proof inputs
// it also returns the necessary data used to sign the proof PSBT
func toIntentInputs(
	boardingUtxos []types.Utxo, vtxos []types.VtxoWithTapTree, notes []string,
) ([]intent.Input, []*arklib.TaprootMerkleProof, [][]*psbt.Unknown, error) {
	inputs := make([]intent.Input, 0, len(boardingUtxos)+len(vtxos))
	signingLeaves := make([]*arklib.TaprootMerkleProof, 0, len(boardingUtxos)+len(vtxos))
	arkFields := make([][]*psbt.Unknown, 0, len(boardingUtxos)+len(vtxos))

	for _, coin := range vtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		pkScript, leafProof, err := extractCollaborativePath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		signingLeaves = append(signingLeaves, leafProof)

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})

		taptreeField, err := txutils.VtxoTaprootTreeField.Encode(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		arkFields = append(arkFields, []*psbt.Unknown{taptreeField})
	}

	for _, coin := range boardingUtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		pkScript, leafProof, err := extractCollaborativePath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		signingLeaves = append(signingLeaves, leafProof)

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})

		taptreeField, err := txutils.VtxoTaprootTreeField.Encode(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}
		arkFields = append(arkFields, []*psbt.Unknown{taptreeField})
	}

	nextInputIndex := len(inputs)
	if nextInputIndex > 0 {
		// if there is non-notes inputs, count the extra intent proof input
		nextInputIndex++
	}

	for _, n := range notes {
		parsedNote, err := note.NewNoteFromString(n)
		if err != nil {
			return nil, nil, nil, err
		}

		outpoint, input, err := parsedNote.IntentProofInput()
		if err != nil {
			return nil, nil, nil, err
		}

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    input.WitnessUtxo.Value,
				PkScript: input.WitnessUtxo.PkScript,
			},
		})

		vtxoScript := parsedNote.VtxoScript()

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, nil, nil, err
		}

		forfeitScript, err := vtxoScript.Closures[0].Script()
		if err != nil {
			return nil, nil, nil, err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		nextInputIndex++
		// if the note vtxo is the first input, it will be used twice
		if nextInputIndex == 1 {
			nextInputIndex++
		}

		signingLeaves = append(signingLeaves, leafProof)
		arkFields = append(arkFields, input.Unknowns)
	}

	return inputs, signingLeaves, arkFields, nil
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

func registerIntentMessage(
	outputs []types.Receiver, cosignersPublicKeys []string,
) (string, []*wire.TxOut, error) {
	outputsTxOut := make([]*wire.TxOut, 0)
	onchainOutputsIndexes := make([]int, 0)

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

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: onchainOutputsIndexes,
		CosignersPublicKeys:  cosignersPublicKeys,
	}.Encode()
	if err != nil {
		return "", nil, err
	}

	return message, outputsTxOut, nil
}

func findVtxosSpentInSettlement(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSettled(vtxos, vtxo.CommitmentTxids[0])
}

func findVtxosSettled(vtxos []types.Vtxo, id string) []types.Vtxo {
	var result []types.Vtxo
	leftVtxos := make([]types.Vtxo, 0)
	for _, v := range vtxos {
		if v.SettledBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func findVtxosResultedFromSettledBy(vtxos []types.Vtxo, commitmentTxid string) []types.Vtxo {
	var result []types.Vtxo
	for _, v := range vtxos {
		if v.Preconfirmed || len(v.CommitmentTxids) != 1 {
			continue
		}
		if v.CommitmentTxids[0] == commitmentTxid {
			result = append(result, v)
		}
	}
	return result
}

func findVtxosSpent(vtxos []types.Vtxo, id string) []types.Vtxo {
	var result []types.Vtxo
	leftVtxos := make([]types.Vtxo, 0)
	for _, v := range vtxos {
		if v.ArkTxid == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func reduceVtxosAmount(vtxos []types.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSpentBy(vtxos []types.Vtxo, spentByTxid string) []types.Vtxo {
	var result []types.Vtxo
	for _, v := range vtxos {
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []types.Vtxo, spentByVtxos []types.Vtxo) types.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return types.Vtxo{}
}

func ecPubkeyFromHex(pubkey string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(buf)
}

func getBatchExpiryLocktime(expiry uint32) arklib.RelativeLocktime {
	if expiry >= 512 {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: expiry}
	}
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: expiry}
}

func toOutputScript(onchainAddress string, network arklib.Network) ([]byte, error) {
	netParams := utils.ToBitcoinNetwork(network)
	rcvAddr, err := btcutil.DecodeAddress(onchainAddress, &netParams)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(rcvAddr)
}

func verifySignedCheckpoints(
	originalCheckpoints, signedCheckpoints []string, signerpubkey *btcec.PublicKey,
) error {
	// index by txid
	indexedOriginalCheckpoints := make(map[string]*psbt.Packet)
	indexedSignedCheckpoints := make(map[string]*psbt.Packet)

	for _, cp := range originalCheckpoints {
		originalPtx, err := psbt.NewFromRawBytes(strings.NewReader(cp), true)
		if err != nil {
			return err
		}
		indexedOriginalCheckpoints[originalPtx.UnsignedTx.TxID()] = originalPtx
	}

	for _, cp := range signedCheckpoints {
		signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(cp), true)
		if err != nil {
			return err
		}
		indexedSignedCheckpoints[signedPtx.UnsignedTx.TxID()] = signedPtx
	}

	for txid, originalPtx := range indexedOriginalCheckpoints {
		signedPtx, ok := indexedSignedCheckpoints[txid]
		if !ok {
			return fmt.Errorf("signed checkpoint %s not found", txid)
		}
		if err := verifyOffchainPsbt(originalPtx, signedPtx, signerpubkey); err != nil {
			return err
		}
	}

	return nil
}

func verifySignedArk(original, signed string, signerPubKey *btcec.PublicKey) error {
	originalPtx, err := psbt.NewFromRawBytes(strings.NewReader(original), true)
	if err != nil {
		return err
	}

	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		return err
	}

	return verifyOffchainPsbt(originalPtx, signedPtx, signerPubKey)
}

func verifyOffchainPsbt(original, signed *psbt.Packet, signerpubkey *btcec.PublicKey) error {
	xonlySigner := schnorr.SerializePubKey(signerpubkey)

	if original.UnsignedTx.TxID() != signed.UnsignedTx.TxID() {
		return fmt.Errorf("invalid offchain tx : txids mismatch")
	}

	if len(original.Inputs) != len(signed.Inputs) {
		return fmt.Errorf(
			"input count mismatch: expected %d, got %d",
			len(original.Inputs),
			len(signed.Inputs),
		)
	}

	if len(original.UnsignedTx.TxIn) != len(signed.UnsignedTx.TxIn) {
		return fmt.Errorf(
			"transaction input count mismatch: expected %d, got %d",
			len(original.UnsignedTx.TxIn),
			len(signed.UnsignedTx.TxIn),
		)
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for inputIndex, signedInput := range signed.Inputs {

		if signedInput.WitnessUtxo == nil {
			return fmt.Errorf("witness utxo not found for input %d", inputIndex)
		}

		// fill prevouts map with the original witness data
		previousOutpoint := original.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		prevouts[previousOutpoint] = original.Inputs[inputIndex].WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txsigHashes := txscript.NewTxSigHashes(original.UnsignedTx, prevoutFetcher)

	// loop over every input and check that the signer's signature is present and valid
	for inputIndex, signedInput := range signed.Inputs {
		orignalInput := original.Inputs[inputIndex]
		if len(orignalInput.TaprootLeafScript) == 0 {
			return fmt.Errorf(
				"original input %d has no taproot leaf script, cannot verify signature",
				inputIndex,
			)
		}

		// check that every input has the signer's signature
		var signerSig *psbt.TaprootScriptSpendSig

		for _, sig := range signedInput.TaprootScriptSpendSig {
			if bytes.Equal(sig.XOnlyPubKey, xonlySigner) {
				signerSig = sig
				break
			}
		}

		if signerSig == nil {
			return fmt.Errorf("signer signature not found for input %d", inputIndex)
		}

		sig, err := schnorr.ParseSignature(signerSig.Signature)
		if err != nil {
			return fmt.Errorf("failed to parse signer signature for input %d: %s", inputIndex, err)
		}

		// verify the signature
		message, err := txscript.CalcTapscriptSignaturehash(
			txsigHashes,
			signedInput.SighashType,
			original.UnsignedTx,
			inputIndex,
			prevoutFetcher,
			txscript.NewBaseTapLeaf(orignalInput.TaprootLeafScript[0].Script),
		)
		if err != nil {
			return err
		}

		if !sig.Verify(message, signerpubkey) {
			return fmt.Errorf("invalid signer signature for input %d", inputIndex)
		}
	}
	return nil
}
