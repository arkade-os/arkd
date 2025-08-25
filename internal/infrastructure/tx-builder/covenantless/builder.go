package txbuilder

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	log "github.com/sirupsen/logrus"
)

type txBuilder struct {
	wallet            ports.WalletService
	network           arklib.Network
	vtxoTreeExpiry    arklib.RelativeLocktime
	boardingExitDelay arklib.RelativeLocktime
}

func NewTxBuilder(
	wallet ports.WalletService, network arklib.Network,
	vtxoTreeExpiry, boardingExitDelay arklib.RelativeLocktime,
) ports.TxBuilder {
	return &txBuilder{wallet, network, vtxoTreeExpiry, boardingExitDelay}
}

func (b *txBuilder) GetTxid(tx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	return ptx.UnsignedTx.TxID(), nil
}

func (b *txBuilder) VerifyTapscriptPartialSigs(tx string) (bool, string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return false, "", err
	}

	return b.verifyTapscriptPartialSigs(ptx)
}

func (b *txBuilder) verifyTapscriptPartialSigs(ptx *psbt.Packet) (bool, string, error) {
	txid := ptx.UnsignedTx.TxID()

	operatorPubkey, err := b.wallet.GetPubkey(context.Background())
	if err != nil {
		return false, txid, err
	}

	operatorPubkeyHex := hex.EncodeToString(schnorr.SerializePubKey(operatorPubkey))

	prevoutFetcher, err := b.getPrevOutputFetcher(ptx)
	if err != nil {
		return false, txid, err
	}

	txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	for index, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) == 0 {
			continue
		}

		if input.WitnessUtxo == nil {
			return false, txid, fmt.Errorf("missing prevout for input %d", index)
		}

		// verify taproot leaf script
		tapLeaf := input.TaprootLeafScript[0]

		closure, err := script.DecodeClosure(tapLeaf.Script)
		if err != nil {
			return false, txid, err
		}

		keys := make(map[string]bool)

		switch c := closure.(type) {
		case *script.MultisigClosure:
			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *script.CSVMultisigClosure:
			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *script.CLTVMultisigClosure:
			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *script.ConditionMultisigClosure:
			witness, err := txutils.GetConditionWitness(input)
			if err != nil {
				return false, txid, err
			}

			result, err := script.EvaluateScriptToBool(c.Condition, witness)
			if err != nil {
				return false, txid, err
			}

			if !result {
				return false, txid, fmt.Errorf("condition not met for input %d", index)
			}

			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		}

		// we don't need to check if operator signed
		keys[operatorPubkeyHex] = true

		if len(tapLeaf.ControlBlock) == 0 {
			return false, txid, fmt.Errorf("missing control block for input %d", index)
		}

		controlBlock, err := txscript.ParseControlBlock(tapLeaf.ControlBlock)
		if err != nil {
			return false, txid, err
		}

		rootHash := controlBlock.RootHash(tapLeaf.Script)
		tapKeyFromControlBlock := txscript.ComputeTaprootOutputKey(
			script.UnspendableKey(), rootHash[:],
		)
		pkscript, err := script.P2TRScript(tapKeyFromControlBlock)
		if err != nil {
			return false, txid, err
		}

		if !bytes.Equal(pkscript, input.WitnessUtxo.PkScript) {
			return false, txid, fmt.Errorf("invalid control block for input %d", index)
		}

		for _, tapScriptSig := range input.TaprootScriptSpendSig {
			sig, err := schnorr.ParseSignature(tapScriptSig.Signature)
			if err != nil {
				return false, txid, err
			}

			pubkey, err := schnorr.ParsePubKey(tapScriptSig.XOnlyPubKey)
			if err != nil {
				return false, txid, err
			}

			preimage, err := txscript.CalcTapscriptSignaturehash(
				txSigHashes,
				tapScriptSig.SigHash,
				ptx.UnsignedTx,
				index,
				prevoutFetcher,
				txscript.NewBaseTapLeaf(tapLeaf.Script),
			)
			if err != nil {
				return false, txid, err
			}

			if !sig.Verify(preimage, pubkey) {
				return false, txid, fmt.Errorf(
					"invalid signature for input %d, sig: %x, pubkey: %x, sighashtype: %d",
					index,
					sig.Serialize(),
					pubkey.SerializeCompressed(),
					tapScriptSig.SigHash,
				)
			}

			keys[hex.EncodeToString(schnorr.SerializePubKey(pubkey))] = true
		}

		missingSigs := 0
		for key := range keys {
			if !keys[key] {
				missingSigs++
			}
		}

		if missingSigs > 0 {
			return false, txid, fmt.Errorf("missing %d signatures", missingSigs)
		}
	}

	return true, txid, nil
}

func (b *txBuilder) FinalizeAndExtract(tx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	for i, in := range ptx.Inputs {
		isTaproot := txscript.IsPayToTaproot(in.WitnessUtxo.PkScript)
		if isTaproot && len(in.TaprootLeafScript) > 0 {
			closure, err := script.DecodeClosure(in.TaprootLeafScript[0].Script)
			if err != nil {
				return "", err
			}

			conditionWitness, err := txutils.GetConditionWitness(in)
			if err != nil {
				return "", err
			}

			args := make(map[string][]byte)
			if len(conditionWitness) > 0 {
				var conditionWitnessBytes bytes.Buffer
				if err := psbt.WriteTxWitness(
					&conditionWitnessBytes, conditionWitness,
				); err != nil {
					return "", err
				}
				args[string(txutils.CONDITION_WITNESS_KEY_PREFIX)] = conditionWitnessBytes.Bytes()
			}

			for _, sig := range in.TaprootScriptSpendSig {
				args[hex.EncodeToString(sig.XOnlyPubKey)] = script.EncodeTaprootSignature(
					sig.Signature,
					sig.SigHash,
				)
			}

			witness, err := closure.Witness(in.TaprootLeafScript[0].ControlBlock, args)
			if err != nil {
				return "", err
			}

			var witnessBuf bytes.Buffer
			if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
				return "", err
			}

			ptx.Inputs[i].FinalScriptWitness = witnessBuf.Bytes()
			continue

		}

		if err := psbt.Finalize(ptx, i); err != nil {
			return "", fmt.Errorf("failed to finalize input %d: %w", i, err)
		}
	}

	signed, err := psbt.Extract(ptx)
	if err != nil {
		return "", err
	}

	var serialized bytes.Buffer

	if err := signed.Serialize(&serialized); err != nil {
		return "", err
	}

	return hex.EncodeToString(serialized.Bytes()), nil
}

func (b *txBuilder) BuildSweepTx(
	inputs []ports.SweepableBatchOutput,
) (txid, signedSweepTx string, err error) {
	sweepPsbt, err := sweepTransaction(
		b.wallet,
		inputs,
	)
	if err != nil {
		return "", "", err
	}

	sweepPsbtBase64, err := sweepPsbt.B64Encode()
	if err != nil {
		return "", "", err
	}

	ctx := context.Background()
	signedSweepPsbtB64, err := b.wallet.SignTransactionTapscript(ctx, sweepPsbtBase64, nil)
	if err != nil {
		return "", "", err
	}

	signedPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedSweepPsbtB64), true)
	if err != nil {
		return "", "", err
	}

	for i := range inputs {
		if err := psbt.Finalize(signedPsbt, i); err != nil {
			return "", "", err
		}
	}

	tx, err := psbt.Extract(signedPsbt)
	if err != nil {
		return "", "", err
	}

	buf := new(bytes.Buffer)

	if err := tx.Serialize(buf); err != nil {
		return "", "", err
	}

	return tx.TxHash().String(), hex.EncodeToString(buf.Bytes()), nil
}

func (b *txBuilder) VerifyForfeitTxs(
	vtxos []domain.Vtxo, connectors tree.FlatTxTree, forfeitTxs []string,
) (map[domain.Outpoint]ports.ValidForfeitTx, error) {
	connectorsLeaves := tree.FlatTxTree(connectors).Leaves()
	if len(connectorsLeaves) == 0 {
		return nil, fmt.Errorf("invalid connectors tree")
	}

	indexedVtxos := map[domain.Outpoint]domain.Vtxo{}
	for _, vtxo := range vtxos {
		indexedVtxos[vtxo.Outpoint] = vtxo
	}

	forfeitScript, err := b.getForfeitScript()
	if err != nil {
		return nil, err
	}

	blocktimestamp, err := b.wallet.GetCurrentBlockTime(context.Background())
	if err != nil {
		return nil, err
	}

	dustAmount, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	validForfeitTxs := make(map[domain.Outpoint]ports.ValidForfeitTx)

	for _, forfeitTx := range forfeitTxs {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(forfeitTx), true)
		if err != nil {
			return nil, err
		}

		if len(tx.Inputs) != 2 {
			continue
		}

		var vtxoInput, connectorInput *wire.TxIn
		var vtxoTapscript *psbt.TaprootTapLeafScript
		var connectorOutput *wire.TxOut
		var vtxoFirst bool

		// search for the connector output and the vtxo input in the tx
		for i, input := range tx.UnsignedTx.TxIn {
			for _, connector := range connectorsLeaves {
				if connector.Txid == input.PreviousOutPoint.Hash.String() {
					connectorTx, err := psbt.NewFromRawBytes(strings.NewReader(connector.Tx), true)
					if err != nil {
						return nil, err
					}

					if len(connectorTx.UnsignedTx.TxOut) <= int(input.PreviousOutPoint.Index) {
						return nil, fmt.Errorf(
							"connector vout %d out of range [0, %d]",
							input.PreviousOutPoint.Index, len(connectorTx.UnsignedTx.TxOut)-1,
						)
					}

					connectorOutput = connectorTx.UnsignedTx.TxOut[input.PreviousOutPoint.Index]

					// the vtxo input is the other input in the tx
					vtxoInputIndex := 0
					if i == 0 {
						vtxoInputIndex = 1
					}
					vtxoFirst = vtxoInputIndex == 0
					vtxoInput = tx.UnsignedTx.TxIn[vtxoInputIndex]
					connectorInput = tx.UnsignedTx.TxIn[i]

					if len(tx.Inputs[vtxoInputIndex].TaprootLeafScript) <= 0 {
						return nil, fmt.Errorf(
							"missing taproot leaf script for vtxo input, invalid forfeit tx",
						)
					}

					vtxoTapscript = tx.Inputs[vtxoInputIndex].TaprootLeafScript[0]
					break
				}
			}

			if connectorOutput != nil {
				break
			}
		}

		if connectorOutput == nil {
			return nil, fmt.Errorf("missing connector in forfeit tx %s", forfeitTx)
		}

		vtxoKey := domain.Outpoint{
			Txid: vtxoInput.PreviousOutPoint.Hash.String(),
			VOut: vtxoInput.PreviousOutPoint.Index,
		}

		// skip if we already have a valid forfeit for this vtxo
		if _, ok := validForfeitTxs[vtxoKey]; ok {
			continue
		}

		vtxo, ok := indexedVtxos[vtxoKey]
		if !ok {
			return nil, fmt.Errorf("missing vtxo %s", vtxoKey)
		}

		outputAmount := uint64(0)

		for _, output := range tx.UnsignedTx.TxOut {
			outputAmount += uint64(output.Value)
		}

		inputAmount := vtxo.Amount + uint64(connectorOutput.Value)

		// verify the forfeit closure script
		closure, err := script.DecodeClosure(vtxoTapscript.Script)
		if err != nil {
			return nil, err
		}

		locktime := arklib.AbsoluteLocktime(0)

		switch c := closure.(type) {
		case *script.CLTVMultisigClosure:
			locktime = c.Locktime
		case *script.MultisigClosure, *script.ConditionMultisigClosure:
		default:
			return nil, fmt.Errorf("invalid forfeit closure script")
		}

		if locktime != 0 {
			if !locktime.IsSeconds() {
				if locktime > arklib.AbsoluteLocktime(blocktimestamp.Height) {
					return nil, fmt.Errorf(
						"forfeit closure is CLTV locked, %d > %d (block height)",
						locktime, blocktimestamp.Height,
					)
				}
			} else {
				if locktime > arklib.AbsoluteLocktime(blocktimestamp.Time) {
					return nil, fmt.Errorf(
						"forfeit closure is CLTV locked, %d > %d (block time)",
						locktime, blocktimestamp.Time,
					)
				}
			}
		}

		if inputAmount < dustAmount {
			return nil, fmt.Errorf(
				"forfeit tx output amount is dust, %d < %d", inputAmount, dustAmount,
			)
		}

		vtxoTapKey, err := vtxo.TapKey()
		if err != nil {
			return nil, err
		}

		vtxoScript, err := script.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		vtxoPrevout := &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoScript,
		}

		var inputs []*wire.OutPoint
		var prevouts []*wire.TxOut
		var sequences []uint32

		vtxoSequence := wire.MaxTxInSequenceNum
		if locktime != 0 {
			vtxoSequence = wire.MaxTxInSequenceNum - 1
		}

		if vtxoFirst {
			inputs = []*wire.OutPoint{
				&vtxoInput.PreviousOutPoint, &connectorInput.PreviousOutPoint,
			}
			sequences = []uint32{vtxoSequence, wire.MaxTxInSequenceNum}
			prevouts = []*wire.TxOut{vtxoPrevout, connectorOutput}
		} else {
			inputs = []*wire.OutPoint{
				&connectorInput.PreviousOutPoint, &vtxoInput.PreviousOutPoint,
			}
			sequences = []uint32{wire.MaxTxInSequenceNum, vtxoSequence}
			prevouts = []*wire.TxOut{connectorOutput, vtxoPrevout}
		}

		rebuilt, err := tree.BuildForfeitTx(
			inputs,
			sequences,
			prevouts,
			forfeitScript,
			uint32(locktime),
		)
		if err != nil {
			return nil, err
		}

		if rebuilt.UnsignedTx.TxID() != tx.UnsignedTx.TxID() {
			if log.IsLevelEnabled(log.TraceLevel) {
				rebuiltB64, _ := rebuilt.B64Encode()
				txB64, _ := tx.B64Encode()
				log.WithFields(log.Fields{
					"expectedTxid": rebuilt.UnsignedTx.TxID(),
					"expectedB64":  rebuiltB64,
					"gotTxid":      tx.UnsignedTx.TxID(),
					"gotB64":       txB64,
				}).Tracef("invalid forfeit tx")
			}

			return nil, fmt.Errorf(
				"invalid forfeit tx: expected txid %s, got %s",
				rebuilt.UnsignedTx.TxID(),
				tx.UnsignedTx.TxID(),
			)
		}

		validForfeitTxs[vtxoKey] = ports.ValidForfeitTx{
			Tx: forfeitTx,
			Connector: domain.Outpoint{
				Txid: connectorInput.PreviousOutPoint.Hash.String(),
				VOut: connectorInput.PreviousOutPoint.Index,
			},
		}
	}

	return validForfeitTxs, nil
}

func (b *txBuilder) BuildCommitmentTx(
	signerPubkey *btcec.PublicKey, intents domain.Intents,
	boardingInputs []ports.BoardingInput, connectorAddresses []string,
	cosignersPublicKeys [][]string,
) (string, *tree.TxTree, string, *tree.TxTree, error) {
	var batchOutputScript []byte
	var batchOutputAmount int64

	receivers, err := getOutputVtxosLeaves(intents, cosignersPublicKeys)
	if err != nil {
		return "", nil, "", nil, err
	}

	sweepScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{signerPubkey},
		},
		Locktime: b.vtxoTreeExpiry,
	}).Script()
	if err != nil {
		return "", nil, "", nil, err
	}

	sweepTapscriptRoot := txscript.NewBaseTapLeaf(sweepScript).TapHash()

	if !intents.HaveOnlyOnchainOutput() {
		batchOutputScript, batchOutputAmount, err = tree.BuildBatchOutput(
			receivers, sweepTapscriptRoot[:],
		)
		if err != nil {
			return "", nil, "", nil, err
		}
	}

	nbOfConnectors := intents.CountSpentVtxos()

	dustAmount, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return "", nil, "", nil, err
	}

	var nextConnectorAddress string
	var connectorsTreePkScript []byte
	var connectorsTreeAmount int64
	connectorsTreeLeaves := make([]tree.Leaf, 0)

	if nbOfConnectors > 0 {
		nextConnectorAddress, err = b.wallet.DeriveConnectorAddress(context.Background())
		if err != nil {
			return "", nil, "", nil, err
		}

		connectorAddress, err := btcutil.DecodeAddress(nextConnectorAddress, b.onchainNetwork())
		if err != nil {
			return "", nil, "", nil, err
		}

		connectorPkScript, err := txscript.PayToAddrScript(connectorAddress)
		if err != nil {
			return "", nil, "", nil, err
		}

		// check if the connector script is a taproot script
		// we need taproot to properly create the connectors tree
		connectorScriptClass := txscript.GetScriptClass(connectorPkScript)
		if connectorScriptClass != txscript.WitnessV1TaprootTy {
			return "", nil, "", nil, fmt.Errorf(
				"invalid connector script class, expected taproot (%s), got %s",
				txscript.WitnessV1TaprootTy, connectorScriptClass,
			)
		}

		taprootKey, err := schnorr.ParsePubKey(connectorPkScript[2:])
		if err != nil {
			return "", nil, "", nil, err
		}

		cosigners := []string{hex.EncodeToString(taprootKey.SerializeCompressed())}

		for i := 0; i < nbOfConnectors; i++ {
			connectorsTreeLeaves = append(connectorsTreeLeaves, tree.Leaf{
				Amount:              uint64(dustAmount),
				Script:              hex.EncodeToString(connectorPkScript),
				CosignersPublicKeys: cosigners,
			})
		}

		connectorsTreePkScript, connectorsTreeAmount, err = tree.BuildConnectorOutput(
			connectorsTreeLeaves,
		)
		if err != nil {
			return "", nil, "", nil, err
		}
	}

	ptx, err := b.createCommitmentTx(
		batchOutputAmount, batchOutputScript, connectorsTreeAmount, connectorsTreePkScript,
		intents, boardingInputs, connectorAddresses,
	)
	if err != nil {
		return "", nil, "", nil, err
	}

	commitmentTx, err := ptx.B64Encode()
	if err != nil {
		return "", nil, "", nil, err
	}

	var vtxoTree *tree.TxTree

	if !intents.HaveOnlyOnchainOutput() {
		initialOutpoint := &wire.OutPoint{
			Hash:  ptx.UnsignedTx.TxHash(),
			Index: 0,
		}

		vtxoTree, err = tree.BuildVtxoTree(
			initialOutpoint, receivers, sweepTapscriptRoot[:], b.vtxoTreeExpiry,
		)
		if err != nil {
			return "", nil, "", nil, err
		}
	}

	if nbOfConnectors <= 0 {
		return commitmentTx, vtxoTree, nextConnectorAddress, nil, nil
	}

	rootConnectorsOutpoint := &wire.OutPoint{
		Hash:  ptx.UnsignedTx.TxHash(),
		Index: 1,
	}

	connectors, err := tree.BuildConnectorTree(
		rootConnectorsOutpoint,
		connectorsTreeLeaves,
	)
	if err != nil {
		return "", nil, "", nil, err
	}

	return commitmentTx, vtxoTree, nextConnectorAddress, connectors, nil
}

func (b *txBuilder) GetSweepableBatchOutputs(
	vtxoTree *tree.TxTree,
) (vtxoTreeExpiry *arklib.RelativeLocktime, sweepInput ports.SweepableBatchOutput, err error) {
	if len(vtxoTree.Root.UnsignedTx.TxIn) != 1 {
		return nil, nil, fmt.Errorf(
			"invalid node psbt, expect 1 input, got %d", len(vtxoTree.Root.UnsignedTx.TxIn),
		)
	}

	input := vtxoTree.Root.UnsignedTx.TxIn[0]
	txid := input.PreviousOutPoint.Hash
	index := input.PreviousOutPoint.Index

	sweepLeaf, internalKey, vtxoTreeExpiry, err := b.extractSweepLeaf(vtxoTree.Root.Inputs[0])
	if err != nil {
		return nil, nil, err
	}

	txhex, err := b.wallet.GetTransaction(context.Background(), txid.String())
	if err != nil {
		return nil, nil, err
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
		return nil, nil, err
	}

	sweepInput = &sweepBitcoinInput{
		inputArgs: wire.OutPoint{
			Hash:  txid,
			Index: index,
		},
		internalPubkey: internalKey,
		sweepLeaf:      sweepLeaf,
		amount:         tx.TxOut[index].Value,
	}

	return vtxoTreeExpiry, sweepInput, nil
}

func (b *txBuilder) createCommitmentTx(
	batchOutputAmount int64, batchOutputScript []byte,
	connectorOutputAmount int64, connectorOutputScript []byte,
	intents []domain.Intent, boardingInputs []ports.BoardingInput, connectorAddresses []string,
) (*psbt.Packet, error) {
	dustLimit, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	targetAmount := uint64(0)

	outputs := make([]*wire.TxOut, 0)

	if batchOutputScript != nil && batchOutputAmount > 0 {
		targetAmount += uint64(batchOutputAmount)

		outputs = append(outputs, &wire.TxOut{
			Value:    batchOutputAmount,
			PkScript: batchOutputScript,
		})
	}

	if connectorOutputScript != nil && connectorOutputAmount > 0 {
		targetAmount += uint64(connectorOutputAmount)

		outputs = append(outputs, &wire.TxOut{
			Value:    connectorOutputAmount,
			PkScript: connectorOutputScript,
		})
	}

	onchainOutputs, err := getOnchainOutputs(intents, b.onchainNetwork())
	if err != nil {
		return nil, err
	}

	for _, output := range onchainOutputs {
		targetAmount += uint64(output.Value)
	}

	outputs = append(outputs, onchainOutputs...)

	for _, input := range boardingInputs {
		targetAmount -= input.Amount
	}

	ctx := context.Background()
	utxos, change, err := b.selectUtxos(ctx, connectorAddresses, targetAmount)
	if err != nil {
		return nil, err
	}

	var cacheChangeScript []byte
	// avoid derivation of several change addresses
	getChange := func() ([]byte, error) {
		if len(cacheChangeScript) > 0 {
			return cacheChangeScript, nil
		}

		changeAddresses, err := b.wallet.DeriveAddresses(ctx, 1)
		if err != nil {
			return nil, err
		}

		changeAddress, err := btcutil.DecodeAddress(changeAddresses[0], b.onchainNetwork())
		if err != nil {
			return nil, err
		}

		return txscript.PayToAddrScript(changeAddress)
	}

	exceedingValue := uint64(0)
	if change > 0 {
		if change <= dustLimit {
			exceedingValue = change
			change = 0
		} else {
			changeScript, err := getChange()
			if err != nil {
				return nil, err
			}

			outputs = append(outputs, &wire.TxOut{
				Value:    int64(change),
				PkScript: changeScript,
			})
		}
	}

	ins := make([]*wire.OutPoint, 0)
	nSequences := make([]uint32, 0)
	witnessUtxos := make(map[int]*wire.TxOut)
	tapLeaves := make(map[int]*psbt.TaprootTapLeafScript)
	nextIndex := 0

	for _, utxo := range utxos {
		txhash, err := chainhash.NewHashFromStr(utxo.GetTxid())
		if err != nil {
			return nil, err
		}

		ins = append(ins, &wire.OutPoint{
			Hash:  *txhash,
			Index: utxo.GetIndex(),
		})
		nSequences = append(nSequences, wire.MaxTxInSequenceNum)

		script, err := hex.DecodeString(utxo.GetScript())
		if err != nil {
			return nil, err
		}

		witnessUtxos[nextIndex] = &wire.TxOut{
			Value:    int64(utxo.GetValue()),
			PkScript: script,
		}
		nextIndex++
	}

	for _, boardingInput := range boardingInputs {
		txHash, err := chainhash.NewHashFromStr(boardingInput.Txid)
		if err != nil {
			return nil, err
		}

		ins = append(ins, &wire.OutPoint{
			Hash:  *txHash,
			Index: boardingInput.VOut,
		})
		nSequences = append(nSequences, wire.MaxTxInSequenceNum)

		boardingVtxoScript, err := script.ParseVtxoScript(boardingInput.Tapscripts)
		if err != nil {
			return nil, err
		}

		boardingTapKey, boardingTapTree, err := boardingVtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		boardingOutputScript, err := script.P2TRScript(boardingTapKey)
		if err != nil {
			return nil, err
		}

		witnessUtxos[nextIndex] = &wire.TxOut{
			Value:    int64(boardingInput.Amount),
			PkScript: boardingOutputScript,
		}

		biggestProof, err := arklib.BiggestLeafMerkleProof(boardingTapTree)
		if err != nil {
			return nil, err
		}

		tapLeaves[nextIndex] = &psbt.TaprootTapLeafScript{
			Script:       biggestProof.Script,
			ControlBlock: biggestProof.ControlBlock,
		}

		nextIndex++
	}

	ptx, err := psbt.New(ins, outputs, 2, 0, nSequences)
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return nil, err
	}

	for inIndex, utxo := range witnessUtxos {
		if err := updater.AddInWitnessUtxo(utxo, inIndex); err != nil {
			return nil, err
		}
	}

	for inIndex, tapLeaf := range tapLeaves {
		updater.Upsbt.Inputs[inIndex].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
	}

	b64, err := ptx.B64Encode()
	if err != nil {
		return nil, err
	}

	feeAmount, err := b.wallet.EstimateFees(ctx, b64)
	if err != nil {
		return nil, err
	}

	for feeAmount > exceedingValue {
		feesToPay := feeAmount - exceedingValue

		// change is able to cover the remaining fees
		if change > feesToPay {
			newChange := change - (feeAmount - exceedingValue)
			// new change amount is less than dust limit, let's remove it
			if newChange <= dustLimit {
				ptx.UnsignedTx.TxOut = ptx.UnsignedTx.TxOut[:len(ptx.UnsignedTx.TxOut)-1]
				ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
			} else {
				ptx.UnsignedTx.TxOut[len(ptx.Outputs)-1].Value = int64(newChange)
			}

			break
		}

		// change is not enough to cover the remaining fees, let's re-select utxos
		newUtxos, newChange, err := b.wallet.SelectUtxos(ctx, "", feeAmount-exceedingValue, false)
		if err != nil {
			return nil, err
		}

		// add new inputs
		for _, utxo := range newUtxos {
			txhash, err := chainhash.NewHashFromStr(utxo.GetTxid())
			if err != nil {
				return nil, err
			}

			outpoint := &wire.OutPoint{
				Hash:  *txhash,
				Index: utxo.GetIndex(),
			}

			ptx.UnsignedTx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
			ptx.Inputs = append(ptx.Inputs, psbt.PInput{})

			scriptBytes, err := hex.DecodeString(utxo.GetScript())
			if err != nil {
				return nil, err
			}

			if err := updater.AddInWitnessUtxo(
				&wire.TxOut{
					Value:    int64(utxo.GetValue()),
					PkScript: scriptBytes,
				},
				len(ptx.UnsignedTx.TxIn)-1,
			); err != nil {
				return nil, err
			}
		}

		// add new change output if necessary
		if newChange > 0 {
			if newChange <= dustLimit {
				newChange = 0
				exceedingValue += newChange
			} else {
				changeScript, err := getChange()
				if err != nil {
					return nil, err
				}

				ptx.UnsignedTx.AddTxOut(&wire.TxOut{
					Value:    int64(newChange),
					PkScript: changeScript,
				})
				ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
			}
		}

		b64, err = ptx.B64Encode()
		if err != nil {
			return nil, err
		}

		newFeeAmount, err := b.wallet.EstimateFees(ctx, b64)
		if err != nil {
			return nil, err
		}

		feeAmount = newFeeAmount
		change = newChange
	}

	// remove input taproot leaf script
	// used only to compute an accurate fee estimation
	for i := range ptx.Inputs {
		ptx.Inputs[i].TaprootLeafScript = nil
	}

	return ptx, nil
}

func (b *txBuilder) CountSignedTaprootInputs(tx string) (int, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return -1, err
	}

	signedInputsCount := 0
	for _, in := range ptx.Inputs {
		if len(in.TaprootScriptSpendSig) == 0 || len(in.TaprootLeafScript) == 0 {
			continue
		}

		signedInputsCount++
	}
	return signedInputsCount, nil
}

func (b *txBuilder) VerifyAndCombinePartialTx(dest string, src string) (string, error) {
	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(dest), true)
	if err != nil {
		return "", err
	}

	sourceTx, err := psbt.NewFromRawBytes(strings.NewReader(src), true)
	if err != nil {
		return "", err
	}

	if sourceTx.UnsignedTx.TxID() != commitmentTx.UnsignedTx.TxID() {
		return "", fmt.Errorf("txids do not match")
	}

	for i, sourceInput := range sourceTx.Inputs {
		isMultisigTaproot := len(sourceInput.TaprootLeafScript) > 0
		if isMultisigTaproot {
			// check if the source tx signs the leaf
			if len(sourceInput.TaprootScriptSpendSig) == 0 {
				continue
			}

			partialSig := sourceInput.TaprootScriptSpendSig[0]
			preimage, err := b.getTaprootPreimage(
				sourceTx, i, sourceInput.TaprootLeafScript[0].Script,
			)
			if err != nil {
				return "", err
			}

			sig, err := schnorr.ParseSignature(partialSig.Signature)
			if err != nil {
				return "", err
			}

			pubkey, err := schnorr.ParsePubKey(partialSig.XOnlyPubKey)
			if err != nil {
				return "", err
			}

			if !sig.Verify(preimage, pubkey) {
				return "", fmt.Errorf(
					"invalid signature for input %s:%d",
					sourceTx.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
					sourceTx.UnsignedTx.TxIn[i].PreviousOutPoint.Index,
				)
			}

			commitmentTx.Inputs[i].TaprootScriptSpendSig = sourceInput.TaprootScriptSpendSig
			commitmentTx.Inputs[i].TaprootLeafScript = sourceInput.TaprootLeafScript
		}
	}

	return commitmentTx.B64Encode()
}

func (b *txBuilder) selectUtxos(
	ctx context.Context, connectorAddresses []string, amount uint64,
) ([]ports.TxInput, uint64, error) {
	selectedConnectorsUtxos := make([]ports.TxInput, 0)
	selectedConnectorsAmount := uint64(0)

	for _, addr := range connectorAddresses {
		if selectedConnectorsAmount >= amount {
			break
		}
		connectors, err := b.wallet.ListConnectorUtxos(ctx, addr)
		if err != nil {
			return nil, 0, err
		}

		for _, connector := range connectors {
			if selectedConnectorsAmount >= amount {
				break
			}

			selectedConnectorsUtxos = append(selectedConnectorsUtxos, connector)
			selectedConnectorsAmount += connector.GetValue()
		}
	}

	if len(selectedConnectorsUtxos) > 0 {
		if err := b.wallet.LockConnectorUtxos(
			ctx, castToOutpoints(selectedConnectorsUtxos),
		); err != nil {
			return nil, 0, err
		}
	}

	if selectedConnectorsAmount >= amount {
		return selectedConnectorsUtxos, selectedConnectorsAmount - amount, nil
	}

	utxos, change, err := b.wallet.SelectUtxos(ctx, "", amount-selectedConnectorsAmount, false)
	if err != nil {
		return nil, 0, err
	}

	return append(selectedConnectorsUtxos, utxos...), change, nil
}

func (b *txBuilder) getPrevOutputFetcher(tx *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for i, input := range tx.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("missing witness utxo on input #%d", i)
		}

		outpoint := tx.UnsignedTx.TxIn[i].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	return txscript.NewMultiPrevOutFetcher(prevouts), nil
}

func (b *txBuilder) getTaprootPreimage(
	tx *psbt.Packet, inputIndex int, leafScript []byte,
) ([]byte, error) {
	prevoutFetcher, err := b.getPrevOutputFetcher(tx)
	if err != nil {
		return nil, err
	}

	return txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(tx.UnsignedTx, prevoutFetcher),
		txscript.SigHashDefault,
		tx.UnsignedTx,
		inputIndex,
		prevoutFetcher,
		txscript.NewBaseTapLeaf(leafScript),
	)
}

func (b *txBuilder) onchainNetwork() *chaincfg.Params {
	switch b.network.Name {
	case arklib.Bitcoin.Name:
		return &chaincfg.MainNetParams
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//return arklib.TestNet4Params
	case arklib.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case arklib.BitcoinSigNet.Name:
		return &chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return &arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return nil
	}
}

func castToOutpoints(inputs []ports.TxInput) []domain.Outpoint {
	outpoints := make([]domain.Outpoint, 0, len(inputs))
	for _, input := range inputs {
		outpoints = append(outpoints, domain.Outpoint{
			Txid: input.GetTxid(),
			VOut: input.GetIndex(),
		})
	}
	return outpoints
}

func (b *txBuilder) extractSweepLeaf(input psbt.PInput) (
	sweepLeaf *psbt.TaprootTapLeafScript, internalKey *btcec.PublicKey,
	vtxoTreeExpiry *arklib.RelativeLocktime, err error,
) {
	// this if case is here to handle previous version of the tree
	if len(input.TaprootLeafScript) > 0 {
		for _, leaf := range input.TaprootLeafScript {
			closure := &script.CSVMultisigClosure{}
			valid, err := closure.Decode(leaf.Script)
			if err != nil {
				return nil, nil, nil, err
			}

			if valid && (vtxoTreeExpiry == nil || closure.Locktime.LessThan(*vtxoTreeExpiry)) {
				sweepLeaf = leaf
				vtxoTreeExpiry = &closure.Locktime
			}
		}

		internalKey, err = schnorr.ParsePubKey(input.TaprootInternalKey)
		if err != nil {
			return nil, nil, nil, err
		}

		if sweepLeaf == nil {
			return nil, nil, nil, fmt.Errorf("sweep leaf not found")
		}
		return sweepLeaf, internalKey, vtxoTreeExpiry, nil
	}

	signerPubKey, err := b.wallet.GetPubkey(context.Background())
	if err != nil {
		return nil, nil, nil, err
	}

	cosignerPubKeys, err := txutils.GetCosignerKeys(input)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(cosignerPubKeys) == 0 {
		return nil, nil, nil, fmt.Errorf("no cosigner pubkeys found")
	}

	vtxoTreeExpiry, err = txutils.GetVtxoTreeExpiry(input)
	if err != nil {
		return nil, nil, nil, err
	}

	sweepClosure := &script.CSVMultisigClosure{
		Locktime: *vtxoTreeExpiry,
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{signerPubKey},
		},
	}

	sweepScript, err := sweepClosure.Script()
	if err != nil {
		return nil, nil, nil, err
	}

	sweepTapTree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript))
	sweepRoot := sweepTapTree.RootNode.TapHash()

	aggregatedKey, err := tree.AggregateKeys(cosignerPubKeys, sweepRoot[:])
	if err != nil {
		return nil, nil, nil, err
	}
	internalKey = aggregatedKey.PreTweakedKey

	sweepLeafMerkleProof := sweepTapTree.LeafMerkleProofs[0]
	sweepLeafControlBlock := sweepLeafMerkleProof.ToControlBlock(internalKey)
	sweepLeafControlBlockBytes, err := sweepLeafControlBlock.ToBytes()
	if err != nil {
		return nil, nil, nil, err
	}

	sweepLeaf = &psbt.TaprootTapLeafScript{
		Script:       sweepScript,
		ControlBlock: sweepLeafControlBlockBytes,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	return sweepLeaf, internalKey, vtxoTreeExpiry, nil
}

func (b *txBuilder) getForfeitScript() ([]byte, error) {
	forfeitAddress, err := b.wallet.GetForfeitAddress(context.Background())
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.DecodeAddress(forfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(addr)
}

type sweepBitcoinInput struct {
	inputArgs      wire.OutPoint
	sweepLeaf      *psbt.TaprootTapLeafScript
	internalPubkey *btcec.PublicKey
	amount         int64
}

func (s *sweepBitcoinInput) GetAmount() uint64 {
	return uint64(s.amount)
}

func (s *sweepBitcoinInput) GetControlBlock() []byte {
	return s.sweepLeaf.ControlBlock
}

func (s *sweepBitcoinInput) GetHash() chainhash.Hash {
	return s.inputArgs.Hash
}

func (s *sweepBitcoinInput) GetIndex() uint32 {
	return s.inputArgs.Index
}

func (s *sweepBitcoinInput) GetInternalKey() *btcec.PublicKey {
	return s.internalPubkey
}

func (s *sweepBitcoinInput) GetLeafScript() []byte {
	return s.sweepLeaf.Script
}
