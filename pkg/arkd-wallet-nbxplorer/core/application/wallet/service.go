package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/coinset"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

var (
	ErrWalletLocked = errors.New("wallet is locked")
	ANCHOR_PKSCRIPT = []byte{
		0x51, 0x02, 0x4e, 0x73,
	}
)

// https://github.com/bitcoin/bitcoin/blob/439e58c4d8194ca37f70346727d31f52e69592ec/src/policy/policy.cpp#L23C8-L23C11
// biggest input size to compute the maximum dust amount
const biggestInputSize = 148 + 182 // = 330 vbytes

type WalletOptions struct {
	Repository ports.SeedRepository
	Crypto     ports.Crypto
	Nbxplorer  ports.Nbxplorer
	Network    string
}

type wallet struct {
	WalletOptions

	locker  outpointLocker
	keyMgr  *keyManager
	isReady chan struct{}

	cacheArkSignerPublicKey *secp256k1.PublicKey
}

// New creates a new WalletService service
func New(opts WalletOptions) application.WalletService {
	return &wallet{
		opts,
		newInmemoryOutpointLocker(time.Minute),
		nil,
		make(chan struct{}),
		nil,
	}
}

func (w *wallet) GetReadyUpdate(ctx context.Context) <-chan struct{} {
	return w.isReady
}

func (w *wallet) GenSeed(ctx context.Context) (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func (w *wallet) Create(ctx context.Context, mnemonic string, password string) error {
	if _, err := w.init(ctx, mnemonic, password); err != nil {
		return err
	}

	return nil
}

func (w *wallet) Restore(ctx context.Context, mnemonic string, password string) error {
	keyMgr, err := w.init(ctx, mnemonic, password)
	if err != nil {
		return err
	}

	mainAccountScanProgress := w.Nbxplorer.ScanUtxoSet(ctx, keyMgr.getMainAccountDerivationScheme(), 1000)
	connectorAccountScanProgress := w.Nbxplorer.ScanUtxoSet(ctx, keyMgr.getConnectorAccountDerivationScheme(), 1000)

	mainAccountScanDone := false
	connectorAccountScanDone := false
	for !mainAccountScanDone && !connectorAccountScanDone {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case progress := <-mainAccountScanProgress:
			if progress.Done {
				mainAccountScanDone = true
			}
		case progress := <-connectorAccountScanProgress:
			if progress.Done {
				connectorAccountScanDone = true
			}
		}
	}
	return nil
}

func (w *wallet) Unlock(ctx context.Context, password string) error {
	if w.keyMgr != nil {
		return nil
	}

	encryptedSeed, err := w.Repository.GetEncryptedSeed(ctx)
	if err != nil {
		return err
	}
	seed, err := w.Crypto.Decrypt(ctx, encryptedSeed, password)
	if err != nil {
		return err
	}

	w.keyMgr, err = newKeyManager(seed, w.chainParams())
	if err != nil {
		return err
	}

	w.cacheArkSignerPublicKey, err = w.keyMgr.getArkSignerPublicKey()
	if err != nil {
		return err
	}

	w.isReady <- struct{}{}
	logrus.Infof("wallet unlocked")

	return nil
}

func (w *wallet) Lock(ctx context.Context) error {
	if w.keyMgr == nil {
		return fmt.Errorf("wallet is already locked")
	}

	w.keyMgr = nil
	return nil
}

func (w *wallet) Status(ctx context.Context) application.WalletStatus {
	return application.WalletStatus{
		IsInitialized: w.Repository.IsInitialized(ctx),
		IsUnlocked:    w.keyMgr != nil,
		IsSynced:      true,
	}
}

func (w *wallet) BroadcastTransaction(ctx context.Context, txs ...string) (string, error) {
	return w.Nbxplorer.BroadcastTransaction(ctx, txs...)
}

func (w *wallet) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	if w.keyMgr == nil {
		return 0, 0, ErrWalletLocked
	}

	return w.getBalance(ctx, w.keyMgr.getConnectorAccountDerivationScheme())
}

func (w *wallet) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	if w.keyMgr == nil {
		return 0, 0, ErrWalletLocked
	}

	return w.getBalance(ctx, w.keyMgr.getMainAccountDerivationScheme())
}

func (w *wallet) GetNetwork(ctx context.Context) string {
	return w.Network
}

func (w *wallet) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	if w.keyMgr == nil {
		return nil, ErrWalletLocked
	}

	return w.deriveAddresses(ctx, w.keyMgr.getMainAccountDerivationScheme(), num)
}

func (w *wallet) DeriveConnectorAddress(ctx context.Context) (string, error) {
	if w.keyMgr == nil {
		return "", ErrWalletLocked
	}

	addresses, err := w.deriveAddresses(ctx, w.keyMgr.getConnectorAccountDerivationScheme(), 1)
	if err != nil {
		return "", err
	}

	return addresses[0], nil
}

func (w *wallet) GetPubkey(ctx context.Context) (*btcec.PublicKey, error) {
	if w.cacheArkSignerPublicKey == nil {
		return nil, ErrWalletLocked
	}

	return w.cacheArkSignerPublicKey, nil
}

func (w *wallet) EstimateFees(ctx context.Context, rawTx string) (uint64, error) {
	partial, err := psbt.NewFromRawBytes(
		strings.NewReader(rawTx),
		true,
	)
	if err != nil {
		return 0, err
	}

	weightEstimator := &input.TxWeightEstimator{}

	for _, in := range partial.Inputs {
		if in.WitnessUtxo == nil {
			return 0, fmt.Errorf("missing witness utxo for input")
		}

		script, err := txscript.ParsePkScript(in.WitnessUtxo.PkScript)
		if err != nil {
			return 0, err
		}

		switch script.Class() {
		case txscript.PubKeyHashTy:
			weightEstimator.AddP2PKHInput()
		case txscript.WitnessV0PubKeyHashTy:
			weightEstimator.AddP2WKHInput()
		case txscript.WitnessV1TaprootTy:
			if len(in.TaprootLeafScript) > 0 {
				leaf := in.TaprootLeafScript[0]
				ctrlBlock, err := txscript.ParseControlBlock(leaf.ControlBlock)
				if err != nil {
					return 0, err
				}

				weightEstimator.AddTapscriptInput(64*2, &waddrmgr.Tapscript{
					RevealedScript: leaf.Script,
					ControlBlock:   ctrlBlock,
				})
			} else {
				weightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault)
			}
		default:
			return 0, fmt.Errorf("unsupported script type: %v", script.Class())
		}
	}

	for _, output := range partial.UnsignedTx.TxOut {
		weightEstimator.AddOutput(output.PkScript)
	}

	feeRate, err := w.FeeRate(ctx)
	if err != nil {
		return 0, err
	}

	fee := feeRate.FeeForVSize(lntypes.VByte(weightEstimator.VSize()))
	return uint64(math.Ceil(fee.ToUnit(btcutil.AmountSatoshi))), nil
}

func (w *wallet) FeeRate(ctx context.Context) (chainfee.SatPerKVByte, error) {
	rate, err := w.Nbxplorer.EstimateFeeRate(ctx)
	if err != nil {
		if w.Network == "regtest" {
			// in regtest, somtimes the fee estimation fails because there is not enough transactions
			// fallback to minrelayfee
			return chainfee.AbsoluteFeePerKwFloor.FeePerKVByte(), nil
		}
		return 0, err
	}

	return rate, nil
}

func (w *wallet) GetForfeitAddress(ctx context.Context) (string, error) {
	forfeitPubKey, err := w.keyMgr.getForfeitPublicKey()
	if err != nil {
		return "", err
	}

	pubkeyHash := btcutil.Hash160(forfeitPubKey.SerializeCompressed())

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubkeyHash, w.chainParams())
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

func (w *wallet) LockConnectorUtxos(ctx context.Context, utxos []wire.OutPoint) error {
	if w.keyMgr == nil {
		return ErrWalletLocked
	}

	return w.locker.Lock(ctx, utxos...)
}

func (w *wallet) ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]application.Utxo, error) {
	if w.keyMgr == nil {
		return nil, ErrWalletLocked
	}

	connectorAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.getConnectorAccountDerivationScheme())
	if err != nil {
		return nil, err
	}

	lockedOutpoints, err := w.locker.Get(ctx)
	if err != nil {
		return nil, err
	}

	connectorUtxos := make([]application.Utxo, 0, len(connectorAccountUtxos))
	for _, utxo := range connectorAccountUtxos {
		// for connector utxos, we exclude unconfirmed ones because they're always spent via 1C1P package relay
		if utxo.Confirmations < 1 {
			continue
		}

		if utxo.Address != connectorAddress {
			continue
		}
		if _, isLocked := lockedOutpoints[utxo.OutPoint]; isLocked {
			continue
		}

		connectorUtxos = append(connectorUtxos, application.Utxo{
			Txid:   utxo.OutPoint.Hash.String(),
			Index:  utxo.OutPoint.Index,
			Script: utxo.Script,
			Value:  utxo.Value,
		})
	}

	return connectorUtxos, nil
}

func (w *wallet) GetCurrentBlockTime(ctx context.Context) (*application.BlockTimestamp, error) {
	status, err := w.Nbxplorer.GetBitcoinStatus(ctx)
	if err != nil {
		return nil, err
	}

	return &application.BlockTimestamp{
		Height: status.ChainTipHeight,
		Time:   status.ChainTipTime,
	}, nil
}

func (w *wallet) SelectUtxos(ctx context.Context, amount uint64, confirmedOnly bool) ([]application.Utxo, uint64, error) {
	if w.keyMgr == nil {
		return nil, 0, ErrWalletLocked
	}

	mainAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.getMainAccountDerivationScheme())
	if err != nil {
		return nil, 0, err
	}

	lockedOutpoints, err := w.locker.Get(ctx)
	if err != nil {
		return nil, 0, err
	}

	availableUtxos := make([]coinset.Coin, 0, len(mainAccountUtxos))
	for _, utxo := range mainAccountUtxos {
		if confirmedOnly && utxo.Confirmations < 1 {
			continue
		}
		if _, isLocked := lockedOutpoints[utxo.OutPoint]; isLocked {
			continue
		}

		availableUtxos = append(availableUtxos, selectable{utxo})
	}

	coins, err := coinSelector.CoinSelect(btcutil.Amount(amount), availableUtxos)
	if err != nil {
		return nil, 0, err
	}

	selected := coins.Coins()
	selectedUtxos := make([]application.Utxo, 0, len(selected))
	toLock := make([]wire.OutPoint, 0, len(selected))
	totalValue := uint64(0)

	for _, coin := range selected {
		value := uint64(coin.Value().ToUnit(btcutil.AmountSatoshi))
		selectedUtxos = append(selectedUtxos, application.Utxo{
			Txid:   coin.Hash().String(),
			Index:  coin.Index(),
			Script: hex.EncodeToString(coin.PkScript()),
			Value:  value,
		})
		toLock = append(toLock, wire.OutPoint{
			Hash:  *coin.Hash(),
			Index: coin.Index(),
		})
		totalValue += value
	}

	if err := w.locker.Lock(ctx, toLock...); err != nil {
		logrus.Error("failed to lock utxos", err)
		// ignore error
	}

	change := totalValue - amount

	return selectedUtxos, change, nil
}

func (w *wallet) GetTransaction(ctx context.Context, txid string) (string, error) {
	txDetails, err := w.Nbxplorer.GetTransaction(ctx, txid)
	if err != nil {
		return "", err
	}

	return txDetails.Hex, nil
}

func (w *wallet) GetDustAmount(ctx context.Context) uint64 {
	minRelayFee := chainfee.AbsoluteFeePerKwFloor.FeeForVByte(lntypes.VByte(biggestInputSize))
	return uint64(minRelayFee.ToUnit(btcutil.AmountSatoshi))
}

// TODO do we really need to wait for sync with nbxplorer ?
func (w *wallet) WaitForSync(ctx context.Context, txid string) error {
	bitcoinStatus, err := w.Nbxplorer.GetBitcoinStatus(ctx)
	if err != nil {
		return err
	}

	if bitcoinStatus.Synched {
		return nil
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			bitcoinStatus, err = w.Nbxplorer.GetBitcoinStatus(ctx)
			if err != nil {
				return err
			}

			if bitcoinStatus.Synched {
				return nil
			}
		}
	}
}

func (w *wallet) SignTransaction(ctx context.Context, partialTx string, extractRawTx bool, inputIndexes []int) (string, error) {
	ptx, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return "", err
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for inputIndex, input := range ptx.Inputs {
		previousOutPoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if input.WitnessUtxo == nil {
			txHex, err := w.GetTransaction(ctx, previousOutPoint.Hash.String())
			if err != nil {
				return "", err
			}

			var tx wire.MsgTx
			if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))); err != nil {
				return "", err
			}

			prevout := tx.TxOut[previousOutPoint.Index]
			prevouts[previousOutPoint] = prevout
			ptx.Inputs[inputIndex].WitnessUtxo = prevout
		} else {
			prevouts[previousOutPoint] = input.WitnessUtxo
		}

		if !txscript.IsPayToTaproot(prevouts[previousOutPoint].PkScript) {
			if ptx.Inputs[inputIndex].SighashType == txscript.SigHashDefault {
				ptx.Inputs[inputIndex].SighashType = txscript.SigHashAll
			}
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	for inputIndex, input := range ptx.Inputs {
		if bytes.Equal(input.WitnessUtxo.PkScript, ANCHOR_PKSCRIPT) {
			// skip anchor inputs
			continue
		}

		if len(inputIndexes) > 0 && !slices.Contains(inputIndexes, inputIndex) {
			continue
		}

		isTaproot := txscript.IsPayToTaproot(input.WitnessUtxo.PkScript)

		if isTaproot {
			// tapscript = ark signer case
			if len(input.TaprootLeafScript) > 0 {
				tapLeaf := txscript.NewBaseTapLeaf(input.TaprootLeafScript[0].Script)

				privateKey, err := w.keyMgr.getArkSignerPrivateKey()
				if err != nil {
					return "", err
				}

				signature, err := txscript.RawTxInTapscriptSignature(
					ptx.UnsignedTx, txSigHashes, inputIndex,
					input.WitnessUtxo.Value, input.WitnessUtxo.PkScript,
					tapLeaf, input.SighashType, privateKey,
				)
				if err != nil {
					return "", err
				}

				leafHash := tapLeaf.TapHash()

				ptx.Inputs[inputIndex].TaprootScriptSpendSig = append(ptx.Inputs[inputIndex].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
					Signature:   signature,
					XOnlyPubKey: schnorr.SerializePubKey(privateKey.PubKey()),
					LeafHash:    leafHash[:],
					SigHash:     input.SighashType,
				})
				continue
			}

			// if not tapscripts, key-path = connector
			if len(input.TaprootKeySpendSig) > 0 {
				continue // skip if already signed
			}

			privateKey, err := w.getScriptPubKeyPrivateKey(ctx, hex.EncodeToString(input.WitnessUtxo.PkScript))
			if err != nil {
				return "", err
			}

			if privateKey == nil {
				return "", fmt.Errorf("private key not found for input %d", inputIndex)
			}

			signature, err := txscript.RawTxInTaprootSignature(
				ptx.UnsignedTx, txSigHashes, inputIndex,
				input.WitnessUtxo.Value, input.WitnessUtxo.PkScript,
				input.TaprootMerkleRoot, input.SighashType,
				privateKey,
			)
			if err != nil {
				return "", err
			}

			ptx.Inputs[inputIndex].TaprootKeySpendSig = signature
		}

		// P2WPKH case (either connector or main account)
		privateKey, err := w.getScriptPubKeyPrivateKey(ctx, hex.EncodeToString(input.WitnessUtxo.PkScript))
		if err != nil {
			return "", err
		}

		if privateKey == nil {
			if len(inputIndexes) > 0 {
				return "", fmt.Errorf("private key not found for input %d", inputIndex)
			}
			continue
		}

		signature, err := txscript.RawTxInWitnessSignature(
			ptx.UnsignedTx, txSigHashes, inputIndex,
			input.WitnessUtxo.Value,
			input.WitnessUtxo.PkScript,
			input.SighashType,
			privateKey,
		)
		if err != nil {
			return "", err
		}

		ptx.Inputs[inputIndex].PartialSigs = append(ptx.Inputs[inputIndex].PartialSigs, &psbt.PartialSig{
			PubKey:    privateKey.PubKey().SerializeCompressed(),
			Signature: signature,
		})
	}

	if extractRawTx {
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
					if err := psbt.WriteTxWitness(&conditionWitnessBytes, conditionWitness); err != nil {
						return "", err
					}
					args[string(txutils.CONDITION_WITNESS_KEY_PREFIX)] = conditionWitnessBytes.Bytes()
				}

				for _, sig := range in.TaprootScriptSpendSig {
					args[hex.EncodeToString(sig.XOnlyPubKey)] = sig.Signature
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

		extracted, err := psbt.Extract(ptx)
		if err != nil {
			return "", err
		}

		var buf bytes.Buffer
		if err := extracted.Serialize(&buf); err != nil {
			return "", err
		}

		return hex.EncodeToString(buf.Bytes()), nil
	}

	return ptx.B64Encode()
}

func (w *wallet) Withdraw(ctx context.Context, destinationAddress string, amount uint64) (string, error) {
	if w.keyMgr == nil {
		return "", ErrWalletLocked
	}

	// validate the destination address
	destinationAddr, err := btcutil.DecodeAddress(destinationAddress, w.chainParams())
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}

	feeRate, err := w.FeeRate(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get fee rate: %w", err)
	}

	// estimate fees for a typical 2-input, 2-output transaction (amount + change)
	// will be refined after coin selection
	estimatedFee := w.estimateWithdrawFee(feeRate, 2, 2)

	selectedUtxos, _, err := w.SelectUtxos(ctx, amount+estimatedFee, true)
	if err != nil {
		return "", fmt.Errorf("failed to select UTXOs: %w", err)
	}

	ptx, err := psbt.New(nil, nil, 0, 0, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create PSBT: %w", err)
	}

	totalInputValue := uint64(0)
	for _, utxo := range selectedUtxos {
		scriptBytes, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return "", fmt.Errorf("failed to decode script: %w", err)
		}

		ptx.Inputs = append(ptx.Inputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value:    int64(utxo.Value),
				PkScript: scriptBytes,
			},
			SighashType: txscript.SigHashAll,
		})

		hash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return "", fmt.Errorf("failed to parse txid: %w", err)
		}

		ptx.UnsignedTx.TxIn = append(ptx.UnsignedTx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: utxo.Index,
			},
		})

		totalInputValue += utxo.Value
	}

	actualFee := w.estimateWithdrawFee(feeRate, len(selectedUtxos), 2) // 2 outputs: destination + change

	changeAmount := totalInputValue - amount - actualFee

	destPkScript, err := txscript.PayToAddrScript(destinationAddr)
	if err != nil {
		return "", fmt.Errorf("failed to create destination script: %w", err)
	}
	ptx.UnsignedTx.TxOut = append(ptx.UnsignedTx.TxOut, &wire.TxOut{
		Value:    int64(amount),
		PkScript: destPkScript,
	})
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})

	dustAmount := w.GetDustAmount(ctx)
	if changeAmount >= dustAmount {
		changeAddress, err := w.Nbxplorer.GetNewUnusedAddress(ctx, w.keyMgr.getMainAccountDerivationScheme(), true, 0)
		if err != nil {
			return "", fmt.Errorf("failed to generate change address: %w", err)
		}

		changeAddr, err := btcutil.DecodeAddress(changeAddress, w.chainParams())
		if err != nil {
			return "", fmt.Errorf("failed to decode change address: %w", err)
		}

		changePkScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return "", fmt.Errorf("failed to create change script: %w", err)
		}

		ptx.UnsignedTx.TxOut = append(ptx.UnsignedTx.TxOut, &wire.TxOut{
			Value:    int64(changeAmount),
			PkScript: changePkScript,
		})
		ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
	} else {
		actualFee += changeAmount
	}

	psbtB64, err := ptx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode PSBT: %w", err)
	}

	signedTx, err := w.SignTransaction(ctx, psbtB64, true, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	txid, err := w.BroadcastTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	return txid, nil
}

func (w *wallet) Close() {
	// nolint:errcheck
	w.Nbxplorer.Close()
	w.keyMgr = nil
	close(w.isReady)
}

func (w *wallet) init(ctx context.Context, mnemonic string, password string) (keyMgr *keyManager, err error) {
	if w.Repository.IsInitialized(ctx) {
		return nil, fmt.Errorf("wallet already initialized")
	}

	seedBytes, err := bip39.MnemonicToByteArray(mnemonic)
	if err != nil {
		return nil, err
	}
	encryptedSeed, err := w.Crypto.Encrypt(ctx, seedBytes, password)
	if err != nil {
		return nil, err
	}

	if err := w.Repository.SetEncryptedSeed(ctx, encryptedSeed); err != nil {
		return nil, err
	}

	keyMgr, err = newKeyManager(seedBytes, w.chainParams())
	if err != nil {
		return nil, err
	}

	mainAccountXPub := keyMgr.getMainAccountDerivationScheme()
	connectorAccountXPub := keyMgr.getConnectorAccountDerivationScheme()

	w.cacheArkSignerPublicKey, err = keyMgr.getArkSignerPublicKey()
	if err != nil {
		return nil, err
	}

	if err := w.Nbxplorer.Track(ctx, mainAccountXPub); err != nil {
		return nil, err
	}

	if err := w.Nbxplorer.Track(ctx, connectorAccountXPub); err != nil {
		return nil, err
	}

	return keyMgr, nil
}

func (w *wallet) deriveAddresses(ctx context.Context, derivationScheme string, num int) ([]string, error) {
	addresses := make([]string, 0, num)
	for i := 0; i < num; i++ {
		address, err := w.Nbxplorer.GetNewUnusedAddress(ctx, derivationScheme, false, i)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}

	return addresses, nil
}

func (w *wallet) chainParams() *chaincfg.Params {
	return application.NetworkToChainParams(w.Network)
}

func (w *wallet) estimateWithdrawFee(feeRate chainfee.SatPerKVByte, numInputs, numOutputs int) uint64 {
	weightEstimator := &input.TxWeightEstimator{}

	for i := 0; i < numInputs; i++ {
		weightEstimator.AddP2WKHInput()
	}

	for i := 0; i < numOutputs; i++ {
		dummyAddr, _ := btcutil.NewAddressWitnessPubKeyHash(make([]byte, 20), w.chainParams())
		dummyScript, _ := txscript.PayToAddrScript(dummyAddr)
		weightEstimator.AddOutput(dummyScript)
	}

	fee := feeRate.FeeForVSize(lntypes.VByte(weightEstimator.VSize()))
	return uint64(math.Ceil(fee.ToUnit(btcutil.AmountSatoshi)))
}

func (w *wallet) getScriptPubKeyPrivateKey(ctx context.Context, scriptPubKey string) (*secp256k1.PrivateKey, error) {
	if w.keyMgr == nil {
		return nil, ErrWalletLocked
	}

	xpubs := []string{
		w.keyMgr.getMainAccountDerivationScheme(),
		w.keyMgr.getConnectorAccountDerivationScheme(),
	}

	for _, xpub := range xpubs {
		scriptPubKeyDetails, err := w.Nbxplorer.GetScriptPubKeyDetails(ctx, xpub, scriptPubKey)
		if err != nil {
			continue
		}

		return w.keyMgr.getPrivateKey(xpub, scriptPubKeyDetails.KeyPath)
	}

	return nil, nil
}

func (w *wallet) getBalance(ctx context.Context, derivationScheme string) (uint64, uint64, error) {
	utxos, err := w.Nbxplorer.GetUtxos(ctx, derivationScheme)
	if err != nil {
		return 0, 0, err
	}

	lockedOutpoints, err := w.locker.Get(ctx)
	if err != nil {
		return 0, 0, err
	}

	available := uint64(0)
	locked := uint64(0)

	for _, u := range utxos {
		if _, isLocked := lockedOutpoints[u.OutPoint]; isLocked {
			locked += u.Value
		} else {
			available += u.Value
		}
	}

	return available, locked, nil
}
