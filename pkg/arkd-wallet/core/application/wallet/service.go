package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
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
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

var (
	ErrWalletLocked        = fmt.Errorf("wallet is locked")
	ErrSignerDisabled      = fmt.Errorf("signer not enabled")
	ErrSignerAlreadyLoaded = fmt.Errorf("signer key already loaded")

	ANCHOR_PKSCRIPT = []byte{0x51, 0x02, 0x4e, 0x73}
)

// https://github.com/bitcoin/bitcoin/blob/439e58c4d8194ca37f70346727d31f52e69592ec/src/policy/policy.cpp#L23C8-L23C11
// biggest input size to compute the maximum dust amount
const biggestInputSize = 148 + 182 // = 330 vbytes

type WalletOptions struct {
	SeedRepository       ports.SeedRepository
	Cypher               ports.Cypher
	Nbxplorer            ports.Nbxplorer
	Network              string
	SignerKey            *btcec.PrivateKey
	DeprecatedSignerKeys []DeprecatedSignerKey
}

type DeprecatedSignerKey struct {
	Key *btcec.PrivateKey
	// unix timestamp after which the key is no longer accepted, 0 if unset
	CutoffDate int64
}

type wallet struct {
	WalletOptions

	locker  *outpointLocker
	keyMgr  *keyManager
	readyCh chan bool
}

// New creates a new WalletService service
func New(opts WalletOptions) application.WalletService {
	return &wallet{opts, newOutpointLocker(time.Minute), nil, make(chan bool)}
}

func (w *wallet) GetReadyUpdate(ctx context.Context) <-chan bool {
	isUnlocked := w.keyMgr != nil

	if isUnlocked {
		go func() {
			select {
			case <-ctx.Done():
				return
			case w.readyCh <- true:
				return
			default:
				log.Warn("could not send event for ready update, channel full")
			}
		}()
	}

	return w.readyCh
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

	mainAccountScanProgress := w.Nbxplorer.ScanUtxoSet(ctx, keyMgr.mainAccountDerivationScheme, 1000)
	connectorAccountScanProgress := w.Nbxplorer.ScanUtxoSet(ctx, keyMgr.connectorAccountDerivationScheme, 1000)

	mainAccountScanDone := false
	connectorAccountScanDone := false
	for !(mainAccountScanDone && connectorAccountScanDone) {
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

	encryptedSeed, err := w.SeedRepository.GetEncryptedSeed(ctx)
	if err != nil {
		return err
	}
	seed, err := w.Cypher.Decrypt(ctx, encryptedSeed, password)
	if err != nil {
		return err
	}

	keyMgr, err := newKeyManager(seed, w.chainParams())
	if err != nil {
		return err
	}

	w.keyMgr = keyMgr

	go func() {
		// To not send the notification immediately after unlocking
		<-time.After(500 * time.Millisecond)
		select {
		case w.readyCh <- true:
		default:
			log.Warn("could not send event for ready update, channel full")
		}
	}()

	log.Infof("wallet unlocked")

	return nil
}

func (w *wallet) Lock(ctx context.Context) error {
	if w.keyMgr == nil {
		return fmt.Errorf("wallet is already locked")
	}
	select {
	case w.readyCh <- false:
	default:
		log.Warn("could not send event for ready update, channel full")
	}
	w.keyMgr = nil
	return nil
}

func (w *wallet) Status(ctx context.Context) application.WalletStatus {
	return application.WalletStatus{
		IsInitialized: w.SeedRepository.IsInitialized(ctx),
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

	return w.getBalance(ctx, w.keyMgr.connectorAccountDerivationScheme)
}

func (w *wallet) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	if w.keyMgr == nil {
		return 0, 0, ErrWalletLocked
	}

	return w.getBalance(ctx, w.keyMgr.mainAccountDerivationScheme)
}

func (w *wallet) GetNetwork(ctx context.Context) string {
	return w.Network
}

func (w *wallet) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	if w.keyMgr == nil {
		return nil, ErrWalletLocked
	}

	return w.deriveAddresses(ctx, w.keyMgr.mainAccountDerivationScheme, num)
}

func (w *wallet) DeriveConnectorAddress(ctx context.Context) (string, error) {
	if w.keyMgr == nil {
		return "", ErrWalletLocked
	}

	addresses, err := w.deriveAddresses(ctx, w.keyMgr.connectorAccountDerivationScheme, 1)
	if err != nil {
		return "", err
	}

	return addresses[0], nil
}

func (w *wallet) GetSignerPubkey(ctx context.Context) (string, error) {
	if w.SignerKey == nil {
		return "", ErrSignerDisabled
	}

	pubkey := hex.EncodeToString(w.SignerKey.PubKey().SerializeCompressed())
	return pubkey, nil
}

func (w *wallet) GetDeprecatedSignerPubkeys(
	ctx context.Context,
) ([]application.DeprecatedSignerPubkey, error) {
	pubkeys := make([]application.DeprecatedSignerPubkey, 0, len(w.DeprecatedSignerKeys))
	for _, k := range w.DeprecatedSignerKeys {
		pubkeys = append(pubkeys, application.DeprecatedSignerPubkey{
			Pubkey:     hex.EncodeToString(k.Key.PubKey().SerializeCompressed()),
			CutoffDate: k.CutoffDate,
		})
	}
	return pubkeys, nil
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
				weightEstimator.AddTaprootKeySpendInput(txscript.SigHashAll)
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
			// in regtest, sometimes the fee estimation fails because there is not enough transactions
			// fallback to minrelayfee
			return chainfee.AbsoluteFeePerKwFloor.FeePerKVByte(), nil
		}
		return 0, err
	}

	return rate, nil
}

func (w *wallet) GetForfeitPubkey(ctx context.Context) (string, error) {
	if w.keyMgr == nil {
		return "", ErrWalletLocked
	}

	return hex.EncodeToString(w.keyMgr.forfeitPrvkey.PubKey().SerializeCompressed()), nil
}

func (w *wallet) LockConnectorUtxos(ctx context.Context, utxos []wire.OutPoint) error {
	if w.keyMgr == nil {
		return ErrWalletLocked
	}

	return w.locker.lock(ctx, utxos...)
}

func (w *wallet) ListConnectorUtxos(
	ctx context.Context, connectorAddresses []string,
) ([]application.Utxo, error) {
	if w.keyMgr == nil {
		return nil, ErrWalletLocked
	}

	addressSet := make(map[string]struct{}, len(connectorAddresses))
	for _, addr := range connectorAddresses {
		addressSet[addr] = struct{}{}
	}

	connectorAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.connectorAccountDerivationScheme)
	if err != nil {
		return nil, err
	}

	lockedOutpoints, err := w.locker.get(ctx)
	if err != nil {
		return nil, err
	}

	connectorUtxos := make([]application.Utxo, 0, len(connectorAccountUtxos))
	for _, utxo := range connectorAccountUtxos {
		// for connector utxos, we exclude unconfirmed ones because they're always spent via 1C1P package relay
		if utxo.Confirmations < 1 {
			continue
		}

		if _, ok := addressSet[utxo.Address]; !ok {
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

// GetMainAccountUtxos lists the whole UTXO set of the main account, including
// locked and unconfirmed UTXOs, each flagged with its lock status.
func (w *wallet) GetMainAccountUtxos(ctx context.Context) ([]application.MainAccountUtxo, error) {
	if w.keyMgr == nil {
		return nil, ErrWalletLocked
	}

	mainAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.mainAccountDerivationScheme)
	if err != nil {
		return nil, err
	}

	lockedOutpoints, err := w.locker.get(ctx)
	if err != nil {
		return nil, err
	}

	utxos := make([]application.MainAccountUtxo, 0, len(mainAccountUtxos))
	for _, utxo := range mainAccountUtxos {
		_, locked := lockedOutpoints[utxo.OutPoint]
		utxos = append(utxos, application.MainAccountUtxo{
			Txid:          utxo.OutPoint.Hash.String(),
			Vout:          utxo.OutPoint.Index,
			Value:         utxo.Value,
			Script:        utxo.Script,
			Address:       utxo.Address,
			Confirmations: utxo.Confirmations,
			Locked:        locked,
		})
	}

	return utxos, nil
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
	selectedUtxos, totalValue, err := w.selectCoins(ctx, amount, confirmedOnly, defaultMinChangeAmount)
	if err != nil {
		return nil, 0, err
	}

	if err := w.lockUtxos(ctx, selectedUtxos); err != nil {
		log.Error("failed to lock utxos", err)
		// ignore error
	}

	return selectedUtxos, totalValue - amount, nil
}

// selectCoins picks a subset of the main account UTXOs covering amount
func (w *wallet) selectCoins(
	ctx context.Context, amount uint64, confirmedOnly bool, minChangeAmount btcutil.Amount,
) ([]application.Utxo, uint64, error) {
	if w.keyMgr == nil {
		return nil, 0, ErrWalletLocked
	}

	mainAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.mainAccountDerivationScheme)
	if err != nil {
		return nil, 0, err
	}

	lockedOutpoints, err := w.locker.get(ctx)
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

		availableUtxos = append(availableUtxos, coin{utxo})
	}

	coins, err := coinSelector{minChangeAmount}.CoinSelect(btcutil.Amount(amount), availableUtxos)
	if err != nil {
		return nil, 0, err
	}

	selected := coins.Coins()
	selectedUtxos := make([]application.Utxo, 0, len(selected))
	totalValue := uint64(0)

	for _, coin := range selected {
		value := uint64(coin.Value().ToUnit(btcutil.AmountSatoshi))
		selectedUtxos = append(selectedUtxos, application.Utxo{
			Txid:   coin.Hash().String(),
			Index:  coin.Index(),
			Script: hex.EncodeToString(coin.PkScript()),
			Value:  value,
		})
		totalValue += value
	}

	return selectedUtxos, totalValue, nil
}

// selectCoinsForWithdraw selects main-account UTXOs to fund a withdrawal of
// `amount` in a tx paying `feeRate`.
func (w *wallet) selectCoinsForWithdraw(
	ctx context.Context, amount uint64, feeRate chainfee.SatPerKVByte, destPkScript []byte,
) ([]application.Utxo, uint64, error) {
	if w.keyMgr == nil {
		return nil, 0, ErrWalletLocked
	}

	mainAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.mainAccountDerivationScheme)
	if err != nil {
		return nil, 0, err
	}

	lockedOutpoints, err := w.locker.get(ctx)
	if err != nil {
		return nil, 0, err
	}

	// fee(n) = base + perInput*n, derived from the weight estimator.
	feeOneInput := w.estimateWithdrawFee(feeRate, 1, destPkScript)
	feeTwoInputs := w.estimateWithdrawFee(feeRate, 2, destPkScript)
	perInput := feeTwoInputs - feeOneInput
	base := feeOneInput - perInput

	availableUtxos := make([]coinset.Coin, 0, len(mainAccountUtxos))
	for _, utxo := range mainAccountUtxos {
		if _, isLocked := lockedOutpoints[utxo.OutPoint]; isLocked {
			continue
		}
		// skip UTXOs that cost at least as much to spend as they are worth
		if utxo.Value <= perInput {
			continue
		}
		availableUtxos = append(availableUtxos, effectiveValueCoin{
			coin:           coin{utxo},
			effectiveValue: btcutil.Amount(utxo.Value - perInput),
		})
	}

	coins, err := coinSelector{0}.CoinSelect(btcutil.Amount(amount+base), availableUtxos)
	if err != nil {
		return nil, 0, err
	}

	selected := coins.Coins()
	selectedUtxos := make([]application.Utxo, 0, len(selected))
	totalValue := uint64(0)
	for _, c := range selected {
		utxo := c.(effectiveValueCoin).coin.utxo
		selectedUtxos = append(selectedUtxos, application.Utxo{
			Txid:   utxo.OutPoint.Hash.String(),
			Index:  utxo.OutPoint.Index,
			Script: utxo.Script,
			Value:  utxo.Value,
		})
		totalValue += utxo.Value
	}

	return selectedUtxos, totalValue, nil
}

// lockUtxos locks the given UTXOs so concurrent operations don't double-spend them.
func (w *wallet) lockUtxos(ctx context.Context, utxos []application.Utxo) error {
	toLock := make([]wire.OutPoint, 0, len(utxos))
	for _, utxo := range utxos {
		hash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return fmt.Errorf("failed to parse txid: %w", err)
		}
		toLock = append(toLock, wire.OutPoint{Hash: *hash, Index: utxo.Index})
	}

	return w.locker.lock(ctx, toLock...)
}

// unlockUtxos releases UTXOs previously locked by lockUtxos, e.g. when the tx
// they were selected for ends up not being broadcast.
func (w *wallet) unlockUtxos(ctx context.Context, utxos []application.Utxo) {
	toUnlock := make([]wire.OutPoint, 0, len(utxos))
	for _, utxo := range utxos {
		hash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			continue
		}
		toUnlock = append(toUnlock, wire.OutPoint{Hash: *hash, Index: utxo.Index})
	}

	w.locker.unlock(ctx, toUnlock...)
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

func (w *wallet) SignTransaction(
	ctx context.Context, signMode, partialTx string, extractRawTx bool, inputIndexes []int,
) (string, error) {
	if signMode == application.SignModeLiquidityProvider && w.keyMgr == nil {
		return "", ErrWalletLocked
	}
	if signMode == application.SignModeSigner && w.SignerKey == nil {
		return "", ErrSignerDisabled
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(partialTx), true)
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
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	for inputIndex, input := range ptx.Inputs {
		// skip P2A inputs
		if bytes.Equal(input.WitnessUtxo.PkScript, ANCHOR_PKSCRIPT) {
			continue
		}

		// skip if inputIndex is not in inputIndexes
		if len(inputIndexes) > 0 && !slices.Contains(inputIndexes, inputIndex) {
			continue
		}

		// if not a taproot input, skip because arkd-wallet is taproot only accounts
		if !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
			continue
		}

		if len(input.TaprootLeafScript) > 0 {
			signingKey := w.keyMgr.forfeitPrvkey
			if signMode == application.SignModeSigner {
				signingKey  = w.signerKeyForLeaf(input.TaprootLeafScript[0].Script)
			}

			tapLeaf := txscript.NewBaseTapLeaf(input.TaprootLeafScript[0].Script)

			signature, err := txscript.RawTxInTapscriptSignature(
				ptx.UnsignedTx, txSigHashes, inputIndex, input.WitnessUtxo.Value,
				input.WitnessUtxo.PkScript, tapLeaf, input.SighashType, signingKey,
			)
			if err != nil {
				return "", err
			}

			leafHash := tapLeaf.TapHash()

			ptx.Inputs[inputIndex].TaprootScriptSpendSig = append(ptx.Inputs[inputIndex].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
				Signature:   signature[:64], // remove the last byte (sig hash type) because signature is already encoded
				XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
				LeafHash:    leafHash[:],
				SigHash:     input.SighashType,
			})
			continue
		}

		// otherwise, it's key-path = main or connector account

		// skip if already signed
		if len(input.TaprootKeySpendSig) > 0 {
			continue
		}

		privateKey, err := w.getPrivateKeyFromScript(ctx, hex.EncodeToString(input.WitnessUtxo.PkScript))
		if err != nil {
			return "", err
		}
		if privateKey == nil {
			return "", fmt.Errorf("script %x is not a wallet script, cannot sign input %s",
				input.WitnessUtxo.PkScript, ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.String())
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

	if extractRawTx {
		for i, in := range ptx.Inputs {
			isTaproot := txscript.IsPayToTaproot(in.WitnessUtxo.PkScript)
			if isTaproot && len(in.TaprootLeafScript) > 0 {
				closure, err := script.DecodeClosure(in.TaprootLeafScript[0].Script)
				if err != nil {
					return "", err
				}

				conditionWitnessFields, err := txutils.GetArkPsbtFields(ptx, i, txutils.ConditionWitnessField)
				if err != nil {
					return "", err
				}

				args := make(map[string][]byte)
				if len(conditionWitnessFields) > 0 {
					var conditionWitnessBytes bytes.Buffer
					if err := psbt.WriteTxWitness(&conditionWitnessBytes, conditionWitnessFields[0]); err != nil {
						return "", err
					}
					args[string(txutils.ArkFieldConditionWitness)] = conditionWitnessBytes.Bytes()
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

// signerKeyForLeaf returns the deprecated signer key referenced by the leaf, or the current SignerKey.
func (w *wallet) signerKeyForLeaf(leafScript []byte) *btcec.PrivateKey {
	if len(w.DeprecatedSignerKeys) == 0 {
		return w.SignerKey
	}

	closure, err := script.DecodeClosure(leafScript)
	if err != nil {
		return w.SignerKey
	}

	leafKeys := make([]*btcec.PublicKey, 0)
	switch c := closure.(type) {
	case *script.MultisigClosure:
		leafKeys = c.PubKeys
	case *script.CLTVMultisigClosure:
		leafKeys = c.PubKeys
	case *script.ConditionMultisigClosure:
		leafKeys = c.PubKeys
	default:
		return w.SignerKey
	}
	
	for _, k := range w.DeprecatedSignerKeys {
		want := schnorr.SerializePubKey(k.Key.PubKey())
		for _, pubkey := range leafKeys {
			if bytes.Equal(schnorr.SerializePubKey(pubkey), want) {
				return k.Key
			}
		}
	}
	return w.SignerKey
}

// WithdrawAll withdraws all available balance including connectors account funds
func (w *wallet) WithdrawAll(ctx context.Context, destinationAddress string) (string, error) {
	destinationAddr, err := btcutil.DecodeAddress(destinationAddress, w.chainParams())
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}

	destPkScript, err := txscript.PayToAddrScript(destinationAddr)
	if err != nil {
		return "", fmt.Errorf("failed to create destination script: %w", err)
	}

	feeRate, err := w.FeeRate(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get fee rate: %w", err)
	}

	ptx, err := w.withdrawAll(ctx, feeRate, destPkScript, true)
	if err != nil {
		return "", fmt.Errorf("failed to create send all tx: %w", err)
	}

	psbtB64, err := ptx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode PSBT: %w", err)
	}

	signMode := application.SignModeLiquidityProvider
	signedTx, err := w.SignTransaction(ctx, signMode, psbtB64, true, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	return w.BroadcastTransaction(ctx, signedTx)
}

// Withdraw withdraws a specified amount of main account funds
func (w *wallet) Withdraw(ctx context.Context, destinationAddress string, amount uint64) (string, error) {
	if w.keyMgr == nil {
		return "", ErrWalletLocked
	}
	dustAmount := w.GetDustAmount(ctx)
	if amount < dustAmount {
		return "", fmt.Errorf("amount is too small to be withdrawn (dust amount: %d)", dustAmount)
	}

	// validate the destination address
	destinationAddr, err := btcutil.DecodeAddress(destinationAddress, w.chainParams())
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}

	destPkScript, err := txscript.PayToAddrScript(destinationAddr)
	if err != nil {
		return "", fmt.Errorf("failed to create destination script: %w", err)
	}

	feeRate, err := w.FeeRate(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get fee rate: %w", err)
	}

	balance, _, err := w.MainAccountBalance(ctx)
	if err != nil {
		return "", err
	}

	var ptx *psbt.Packet

	if balance == amount {
		ptx, err = w.withdrawAll(ctx, feeRate, destPkScript, false)
		if err != nil {
			return "", fmt.Errorf("failed to create send all tx: %w", err)
		}
	} else {
		ptx, err = w.withdrawPartially(ctx, feeRate, amount, destPkScript)
		if err != nil {
			return "", fmt.Errorf("failed to create send partially tx: %w", err)
		}
	}

	// If signing or broadcasting fails, release the locks held on the inputs so
	// the funds become spendable again instead of waiting for the lock expiry.
	// (withdrawAll inputs aren't locked, so this is a no-op for that path.)
	broadcasted := false
	defer func() {
		if !broadcasted {
			outpoints := make([]wire.OutPoint, 0, len(ptx.UnsignedTx.TxIn))
			for _, in := range ptx.UnsignedTx.TxIn {
				outpoints = append(outpoints, in.PreviousOutPoint)
			}
			w.locker.unlock(ctx, outpoints...)
		}
	}()

	psbtB64, err := ptx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode PSBT: %w", err)
	}

	signMode := application.SignModeLiquidityProvider
	signedTx, err := w.SignTransaction(ctx, signMode, psbtB64, true, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	txid, err := w.BroadcastTransaction(ctx, signedTx)
	if err != nil {
		return "", err
	}

	broadcasted = true
	return txid, nil
}

func (w *wallet) LoadSignerKey(ctx context.Context, prvkey *btcec.PrivateKey) error {
	if w.SignerKey != nil {
		return ErrSignerAlreadyLoaded
	}

	w.SignerKey = prvkey
	return nil
}

func (w *wallet) Close() {
	// nolint:errcheck
	w.Nbxplorer.Close()
	w.keyMgr = nil
	close(w.readyCh)
	w.SeedRepository.Close()
}

func (w *wallet) withdrawPartially(ctx context.Context, feeRate chainfee.SatPerKVByte, amount uint64, destPkScript []byte) (*psbt.Packet, error) {
	// Effective-value selection: the chosen UTXOs always cover amount + the fee
	// for their actual input count, whatever that count is. This makes any
	// fundable withdraw succeed without a re-selection loop.
	selectedUtxos, totalInputValue, err := w.selectCoinsForWithdraw(ctx, amount, feeRate, destPkScript)
	if err != nil {
		return nil, fmt.Errorf("failed to select UTXOs: %w", err)
	}

	if err := w.lockUtxos(ctx, selectedUtxos); err != nil {
		log.Error("failed to lock utxos", err)
		// ignore error
	}

	// Release the locked UTXOs if we fail to build the tx, so they don't stay
	// locked until the lock expiry for nothing.
	built := false
	defer func() {
		if !built {
			w.unlockUtxos(ctx, selectedUtxos)
		}
	}()

	inputs := make([]*wire.OutPoint, 0, len(selectedUtxos))
	outputs := make([]*wire.TxOut, 0)
	nSequences := make([]uint32, 0, len(selectedUtxos))

	for _, utxo := range selectedUtxos {
		hash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return nil, fmt.Errorf("failed to parse txid: %w", err)
		}
		inputs = append(inputs, &wire.OutPoint{Hash: *hash, Index: utxo.Index})
		nSequences = append(nSequences, wire.MaxTxInSequenceNum)
	}

	actualFee := w.estimateWithdrawFee(feeRate, len(selectedUtxos), destPkScript) // 2 outputs: destination + change

	surplus := totalInputValue - amount
	changeAmount := uint64(0)
	if surplus > actualFee {
		changeAmount = surplus - actualFee
	}

	outputs = append(outputs, &wire.TxOut{
		Value:    int64(amount),
		PkScript: destPkScript,
	})

	if changeAmount >= w.GetDustAmount(ctx) {
		changeAddress, err := w.Nbxplorer.GetNewUnusedAddress(ctx, w.keyMgr.mainAccountDerivationScheme, true, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to generate change address: %w", err)
		}

		changeAddr, err := btcutil.DecodeAddress(changeAddress, w.chainParams())
		if err != nil {
			return nil, fmt.Errorf("failed to decode change address: %w", err)
		}

		changePkScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create change script: %w", err)
		}

		outputs = append(outputs, &wire.TxOut{
			Value:    int64(changeAmount),
			PkScript: changePkScript,
		})
	} else {
		actualFee += changeAmount
	}

	ptx, err := psbt.New(inputs, outputs, 2, 0, nSequences)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT: %w", err)
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT updater: %w", err)
	}

	for inputIndex, utxo := range selectedUtxos {
		scriptBytes, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return nil, fmt.Errorf("failed to decode script: %w", err)
		}

		if err := updater.AddInWitnessUtxo(&wire.TxOut{
			Value:    int64(utxo.Value),
			PkScript: scriptBytes,
		}, inputIndex); err != nil {
			return nil, fmt.Errorf("failed to add input witness utxo: %w", err)
		}
	}

	built = true
	return ptx, nil
}

func (w *wallet) withdrawAll(ctx context.Context, feeRate chainfee.SatPerKVByte, destPkScript []byte, withConnectors bool) (*psbt.Packet, error) {
	utxos := make([]ports.Utxo, 0)

	mainAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.mainAccountDerivationScheme)
	if err != nil {
		return nil, err
	}

	utxos = append(utxos, mainAccountUtxos...)

	if withConnectors {
		connectorAccountUtxos, err := w.Nbxplorer.GetUtxos(ctx, w.keyMgr.connectorAccountDerivationScheme)
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, connectorAccountUtxos...)
	}

	lockedOutpoints, err := w.locker.get(ctx)
	if err != nil {
		return nil, err
	}

	amount := uint64(0)
	availableUtxos := make([]ports.Utxo, 0, len(utxos))

	for _, utxo := range utxos {
		if _, isLocked := lockedOutpoints[utxo.OutPoint]; isLocked {
			continue
		}

		availableUtxos = append(availableUtxos, utxo)
		amount += utxo.Value
	}

	estimatedFee := w.estimateWithdrawFee(feeRate, len(availableUtxos), destPkScript)
	if amount < estimatedFee {
		return nil, fmt.Errorf("amount is too small to be withdrawn (estimated fee: %d)", estimatedFee)
	}
	amount -= estimatedFee
	if amount < w.GetDustAmount(ctx) {
		return nil, fmt.Errorf("amount is too small to be withdrawn (dust amount: %d)", w.GetDustAmount(ctx))
	}

	inputs := make([]*wire.OutPoint, 0)
	outputs := make([]*wire.TxOut, 0, 1)
	nSequences := make([]uint32, 0)

	for _, utxo := range availableUtxos {
		inputs = append(inputs, &utxo.OutPoint)
		nSequences = append(nSequences, wire.MaxTxInSequenceNum)
	}

	outputs = append(outputs, &wire.TxOut{
		Value:    int64(amount),
		PkScript: destPkScript,
	})

	ptx, err := psbt.New(inputs, outputs, 2, 0, nSequences)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT: %w", err)
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT updater: %w", err)
	}

	for i, utxo := range availableUtxos {
		script, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return nil, fmt.Errorf("failed to decode prevout script: %w", err)
		}

		if err := updater.AddInWitnessUtxo(&wire.TxOut{
			Value:    int64(utxo.Value),
			PkScript: script,
		}, i); err != nil {
			return nil, fmt.Errorf("failed to add input witness utxo: %w", err)
		}
	}

	return ptx, nil
}

func (w *wallet) init(ctx context.Context, mnemonic string, password string) (keyMgr *keyManager, err error) {
	if w.SeedRepository.IsInitialized(ctx) {
		return nil, fmt.Errorf("wallet already initialized")
	}

	seedBytes, err := bip39.MnemonicToByteArray(mnemonic)
	if err != nil {
		return nil, err
	}
	encryptedSeed, err := w.Cypher.Encrypt(ctx, seedBytes, password)
	if err != nil {
		return nil, err
	}

	if err := w.SeedRepository.AddEncryptedSeed(ctx, encryptedSeed); err != nil {
		return nil, err
	}

	keyMgr, err = newKeyManager(seedBytes, w.chainParams())
	if err != nil {
		return nil, err
	}

	if err := w.Nbxplorer.Track(ctx, keyMgr.mainAccountDerivationScheme); err != nil {
		return nil, err
	}

	if err := w.Nbxplorer.Track(ctx, keyMgr.connectorAccountDerivationScheme); err != nil {
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

// estimateWithdrawFee tries to compute the expected fee for a withdrawal transaction
// it assumes inputs are all tapkey and outputs are 1 change (tapkey) and 1 destination
func (w *wallet) estimateWithdrawFee(feeRate chainfee.SatPerKVByte, numInputs int, destinationScript []byte) uint64 {
	weightEstimator := &input.TxWeightEstimator{}

	for range numInputs {
		weightEstimator.AddTaprootKeySpendInput(txscript.SigHashAll)
	}

	weightEstimator.
		// destination output
		AddOutput(destinationScript).
		// change output
		AddP2TROutput()

	fee := feeRate.FeeForVSize(lntypes.VByte(weightEstimator.VSize()))
	return uint64(math.Ceil(fee.ToUnit(btcutil.AmountSatoshi)))
}

func (w *wallet) getPrivateKeyFromScript(ctx context.Context, scriptPubKey string) (*btcec.PrivateKey, error) {
	if w.keyMgr == nil {
		return nil, ErrWalletLocked
	}

	accountsDerivationSchemes := []string{
		w.keyMgr.mainAccountDerivationScheme,
		w.keyMgr.connectorAccountDerivationScheme,
	}

	for _, derivationScheme := range accountsDerivationSchemes {
		scriptPubKeyDetails, err := w.Nbxplorer.GetScriptPubKeyDetails(ctx, derivationScheme, scriptPubKey)
		if err != nil {
			continue
		}

		return w.keyMgr.deriveKey(derivationScheme, scriptPubKeyDetails.KeyPath)
	}

	return nil, nil
}

func (w *wallet) getBalance(ctx context.Context, derivationScheme string) (uint64, uint64, error) {
	utxos, err := w.Nbxplorer.GetUtxos(ctx, derivationScheme)
	if err != nil {
		return 0, 0, err
	}

	lockedOutpoints, err := w.locker.get(ctx)
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
