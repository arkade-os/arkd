package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-bip39"
)

const (
	// p2wkh scope
	mainAccount accountName = "default" // default is always the first account (index 0)

	// p2tr scope
	connectorAccount accountName = "default"

	// this account won't be restored by lnd, but it's not a problem cause it does not track any funds
	// it's used to derive a constant public key to be used as "server key" in Vtxo scripts
	serverKeyAccount accountName = "server"

	// https://github.com/bitcoin/bitcoin/blob/439e58c4d8194ca37f70346727d31f52e69592ec/src/policy/policy.cpp#L23C8-L23C11
	// biggest input size to compute the maximum dust amount
	biggestInputSize = 148 + 182 // = 330 vbytes
)

var (
	ErrNotLoaded          = fmt.Errorf("wallet not loaded, create or unlock it first")
	ErrNotSynced          = fmt.Errorf("wallet still syncing, please retry later")
	ErrNotReady           = fmt.Errorf("wallet not ready, please init and wait for it to complete syncing")
	ErrNotUnlocked        = fmt.Errorf("wallet is locked, please unlock it to perform this operation")
	ErrAlreadyInitialized = fmt.Errorf("wallet already initialized")
	p2wpkhKeyScope        = waddrmgr.KeyScopeBIP0084
	p2trKeyScope          = waddrmgr.KeyScopeBIP0086
	outputLockDuration    = time.Minute
)

type accountName string

type service struct {
	wallet *btcwallet.BtcWallet
	cfg    WalletConfig

	chainSource  chain.Interface
	scanner      chain.Interface
	extraAPI     extraChainAPI
	feeEstimator chainfee.Estimator

	watchedScriptsLock sync.RWMutex
	watchedScripts     map[string]struct{}

	// holds the data related to the server key used in Vtxo scripts
	serverKeyAddr waddrmgr.ManagedPubKeyAddress

	// cached forfeit addres
	forfeitAddr string

	isSynced   bool
	isUnlocked bool
	readyCh    chan struct{}
}

// NewService creates the wallet service, an option must be set to configure the chain source.
func NewService(cfg WalletConfig, options ...WalletOption) (WalletService, error) {
	wallet.UseLogger(logger("wallet"))

	svc := &service{
		cfg:                cfg,
		watchedScriptsLock: sync.RWMutex{},
		watchedScripts:     make(map[string]struct{}),
		readyCh:            make(chan struct{}),
	}

	for _, option := range options {
		if err := option(svc); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

func (s *service) Close() {
	if s.isLoaded() {
		s.wallet.InternalWallet().Stop()
	}
	s.chainSource.Stop()
}

func (s *service) GetReadyUpdate(_ context.Context) <-chan struct{} {
	return s.readyCh
}

func (s *service) GenSeed(_ context.Context) (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func (s *service) Create(_ context.Context, seed, password string) error {
	return s.create(seed, password, 0)
}

func (s *service) Restore(_ context.Context, seed, password string) error {
	return s.create(seed, password, 2000) // restore = create with a bigger recovery window
}

func (s *service) Unlock(_ context.Context, password string) error {
	if !s.isInitialized() {
		return fmt.Errorf("wallet not initialized")
	}

	if !s.isLoaded() {
		pwd := []byte(password)
		opt := btcwallet.LoaderWithLocalWalletDB(s.cfg.Datadir, false, time.Minute)
		config := btcwallet.Config{
			LogDir:                s.cfg.Datadir,
			PrivatePass:           pwd,
			PublicPass:            pwd,
			RecoveryWindow:        512,
			NetParams:             s.cfg.chainParams(),
			LoaderOptions:         []btcwallet.LoaderOption{opt},
			CoinSelectionStrategy: wallet.CoinSelectionLargest,
			ChainSource:           s.chainSource,
		}
		blockCache := blockcache.NewBlockCache(2 * 1024 * 1024 * 1024)

		wlt, err := btcwallet.New(config, blockCache)
		if err != nil {
			return fmt.Errorf("failed to setup wallet loader: %s", err)
		}

		if err := wlt.Start(); err != nil {
			return fmt.Errorf("failed to start wallet: %s", err)
		}

		serverAddr, err := s.loadServerAddress(wlt)
		if err != nil {
			return err
		}

		forfeitAddr, err := s.loadForfeitAddress(wlt)
		if err != nil {
			return err
		}

		s.serverKeyAddr = serverAddr
		s.forfeitAddr = forfeitAddr
		s.wallet = wlt
		s.isUnlocked = true

		go s.listenToSynced()

		return nil
	}

	if err := s.wallet.InternalWallet().Unlock([]byte(password), nil); err != nil {
		return err
	}

	s.isUnlocked = true
	if s.isUnlocked && s.isSynced {
		s.readyCh <- struct{}{}
	}
	return nil
}

func (s *service) Lock(_ context.Context) error {
	if !s.isLoaded() {
		return ErrNotLoaded
	}

	s.wallet.InternalWallet().Lock()
	return nil
}

func (s *service) BroadcastTransaction(_ context.Context, txs ...string) (string, error) {
	if err := s.extraAPI.broadcast(txs...); err != nil {
		return "", err
	}

	if len(txs) == 1 {
		var tx wire.MsgTx
		if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txs[0]))); err != nil {
			return "", err
		}

		return tx.TxHash().String(), nil
	}

	return "", nil
}

func (s *service) ConnectorsAccountBalance(_ context.Context) (uint64, uint64, error) {
	if err := s.safeCheck(); err != nil {
		return 0, 0, err
	}

	withConfirmedOnly := true
	withUnconfirmed := !withConfirmedOnly
	utxos, err := s.listUtxos(p2trKeyScope, withUnconfirmed)
	if err != nil {
		return 0, 0, err
	}

	amount := uint64(0)
	for _, utxo := range utxos {
		amount += uint64(utxo.Output.Value)
	}

	return amount, 0, nil
}

func (s *service) MainAccountBalance(_ context.Context) (uint64, uint64, error) {
	if err := s.safeCheck(); err != nil {
		return 0, 0, err
	}

	withConfirmedOnly := true
	withUnconfirmed := !withConfirmedOnly
	utxos, err := s.listUtxos(p2wpkhKeyScope, withUnconfirmed)
	if err != nil {
		return 0, 0, err
	}

	amount := uint64(0)
	for _, utxo := range utxos {
		amount += uint64(utxo.Output.Value)
	}

	return amount, 0, nil
}

func (s *service) DeriveAddresses(_ context.Context, num int) ([]string, error) {
	if err := s.safeCheck(); err != nil {
		return nil, err
	}

	addresses := make([]string, 0, num)
	for i := 0; i < num; i++ {
		addr, err := s.deriveNextAddress()
		if err != nil {
			return nil, err
		}

		addresses = append(addresses, addr.EncodeAddress())
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses derived")
	}

	return addresses, nil
}

func (s *service) DeriveConnectorAddress(_ context.Context) (string, error) {
	if err := s.safeCheck(); err != nil {
		return "", err
	}

	addr, err := s.wallet.NewAddress(lnwallet.TaprootPubkey, false, string(connectorAccount))
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

func (s *service) GetPubkey(_ context.Context) (*secp256k1.PublicKey, error) {
	if !s.isLoaded() {
		return nil, ErrNotLoaded
	}
	return s.serverKeyAddr.PubKey(), nil
}

func (s *service) GetNetwork(_ context.Context) string {
	return s.cfg.chainParams().Name
}

func (s *service) GetForfeitAddress(_ context.Context) (string, error) {
	if err := s.safeCheck(); err != nil {
		return "", err
	}

	return s.forfeitAddr, nil
}

func (s *service) ListConnectorUtxos(_ context.Context, connectorAddress string) ([]TxInput, error) {
	if err := s.safeCheck(); err != nil {
		return nil, err
	}

	w := s.wallet.InternalWallet()

	addr, err := btcutil.DecodeAddress(connectorAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	withConfirmedOnly := true
	withUnconfirmed := !withConfirmedOnly
	utxos, err := s.listUtxos(p2trKeyScope, withUnconfirmed)
	if err != nil {
		return nil, err
	}

	txInputs := make([]TxInput, 0, len(utxos))
	for _, utxo := range utxos {
		if !bytes.Equal(utxo.Output.PkScript, script) {
			continue
		}

		txInputs = append(txInputs, TxInput{
			Txid:   utxo.OutPoint.Hash.String(),
			Index:  utxo.OutPoint.Index,
			Script: hex.EncodeToString(utxo.Output.PkScript),
			Value:  uint64(utxo.Output.Value),
		})
	}

	return txInputs, nil
}

func (s *service) LockConnectorUtxos(_ context.Context, utxos []TxOutpoint) error {
	if err := s.safeCheck(); err != nil {
		return err
	}

	w := s.wallet.InternalWallet()

	for _, utxo := range utxos {
		const retry = 60

		for i := 0; i < retry; i++ {
			id, _ := chainhash.NewHashFromStr(utxo.Txid)
			if _, err := w.LeaseOutput(
				wtxmgr.LockID(id[:]),
				wire.OutPoint{
					Hash:  *id,
					Index: utxo.Index,
				},
				outputLockDuration,
			); err != nil {
				if errors.Is(err, wtxmgr.ErrUnknownOutput) {
					time.Sleep(1 * time.Second)
					continue
				}
				return err
			}
			break
		}
	}

	return nil
}

func (s *service) SelectUtxos(_ context.Context, _ string, amount uint64, confirmedOnly bool) ([]TxInput, uint64, error) {
	if err := s.safeCheck(); err != nil {
		return nil, 0, err
	}

	w := s.wallet.InternalWallet()

	utxos, err := s.listUtxos(p2wpkhKeyScope, confirmedOnly)
	if err != nil {
		return nil, 0, err
	}

	coins := make([]wallet.Coin, 0, len(utxos))
	for _, utxo := range utxos {
		coins = append(coins, wallet.Coin{
			OutPoint: *wire.NewOutPoint(&utxo.OutPoint.Hash, utxo.OutPoint.Index),
			TxOut:    utxo.Output,
		})
	}

	arranged, err := wallet.CoinSelectionLargest.ArrangeCoins(
		coins,
		btcutil.Amount(0), // unused by CoinSelectionLargest strategy
	)
	if err != nil {
		return nil, 0, err
	}

	selectedAmount := uint64(0)
	selectedUtxos := make([]TxInput, 0, len(arranged))

	for _, coin := range arranged {
		if selectedAmount >= amount {
			break
		}
		selectedAmount += uint64(coin.Value)
		selectedUtxos = append(selectedUtxos, TxInput{
			Txid:   coin.Hash.String(),
			Index:  coin.Index,
			Script: hex.EncodeToString(coin.PkScript),
			Value:  uint64(coin.Value),
		})
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("insufficient funds to select %d, only %d available", amount, selectedAmount)
	}

	for _, utxo := range selectedUtxos {
		id, _ := chainhash.NewHashFromStr(utxo.Txid)
		if _, err := w.LeaseOutput(
			wtxmgr.LockID(id[:]),
			wire.OutPoint{
				Hash:  *id,
				Index: utxo.Index,
			},
			outputLockDuration,
		); err != nil {
			return nil, 0, err
		}
	}
	return selectedUtxos, selectedAmount - amount, nil
}

func (s *service) SignTransaction(_ context.Context, partialTx string, extractRawTx bool) (string, error) {
	if err := s.safeCheck(); err != nil {
		return "", err
	}

	ptx, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return "", err
	}

	signedInputs, err := s.signPsbt(ptx, nil)
	if err != nil {
		return "", err
	}
	if extractRawTx {
		// verify that all inputs are signed
		if len(signedInputs) != len(ptx.Inputs) {
			return "", fmt.Errorf("not all inputs are signed, unable to finalize the psbt")
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

func (s *service) SignTransactionTapscript(_ context.Context, partialTx string, inputIndexes []int) (string, error) {
	if err := s.safeCheck(); err != nil {
		return "", err
	}

	partial, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return "", err
	}

	if len(inputIndexes) == 0 {
		inputIndexes = make([]int, len(partial.Inputs))
		for i := range partial.Inputs {
			inputIndexes[i] = i
		}
	}

	signedInputs, err := s.signPsbt(partial, inputIndexes)
	if err != nil {
		return "", err
	}

	for _, index := range inputIndexes {
		hasBeenSigned := false
		for _, signedIndex := range signedInputs {
			if signedIndex == uint32(index) {
				hasBeenSigned = true
				break
			}
		}

		if !hasBeenSigned {
			return "", fmt.Errorf("input %d has not been signed", index)
		}
	}

	return partial.B64Encode()
}

func (s *service) Status(_ context.Context) (WalletStatus, error) {
	if !s.isLoaded() {
		return WalletStatus{
			IsInitialized: s.isInitialized(),
		}, nil
	}

	w := s.wallet.InternalWallet()
	return WalletStatus{
		IsInitialized: true,
		IsUnlocked:    !w.Manager.IsLocked(),
		IsSynced:      s.isSynced,
	}, nil
}

func (s *service) WaitForSync(ctx context.Context, txid string) error {
	if err := s.safeCheck(); err != nil {
		return err
	}

	w := s.wallet.InternalWallet()

	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_, err := w.GetTransaction(*txhash)
			if err != nil {
				if strings.Contains(err.Error(), wallet.ErrNoTx.Error()) {
					continue
				}
				return err
			} else {
				ticker.Stop()
				return nil
			}
		}
	}
}

func (s *service) FeeRate(_ context.Context) (chainfee.SatPerKVByte, error) {
	feeRate, err := s.feeEstimator.EstimateFeePerKW(1)
	if err != nil {
		return 0, err
	}

	return feeRate.FeePerKVByte(), nil
}

func (s *service) EstimateFees(_ context.Context, partialTx string) (uint64, error) {
	feeRate, err := s.feeEstimator.EstimateFeePerKW(1)
	if err != nil {
		return 0, err
	}

	partial, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
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
		script, err := txscript.ParsePkScript(output.PkScript)
		if err != nil {
			return 0, err
		}

		switch script.Class() {
		case txscript.PubKeyHashTy:
			weightEstimator.AddP2PKHOutput()
		case txscript.WitnessV0PubKeyHashTy:
			weightEstimator.AddP2WKHOutput()
		case txscript.ScriptHashTy:
			weightEstimator.AddP2SHOutput()
		case txscript.WitnessV0ScriptHashTy:
			weightEstimator.AddP2WSHOutput()
		case txscript.WitnessV1TaprootTy:
			weightEstimator.AddP2TROutput()
		default:
			return 0, fmt.Errorf("unsupported script type: %v", script.Class())
		}
	}

	fee := feeRate.FeeForVByte(lntypes.VByte(weightEstimator.VSize()))
	return uint64(fee.ToUnit(btcutil.AmountSatoshi)), nil
}

func (s *service) WatchScripts(ctx context.Context, scripts []string) error {
	if !s.isSynced {
		return ErrNotSynced
	}

	addresses := make([]btcutil.Address, 0, len(scripts))

	for _, script := range scripts {
		scriptBytes, err := hex.DecodeString(script)
		if err != nil {
			return err
		}

		addr, err := fromOutputScript(scriptBytes, s.cfg.chainParams())
		if err != nil {
			return err
		}

		addresses = append(addresses, addr)
	}

	if err := s.scanner.NotifyReceived(addresses); err != nil {
		if err := s.UnwatchScripts(ctx, scripts); err != nil {
			return fmt.Errorf("error while unwatching scripts: %w", err)
		}

		return err
	}

	s.watchedScriptsLock.Lock()
	defer s.watchedScriptsLock.Unlock()

	for _, script := range scripts {
		s.watchedScripts[script] = struct{}{}
	}

	return nil
}

func (s *service) UnwatchScripts(_ context.Context, scripts []string) error {
	if !s.isSynced {
		return ErrNotSynced
	}

	s.watchedScriptsLock.Lock()
	defer s.watchedScriptsLock.Unlock()
	for _, script := range scripts {
		delete(s.watchedScripts, script)
	}

	return nil
}

func (s *service) GetNotificationChannel(
	_ context.Context,
) <-chan map[string][]VtxoWithValue {
	ch := make(chan map[string][]VtxoWithValue)

	go func() {
		const maxCacheSize = 100
		sentTxs := make(map[chainhash.Hash]struct{})

		cache := func(hash chainhash.Hash) {
			if len(sentTxs) > maxCacheSize {
				sentTxs = make(map[chainhash.Hash]struct{})
			}

			sentTxs[hash] = struct{}{}
		}

		for n := range s.scanner.Notifications() {
			switch m := n.(type) {
			case chain.RelevantTx:
				if _, sent := sentTxs[m.TxRecord.Hash]; sent {
					continue
				}
				notification := s.castNotification(m.TxRecord)
				cache(m.TxRecord.Hash)
				ch <- notification
			case chain.FilteredBlockConnected:
				for _, tx := range m.RelevantTxs {
					if _, sent := sentTxs[tx.Hash]; sent {
						continue
					}
					notification := s.castNotification(tx)
					cache(tx.Hash)
					ch <- notification
				}
			}
		}
	}()

	return ch
}

func (s *service) IsTransactionConfirmed(
	_ context.Context, txid string,
) (isConfirmed bool, blocknumber int64, blocktime int64, err error) {
	return s.extraAPI.getTxStatus(txid)
}

func (s *service) GetDustAmount(
	ctx context.Context,
) uint64 {
	fee := s.feeEstimator.RelayFeePerKW().FeeForVByte(lntypes.VByte(biggestInputSize))
	return uint64(fee.ToUnit(btcutil.AmountSatoshi))
}

func (s *service) GetTransaction(_ context.Context, txid string) (string, error) {
	tx, err := s.extraAPI.getTx(txid)
	if err != nil {
		return "", err
	}

	if tx == nil {
		return "", fmt.Errorf("transaction not found")
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

func (s *service) SignMessage(_ context.Context, message []byte) ([]byte, error) {
	if s.serverKeyAddr == nil {
		return nil, fmt.Errorf("wallet not initialized or locked")
	}

	prvkey, err := s.serverKeyAddr.PrivKey()
	if err != nil {
		return nil, err
	}

	sig, err := schnorr.Sign(prvkey, message)
	if err != nil {
		return nil, err
	}

	return sig.Serialize(), nil
}

func (s *service) VerifyMessageSignature(_ context.Context, message, signature []byte) (bool, error) {
	sig, err := schnorr.ParseSignature(signature)
	if err != nil {
		return false, err
	}

	return sig.Verify(message, s.serverKeyAddr.PubKey()), nil
}

func (s *service) GetCurrentBlockTime(_ context.Context) (*BlockTimestamp, error) {
	blockhash, blockheight, err := s.wallet.GetBestBlock()
	if err != nil {
		return nil, err
	}

	header, err := s.wallet.GetBlockHeader(blockhash)
	if err != nil {
		return nil, err
	}

	return &BlockTimestamp{
		Time:   header.Timestamp.Unix(),
		Height: uint32(blockheight),
	}, nil
}

func (s *service) Withdraw(_ context.Context, address string, amount uint64) (string, error) {
	addr, err := btcutil.DecodeAddress(address, s.cfg.chainParams())
	if err != nil {
		return "", err
	}

	feeRate, err := s.feeEstimator.EstimateFeePerKW(1)
	if err != nil {
		return "", err
	}

	now := time.Now()

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
	}

	output := &wire.TxOut{
		Value:    int64(amount),
		PkScript: pkScript,
	}

	mainAccountNumber, err := s.wallet.InternalWallet().AccountNumber(p2wpkhKeyScope, string(mainAccount))
	if err != nil {
		return "", err
	}

	tx, err := s.wallet.InternalWallet().SendOutputs(
		[]*wire.TxOut{output},
		&p2wpkhKeyScope,
		mainAccountNumber,
		1,
		btcutil.Amount(feeRate.FeePerKVByte()),
		wallet.CoinSelectionLargest,
		fmt.Sprintf("withdraw %d", now.Unix()),
	)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}

	txid := tx.TxHash().String()

	return txid, nil
}

func (s *service) castNotification(tx *wtxmgr.TxRecord) map[string][]VtxoWithValue {
	vtxos := make(map[string][]VtxoWithValue)

	s.watchedScriptsLock.RLock()
	defer s.watchedScriptsLock.RUnlock()

	for outputIndex, txout := range tx.MsgTx.TxOut {
		script := hex.EncodeToString(txout.PkScript)
		if _, ok := s.watchedScripts[script]; !ok {
			continue
		}

		if len(vtxos[script]) <= 0 {
			vtxos[script] = make([]VtxoWithValue, 0)
		}

		vtxos[script] = append(vtxos[script], VtxoWithValue{
			Key: VtxoKey{
				Txid: tx.Hash.String(),
				VOut: uint32(outputIndex),
			},
			Value: uint64(txout.Value),
		})
	}

	return vtxos
}

func (s *service) create(mnemonic, password string, addrGap uint32) error {
	if s.isInitialized() {
		return ErrAlreadyInitialized
	}

	if len(mnemonic) <= 0 {
		return fmt.Errorf("missing hd seed")
	}
	if len(password) <= 0 {
		return fmt.Errorf("missing password")
	}

	pwd := []byte(password)
	seed := bip39.NewSeed(mnemonic, password)
	opt := btcwallet.LoaderWithLocalWalletDB(s.cfg.Datadir, false, time.Minute)

	config := btcwallet.Config{
		LogDir:                s.cfg.Datadir,
		PrivatePass:           pwd,
		PublicPass:            pwd,
		RecoveryWindow:        addrGap,
		HdSeed:                seed,
		NetParams:             s.cfg.chainParams(),
		LoaderOptions:         []btcwallet.LoaderOption{opt},
		CoinSelectionStrategy: wallet.CoinSelectionLargest,
		ChainSource:           s.chainSource,
	}
	blockCache := blockcache.NewBlockCache(2 * 1024 * 1024 * 1024)

	wlt, err := btcwallet.New(config, blockCache)
	if err != nil {
		return fmt.Errorf("failed to setup wallet loader: %s", err)
	}

	if err := wlt.InternalWallet().Unlock([]byte(password), nil); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	defer wlt.InternalWallet().Lock()

	if err := s.initServerKeyAccount(wlt); err != nil {
		return err
	}

	if err := wlt.Start(); err != nil {
		return fmt.Errorf("failed to start wallet: %s", err)
	}

	serverAddr, err := s.loadServerAddress(wlt)
	if err != nil {
		return err
	}

	forfeitAddr, err := s.loadForfeitAddress(wlt)
	if err != nil {
		return err
	}

	s.serverKeyAddr = serverAddr
	s.forfeitAddr = forfeitAddr
	s.wallet = wlt

	go s.listenToSynced()

	return nil
}

func (s *service) listenToSynced() {
	counter := 0
	for {
		if s.wallet.InternalWallet().ChainSynced() {
			log.Debug("wallet: syncing completed")
			s.isSynced = true
			if s.isUnlocked && s.isSynced {
				s.readyCh <- struct{}{}
			}
			return
		}

		isRestore, progress, err := s.wallet.GetRecoveryInfo()
		if err != nil {
			log.Warnf("wallet: failed to check if wallet is synced: %s", err)
		} else {
			if !isRestore {
				if counter%6 == 0 {
					log.Debug("wallet: syncing in progress...")
				}
				counter++
			} else {
				switch progress {
				case 0:
					// nolint: all
					if counter%6 == 0 {
						_, bestBlock, _ := s.wallet.IsSynced()
						if bestBlock > 0 {
							log.Debugf("wallet: waiting for chain source to be synced, last block fetched: %s", time.Unix(bestBlock, 0))
						}
					}
					counter++
				case 1:
					log.Debug("wallet: syncing completed")
					s.isSynced = true
					if s.isUnlocked && s.isSynced {
						s.readyCh <- struct{}{}
					}
					return
				default:
					log.Debugf("wallet: syncing progress %.0f%%", progress*100)
				}
			}
		}

		time.Sleep(10 * time.Second)
	}
}

// initServerKeyAccount creates the server key account if it doesn't exist
func (s *service) initServerKeyAccount(wallet *btcwallet.BtcWallet) error {
	w := wallet.InternalWallet()

	p2trAccounts, err := w.Accounts(p2trKeyScope)
	if err != nil {
		return fmt.Errorf("failed to list wallet accounts: %s", err)
	}

	var serverKeyAccountNumber uint32

	if p2trAccounts != nil {
		for _, account := range p2trAccounts.Accounts {
			if account.AccountName == string(serverKeyAccount) {
				serverKeyAccountNumber = account.AccountNumber
				break
			}
		}
	}

	if serverKeyAccountNumber == 0 {
		log.Debug("creating server key account")
		serverKeyAccountNumber, err = w.NextAccount(p2trKeyScope, string(serverKeyAccount))
		if err != nil {
			return fmt.Errorf("failed to create %s: %s", serverKeyAccount, err)
		}
	}

	log.Debugf("key account number: %d", serverKeyAccountNumber)

	return nil
}

func (s *service) loadServerAddress(
	wallet *btcwallet.BtcWallet,
) (waddrmgr.ManagedPubKeyAddress, error) {
	addrs, err := wallet.ListAddresses(string(serverKeyAccount), false)
	if err != nil {
		return nil, err
	}

	for info, addrs := range addrs {
		if info.AccountName != string(serverKeyAccount) {
			continue
		}

		for _, addr := range addrs {
			if addr.Internal {
				continue
			}

			splittedPath := strings.Split(addr.DerivationPath, "/")
			last := splittedPath[len(splittedPath)-1]
			if last == "0" {
				decoded, err := btcutil.DecodeAddress(addr.Address, s.cfg.chainParams())
				if err != nil {
					return nil, err
				}

				info, err := wallet.AddressInfo(decoded)
				if err != nil {
					return nil, err
				}

				managedPubkeyAddr, ok := info.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return nil, fmt.Errorf("failed to cast address to managed pubkey address")
				}

				return managedPubkeyAddr, nil
			}
		}
	}

	serverKeyAddr, err := wallet.NewAddress(lnwallet.TaprootPubkey, false, string(serverKeyAccount))
	if err != nil {
		return nil, err
	}

	info, err := wallet.AddressInfo(serverKeyAddr)
	if err != nil {
		return nil, err
	}

	managedAddr, ok := info.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, fmt.Errorf("failed to cast address to managed pubkey address")
	}

	return managedAddr, nil
}

func (s *service) loadForfeitAddress(
	wallet *btcwallet.BtcWallet,
) (string, error) {
	addrs, err := wallet.ListAddresses(string(mainAccount), false)
	if err != nil {
		return "", err
	}

	for info, addrs := range addrs {
		if info.KeyScope != p2wpkhKeyScope {
			continue
		}

		if info.AccountName != string(mainAccount) {
			continue
		}

		for _, addr := range addrs {
			if addr.Internal {
				continue
			}

			splittedPath := strings.Split(addr.DerivationPath, "/")
			last := splittedPath[len(splittedPath)-1]
			if last == "0" {
				return addr.Address, nil
			}
		}
	}

	addr, err := wallet.NewAddress(lnwallet.WitnessPubKey, false, string(mainAccount))
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

func (s *service) deriveNextAddress() (btcutil.Address, error) {
	if !s.isLoaded() {
		return nil, ErrNotLoaded
	}

	return s.wallet.NewAddress(lnwallet.WitnessPubKey, false, string(mainAccount))
}

func (s *service) safeCheck() error {
	if !s.isLoaded() {
		if s.isInitialized() {
			return ErrNotUnlocked
		}
		return ErrNotReady
	}
	if !s.isSynced {
		return ErrNotSynced
	}
	return nil
}

func (s *service) isLoaded() bool {
	return s.wallet != nil
}

func (s *service) isInitialized() bool {
	opts := []btcwallet.LoaderOption{btcwallet.LoaderWithLocalWalletDB(s.cfg.Datadir, false, time.Minute)}
	loader, err := btcwallet.NewWalletLoader(
		s.cfg.chainParams(), 0, opts...,
	)
	if err != nil {
		return false
	}

	exist, _ := loader.WalletExists()

	return exist
}

func (s *service) listUtxos(scope waddrmgr.KeyScope, confirmedOnly bool) ([]*wallet.TransactionOutput, error) {
	w := s.wallet.InternalWallet()

	accountNumber, err := w.AccountNumber(scope, string(mainAccount))
	if err != nil {
		return nil, err
	}

	requiredConfirmations := int32(0)
	if confirmedOnly {
		requiredConfirmations = 1
	}

	utxos, err := w.UnspentOutputs(wallet.OutputSelectionPolicy{
		Account:               accountNumber,
		RequiredConfirmations: requiredConfirmations,
	})
	if err != nil {
		return nil, err
	}

	filtered := make([]*wallet.TransactionOutput, 0, len(utxos))
	for _, utxo := range utxos {
		scriptClass, _, _, err := txscript.ExtractPkScriptAddrs(utxo.Output.PkScript, w.ChainParams())
		if err != nil {
			return nil, err
		}

		switch scope {
		case p2wpkhKeyScope:
			if scriptClass == txscript.WitnessV0PubKeyHashTy {
				filtered = append(filtered, utxo)
			}
		case p2trKeyScope:
			if scriptClass == txscript.WitnessV1TaprootTy {
				filtered = append(filtered, utxo)
			}
		}
	}
	return filtered, nil
}

func createOrOpenWalletDB(path string) (walletdb.DB, error) {
	db, err := walletdb.Open("bdb", path, true, 60*time.Second)
	if err == nil {
		return db, nil
	}
	if !errors.Is(err, walletdb.ErrDbDoesNotExist) {
		return nil, err
	}
	return walletdb.Create("bdb", path, true, 60*time.Second)
}

func fromOutputScript(script []byte, netParams *chaincfg.Params) (btcutil.Address, error) {
	return btcutil.NewAddressTaproot(script[2:], netParams)
}

func logger(subsystem string) btclog.Logger {
	logger := btclog.NewBackend(log.StandardLogger().Writer()).Logger(subsystem)
	logger.SetLevel(btclog.LevelWarn)
	return logger
}
