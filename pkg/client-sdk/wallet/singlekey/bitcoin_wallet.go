package singlekeywallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-bip32"
)

type bitcoinWallet struct {
	*singlekeyWallet
}

func NewBitcoinWallet(
	configStore types.ConfigStore, walletStore walletstore.WalletStore,
) (wallet.WalletService, error) {
	walletData, err := walletStore.GetWallet()
	if err != nil {
		return nil, err
	}
	return &bitcoinWallet{
		&singlekeyWallet{
			configStore: configStore,
			walletStore: walletStore,
			walletData:  walletData,
		},
	}, nil
}

func (w *bitcoinWallet) GetAddresses(
	ctx context.Context,
) ([]string, []wallet.TapscriptsAddress, []wallet.TapscriptsAddress, []wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getArkAddresses(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	encodedOffchainAddr, err := offchainAddr.Address.EncodeV0()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	netParams := utils.ToBitcoinNetwork(data.Network)

	redemptionAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(offchainAddr.Address.VtxoTapKey),
		&netParams,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	offchainAddrs := []wallet.TapscriptsAddress{
		{
			Tapscripts: offchainAddr.Tapscripts,
			Address:    encodedOffchainAddr,
		},
	}
	boardingAddrs := []wallet.TapscriptsAddress{
		{
			Tapscripts: boardingAddr.Tapscripts,
			Address:    boardingAddr.Address,
		},
	}
	redemptionAddrs := []wallet.TapscriptsAddress{
		{
			Tapscripts: offchainAddr.Tapscripts,
			Address:    redemptionAddr.EncodeAddress(),
		},
	}

	onchainAddr, err := w.getP2TRAddress(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return []string{onchainAddr.EncodeAddress()}, offchainAddrs, boardingAddrs, redemptionAddrs, nil
}

func (w *bitcoinWallet) NewAddress(
	ctx context.Context, _ bool,
) (string, *wallet.TapscriptsAddress, *wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getArkAddresses(ctx)
	if err != nil {
		return "", nil, nil, err
	}

	encodedOffchainAddr, err := offchainAddr.Address.EncodeV0()
	if err != nil {
		return "", nil, nil, err
	}

	onchainAddr, err := w.getP2TRAddress(ctx)
	if err != nil {
		return "", nil, nil, err
	}

	return onchainAddr.EncodeAddress(), &wallet.TapscriptsAddress{
		Tapscripts: offchainAddr.Tapscripts,
		Address:    encodedOffchainAddr,
	}, boardingAddr, nil
}

func (w *bitcoinWallet) NewAddresses(
	ctx context.Context, _ bool, num int,
) ([]string, []wallet.TapscriptsAddress, []wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getArkAddresses(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	offchainAddrs := make([]wallet.TapscriptsAddress, 0, num)
	boardingAddrs := make([]wallet.TapscriptsAddress, 0, num)
	for i := 0; i < num; i++ {
		encodedOffchainAddr, err := offchainAddr.Address.EncodeV0()
		if err != nil {
			return nil, nil, nil, err
		}

		offchainAddrs = append(offchainAddrs, wallet.TapscriptsAddress{
			Tapscripts: offchainAddr.Tapscripts,
			Address:    encodedOffchainAddr,
		})
		boardingAddrs = append(boardingAddrs, wallet.TapscriptsAddress{
			Tapscripts: boardingAddr.Tapscripts,
			Address:    boardingAddr.Address,
		})
	}

	onchainAddrs := make([]string, 0, num)
	for i := 0; i < num; i++ {
		onchainAddr, err := w.getP2TRAddress(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		onchainAddrs = append(onchainAddrs, onchainAddr.EncodeAddress())
	}

	return onchainAddrs, offchainAddrs, boardingAddrs, nil
}

func (s *bitcoinWallet) SignTransaction(
	ctx context.Context, explorerSvc explorer.Explorer, tx string,
) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	for i, input := range updater.Upsbt.UnsignedTx.TxIn {
		if updater.Upsbt.Inputs[i].WitnessUtxo != nil {
			continue
		}

		prevoutTxHex, err := explorerSvc.GetTxHex(input.PreviousOutPoint.Hash.String())
		if err != nil {
			return "", err
		}

		var prevoutTx wire.MsgTx

		if err := prevoutTx.Deserialize(hex.NewDecoder(strings.NewReader(prevoutTxHex))); err != nil {
			return "", err
		}

		utxo := prevoutTx.TxOut[input.PreviousOutPoint.Index]
		if utxo == nil {
			return "", fmt.Errorf("witness utxo not found")
		}

		if err := updater.AddInWitnessUtxo(utxo, i); err != nil {
			return "", err
		}

		if err := updater.AddInSighashType(txscript.SigHashDefault, i); err != nil {
			return "", err
		}
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for i, input := range updater.Upsbt.Inputs {
		outpoint := updater.Upsbt.UnsignedTx.TxIn[i].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(
		prevouts,
	)

	txsighashes := txscript.NewTxSigHashes(updater.Upsbt.UnsignedTx, prevoutFetcher)

	onchainPkScript, err := common.P2TRScript(txscript.ComputeTaprootKeyNoScript(s.walletData.PubKey))
	if err != nil {
		return "", err
	}

	for i, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) > 0 {
			if err := s.signTapscriptSpend(updater, input, i, txsighashes, prevoutFetcher); err != nil {
				return "", err
			}
			continue
		}

		if input.WitnessUtxo != nil {
			// onchain P2TR
			if bytes.Equal(input.WitnessUtxo.PkScript, onchainPkScript) {
				updater.Upsbt.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(s.walletData.PubKey))
				input = updater.Upsbt.Inputs[i]
			}
		}

		// taproot key path spend
		if len(input.TaprootInternalKey) > 0 {
			if err := s.signTaprootKeySpend(updater, input, i, txsighashes, prevoutFetcher); err != nil {
				return "", err
			}
			continue
		}

	}

	return ptx.B64Encode()
}

func (w *bitcoinWallet) signTapscriptSpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
) error {
	myPubkey := schnorr.SerializePubKey(w.walletData.PubKey)

	for _, leaf := range input.TaprootLeafScript {
		closure, err := tree.DecodeClosure(leaf.Script)
		if err != nil {
			// skip unknown leaf
			continue
		}

		sign := false

		switch c := closure.(type) {
		case *tree.CSVMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *tree.MultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *tree.CLTVMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *tree.ConditionMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		}

		if sign {
			if err := updater.AddInSighashType(txscript.SigHashDefault, inputIndex); err != nil {
				return err
			}

			hash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()

			preimage, err := txscript.CalcTapscriptSignaturehash(
				txsighashes,
				txscript.SigHashDefault,
				updater.Upsbt.UnsignedTx,
				inputIndex,
				prevoutFetcher,
				txscript.NewBaseTapLeaf(leaf.Script),
			)
			if err != nil {
				return err
			}

			sig, err := schnorr.Sign(w.privateKey, preimage)
			if err != nil {
				return err
			}

			if len(updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig) == 0 {
				updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = make([]*psbt.TaprootScriptSpendSig, 0)
			}

			updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = append(updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
				XOnlyPubKey: myPubkey,
				LeafHash:    hash.CloneBytes(),
				Signature:   sig.Serialize(),
				SigHash:     txscript.SigHashDefault,
			})
		}
	}

	return nil
}

func (w *bitcoinWallet) signTaprootKeySpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
) error {
	if len(input.TaprootKeySpendSig) > 0 {
		// already signed, skip
		return nil
	}

	xOnlyPubkey := schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(w.walletData.PubKey))
	if !bytes.Equal(xOnlyPubkey, input.TaprootInternalKey) {
		// not the wallet's key, skip
		return nil
	}

	preimage, err := txscript.CalcTaprootSignatureHash(
		txsighashes,
		txscript.SigHashDefault,
		updater.Upsbt.UnsignedTx,
		inputIndex,
		prevoutFetcher,
	)

	if err != nil {
		return err
	}

	sig, err := schnorr.Sign(txscript.TweakTaprootPrivKey(*w.privateKey, nil), preimage)
	if err != nil {
		return err
	}

	updater.Upsbt.Inputs[inputIndex].TaprootKeySpendSig = sig.Serialize()

	return nil
}

func (w *bitcoinWallet) NewVtxoTreeSigner(
	ctx context.Context, derivationPath string,
) (tree.SignerSession, error) {
	if w.IsLocked() {
		return nil, fmt.Errorf("wallet is locked")
	}

	if len(derivationPath) == 0 {
		return nil, fmt.Errorf("derivation path is required")
	}

	// convert private key to BIP32 master key format
	// TODO UNSAFE ?
	privKeyBytes := w.privateKey.Serialize()
	masterKey, err := bip32.NewMasterKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	paths := strings.Split(strings.TrimPrefix(derivationPath, "m/"), "/")
	currentKey := masterKey

	for _, pathComponent := range paths {
		index := uint32(0)
		isHardened := strings.HasSuffix(pathComponent, "'")
		if isHardened {
			pathComponent = strings.TrimSuffix(pathComponent, "'")
		}

		if _, err := fmt.Sscanf(pathComponent, "%d", &index); err != nil {
			return nil, fmt.Errorf("invalid path component %s: %w", pathComponent, err)
		}

		if isHardened {
			index += bip32.FirstHardenedChild
		}

		currentKey, err = currentKey.NewChildKey(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key: %w", err)
		}
	}

	derivedPrivKey := secp256k1.PrivKeyFromBytes(currentKey.Key)
	return tree.NewTreeSignerSession(derivedPrivKey), nil
}

func (w *bitcoinWallet) SignMessage(
	ctx context.Context, message []byte,
) (string, error) {
	if w.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	sig, err := schnorr.Sign(w.privateKey, message)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sig.Serialize()), nil
}

type addressWithTapscripts struct {
	Address    common.Address
	Tapscripts []string
}

func (w *bitcoinWallet) getP2TRAddress(
	ctx context.Context,
) (*btcutil.AddressTaproot, error) {
	if w.walletData == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, fmt.Errorf("config not set, cannot create P2TR address")
	}

	netParams := utils.ToBitcoinNetwork(data.Network)

	tapKey := txscript.ComputeTaprootKeyNoScript(w.walletData.PubKey)
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &netParams)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

func (w *bitcoinWallet) getArkAddresses(
	ctx context.Context,
) (
	*addressWithTapscripts,
	*wallet.TapscriptsAddress,
	error,
) {
	if w.walletData == nil {
		return nil, nil, fmt.Errorf("wallet not initialized")
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return nil, nil, err
	}

	netParams := utils.ToBitcoinNetwork(data.Network)

	defaultVtxoScript := tree.NewDefaultVtxoScript(
		w.walletData.PubKey,
		data.SignerPubKey,
		data.UnilateralExitDelay,
	)

	vtxoTapKey, _, err := defaultVtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	offchainAddress := &common.Address{
		HRP:        data.Network.Addr,
		Signer:     data.SignerPubKey,
		VtxoTapKey: vtxoTapKey,
	}

	boardingVtxoScript := tree.NewDefaultVtxoScript(
		w.walletData.PubKey,
		data.SignerPubKey,
		data.BoardingExitDelay,
	)

	boardingTapKey, _, err := boardingVtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	boardingAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(boardingTapKey),
		&netParams,
	)
	if err != nil {
		return nil, nil, err
	}

	tapscripts, err := defaultVtxoScript.Encode()
	if err != nil {
		return nil, nil, err
	}

	boardingTapscripts, err := boardingVtxoScript.Encode()
	if err != nil {
		return nil, nil, err
	}

	return &addressWithTapscripts{
			Address:    *offchainAddress,
			Tapscripts: tapscripts,
		},
		&wallet.TapscriptsAddress{
			Tapscripts: boardingTapscripts,
			Address:    boardingAddr.EncodeAddress(),
		},
		nil
}
