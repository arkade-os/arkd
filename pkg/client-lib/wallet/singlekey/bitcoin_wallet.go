package singlekeywallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-bip32"
)

type bitcoinWallet struct {
	*singlekeyWallet
}

func NewBitcoinWallet(walletStore walletstore.WalletStore) (wallet.WalletService, error) {
	walletData, err := walletStore.GetWallet()
	if err != nil {
		return nil, err
	}
	return &bitcoinWallet{
		&singlekeyWallet{
			walletStore: walletStore,
			walletData:  walletData,
		},
	}, nil
}

func (w *bitcoinWallet) NewKey(
	ctx context.Context, opts ...wallet.KeyOption,
) (*wallet.KeyRef, error) {
	if w.walletData == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}
	return &wallet.KeyRef{PubKey: w.walletData.PubKey}, nil
}

func (w *bitcoinWallet) GetKey(
	ctx context.Context, opts ...wallet.KeyOption,
) (*wallet.KeyRef, error) {
	if w.walletData == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}
	return &wallet.KeyRef{PubKey: w.walletData.PubKey}, nil
}

func (w *bitcoinWallet) ListKeys(ctx context.Context) ([]wallet.KeyRef, error) {
	key, err := w.GetKey(ctx)
	if err != nil {
		return nil, err
	}
	return []wallet.KeyRef{*key}, nil
}
func (s *bitcoinWallet) SignTransaction(
	ctx context.Context, explorerSvc explorer.Explorer, tx string, _ map[string]string,
) (string, error) {
	if s.walletData == nil {
		return "", fmt.Errorf("wallet not initialized")
	}

	if s.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

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

	onchainPkScript, err := script.P2TRScript(
		txscript.ComputeTaprootKeyNoScript(s.walletData.PubKey),
	)
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
				updater.Upsbt.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(
					txscript.ComputeTaprootKeyNoScript(s.walletData.PubKey),
				)
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
		closure, err := script.DecodeClosure(leaf.Script)
		if err != nil {
			// skip unknown leaf
			continue
		}

		sign := false

		switch c := closure.(type) {
		case *script.CSVMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *script.MultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *script.CLTVMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		case *script.ConditionMultisigClosure:
			for _, key := range c.PubKeys {
				if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
					sign = true
					break
				}
			}
		}

		if sign {
			hash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()

			preimage, err := txscript.CalcTapscriptSignaturehash(
				txsighashes,
				input.SighashType,
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
				updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = make(
					[]*psbt.TaprootScriptSpendSig,
					0,
				)
			}

			updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = append(
				updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig,
				&psbt.TaprootScriptSpendSig{
					XOnlyPubKey: myPubkey,
					LeafHash:    hash.CloneBytes(),
					Signature:   sig.Serialize(),
					SigHash:     input.SighashType,
				},
			)
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
		input.SighashType,
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
	if w.walletData == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}
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

	derivedPrivKey, _ := btcec.PrivKeyFromBytes(currentKey.Key)
	return tree.NewTreeSignerSession(derivedPrivKey), nil
}

func (w *bitcoinWallet) SignMessage(
	ctx context.Context, message []byte,
) (string, error) {
	if w.walletData == nil {
		return "", fmt.Errorf("wallet not initialized")
	}
	if w.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	sig, err := schnorr.Sign(w.privateKey, message)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sig.Serialize()), nil
}
