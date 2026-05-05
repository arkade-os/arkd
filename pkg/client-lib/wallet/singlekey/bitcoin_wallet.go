package singlekeywallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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

func (w *bitcoinWallet) NewKey(ctx context.Context) (*wallet.KeyRef, error) {
	if w.walletData == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}
	return &wallet.KeyRef{
		Id:     "m/0/0",
		PubKey: w.walletData.PubKey,
	}, nil
}

func (w *bitcoinWallet) GetKey(ctx context.Context, _ string) (*wallet.KeyRef, error) {
	if w.walletData == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}
	return &wallet.KeyRef{
		Id:     "m/0/0",
		PubKey: w.walletData.PubKey,
	}, nil
}

func (w *bitcoinWallet) ListKeys(ctx context.Context) ([]wallet.KeyRef, error) {
	key, err := w.GetKey(ctx, "")
	if err != nil {
		return nil, err
	}
	return []wallet.KeyRef{*key}, nil
}
func (s *bitcoinWallet) SignTransaction(
	ctx context.Context, tx string, _ map[string]string,
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

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for i := range updater.Upsbt.Inputs {
		in := updater.Upsbt.Inputs[i]
		outpoint := updater.Upsbt.UnsignedTx.TxIn[i].PreviousOutPoint
		switch {
		case in.WitnessUtxo != nil:
			prevouts[outpoint] = in.WitnessUtxo
		case in.NonWitnessUtxo != nil && int(outpoint.Index) < len(in.NonWitnessUtxo.TxOut):
			prevouts[outpoint] = in.NonWitnessUtxo.TxOut[outpoint.Index]
		default:
			return "", fmt.Errorf(
				"input %d: missing prevout (WitnessUtxo or NonWitnessUtxo) for %s:%d",
				i, outpoint.Hash, outpoint.Index,
			)
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
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

func (w *bitcoinWallet) NewVtxoTreeSigner(ctx context.Context) (tree.SignerSession, error) {
	if w.walletData == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}
	if w.IsLocked() {
		return nil, fmt.Errorf("wallet is locked")
	}

	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return tree.NewTreeSignerSession(key), nil
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
