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
	configStore types.ConfigStore, explorerSvc explorer.Explorer, walletStore walletstore.WalletStore,
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
			explorerSvc: explorerSvc,
		},
	}, nil
}

func (w *bitcoinWallet) GetAddresses(
	ctx context.Context,
) ([]wallet.TapscriptsAddress, []wallet.TapscriptsAddress, []wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	encodedOffchainAddr, err := offchainAddr.Address.Encode()
	if err != nil {
		return nil, nil, nil, err
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	netParams := utils.ToBitcoinNetwork(data.Network)

	redemptionAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(offchainAddr.Address.VtxoTapKey),
		&netParams,
	)
	if err != nil {
		return nil, nil, nil, err
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
	return offchainAddrs, boardingAddrs, redemptionAddrs, nil
}

func (w *bitcoinWallet) NewAddress(
	ctx context.Context, _ bool,
) (*wallet.TapscriptsAddress, *wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, err
	}

	encodedOffchainAddr, err := offchainAddr.Address.Encode()
	if err != nil {
		return nil, nil, err
	}

	// Track boarding address
	if err := w.explorerSvc.TrackAddress(
		boardingAddr.Address); err != nil {
		return nil, nil, fmt.Errorf("failed to track boarding address: %w", err)
	}

	return &wallet.TapscriptsAddress{
		Tapscripts: offchainAddr.Tapscripts,
		Address:    encodedOffchainAddr,
	}, boardingAddr, nil
}

func (w *bitcoinWallet) NewAddresses(
	ctx context.Context, _ bool, num int,
) ([]wallet.TapscriptsAddress, []wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Track boarding address
	if err := w.explorerSvc.TrackAddress(
		boardingAddr.Address); err != nil {
		return nil, nil, fmt.Errorf("failed to track boarding address: %w", err)
	}

	offchainAddrs := make([]wallet.TapscriptsAddress, 0, num)
	boardingAddrs := make([]wallet.TapscriptsAddress, 0, num)
	for i := 0; i < num; i++ {
		encodedOffchainAddr, err := offchainAddr.Address.Encode()
		if err != nil {
			return nil, nil, err
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
	return offchainAddrs, boardingAddrs, nil
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
	myPubkey := schnorr.SerializePubKey(s.walletData.PubKey)

	for i, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) > 0 {
			for _, leaf := range input.TaprootLeafScript {
				closure, err := tree.DecodeClosure(leaf.Script)
				if err != nil {
					return "", err
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
					if err := updater.AddInSighashType(txscript.SigHashDefault, i); err != nil {
						return "", err
					}

					hash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()

					preimage, err := txscript.CalcTapscriptSignaturehash(
						txsighashes,
						txscript.SigHashDefault,
						ptx.UnsignedTx,
						i,
						prevoutFetcher,
						txscript.NewBaseTapLeaf(leaf.Script),
					)
					if err != nil {
						return "", err
					}

					sig, err := schnorr.Sign(s.privateKey, preimage)
					if err != nil {
						return "", err
					}

					if !sig.Verify(preimage, s.walletData.PubKey) {
						return "", fmt.Errorf("signature verification failed")
					}

					if len(updater.Upsbt.Inputs[i].TaprootScriptSpendSig) == 0 {
						updater.Upsbt.Inputs[i].TaprootScriptSpendSig = make([]*psbt.TaprootScriptSpendSig, 0)
					}

					updater.Upsbt.Inputs[i].TaprootScriptSpendSig = append(updater.Upsbt.Inputs[i].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
						XOnlyPubKey: myPubkey,
						LeafHash:    hash.CloneBytes(),
						Signature:   sig.Serialize(),
						SigHash:     txscript.SigHashDefault,
					})
				}
			}
		}

	}

	return ptx.B64Encode()
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

func (w *bitcoinWallet) getAddress(
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
		data.ServerPubKey,
		data.UnilateralExitDelay,
	)

	vtxoTapKey, _, err := defaultVtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	offchainAddress := &common.Address{
		HRP:        data.Network.Addr,
		Server:     data.ServerPubKey,
		VtxoTapKey: vtxoTapKey,
	}

	boardingVtxoScript := tree.NewDefaultVtxoScript(
		w.walletData.PubKey,
		data.ServerPubKey,
		common.RelativeLocktime{
			Type:  data.BoardingExitDelay.Type,
			Value: data.BoardingExitDelay.Value,
		},
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
