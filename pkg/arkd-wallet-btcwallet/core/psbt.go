package application

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	log "github.com/sirupsen/logrus"
)

var ANCHOR_PKSCRIPT = []byte{
	0x51, 0x02, 0x4e, 0x73,
}

func (s *service) signPsbt(packet *psbt.Packet, inputsToSign []int) ([]uint32, error) {
	updater, err := psbt.NewUpdater(packet)
	if err != nil {
		return nil, err
	}

	// try to set witness utxos for inputs that don't have one
	for idx, input := range packet.Inputs {
		if input.WitnessUtxo == nil {
			// try to fetch the utxo
			inputOutpoint := packet.UnsignedTx.TxIn[idx].PreviousOutPoint

			const retryAttempts = 5
			for i := 0; i < retryAttempts; i++ {
				prevoutTx, err := s.extraAPI.getTx(inputOutpoint.Hash.String())
				if err != nil {
					if i == retryAttempts-1 {
						return nil, err
					}

					log.WithError(err).Debugf("failed to fetch tx %s, attempt %d/%d", inputOutpoint.Hash.String(), i+1, retryAttempts)
					time.Sleep(2 * time.Second)
					continue
				}

				if len(prevoutTx.TxOut) <= int(inputOutpoint.Index) {
					return nil, fmt.Errorf("invalid prevout index %d for tx with %d outputs",
						inputOutpoint.Index, len(prevoutTx.TxOut))
				}

				if err := updater.AddInWitnessUtxo(prevoutTx.TxOut[inputOutpoint.Index], idx); err != nil {
					return nil, err
				}

				break
			}
		}
	}

	for idx, input := range packet.Inputs {
		if input.WitnessUtxo == nil {
			continue
		}

		if bytes.Equal(input.WitnessUtxo.PkScript, ANCHOR_PKSCRIPT) {
			// skip anchor inputs
			continue
		}

		script, err := txscript.ParsePkScript(input.WitnessUtxo.PkScript)
		if err != nil {
			return nil, fmt.Errorf("error detecting signing method, "+
				"couldn't parse pkScript: %v", err)
		}

		sighashType := txscript.SigHashAll

		if script.Class() == txscript.WitnessV1TaprootTy {
			sighashType = txscript.SigHashDefault
		}

		if err := updater.AddInSighashType(sighashType, idx); err != nil {
			return nil, err
		}
	}

	prevoutTx := packet.UnsignedTx
	signedInputs := make([]uint32, 0)
	for idx := range prevoutTx.TxIn {
		in := &packet.Inputs[idx]

		// skip if the input does not have a witness utxo
		if in.WitnessUtxo == nil {
			continue
		}

		// skip if already signed
		if len(in.FinalScriptWitness) > 0 {
			continue
		}

		if len(inputsToSign) > 0 {
			found := false
			for _, i := range inputsToSign {
				if i == idx {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		var managedAddress waddrmgr.ManagedPubKeyAddress
		isTaproot := txscript.IsPayToTaproot(in.WitnessUtxo.PkScript)

		if len(in.TaprootLeafScript) > 0 {
			managedAddress = s.serverKeyAddr
		} else {
			var err error
			managedAddress, _, _, err = s.wallet.ScriptForOutput(in.WitnessUtxo)
			if err != nil {
				log.WithError(err).Debugf(
					"failed to fetch address for input %d with script %s",
					idx, hex.EncodeToString(in.WitnessUtxo.PkScript),
				)
				continue
			}
		}

		signedInputs = append(signedInputs, uint32(idx))

		bip32Infos := derivationPathForAddress(managedAddress)
		packet.Inputs[idx].Bip32Derivation = []*psbt.Bip32Derivation{bip32Infos}

		if isTaproot {
			leafHashes := make([][]byte, 0, len(in.TaprootLeafScript))
			for _, leafScript := range in.TaprootLeafScript {
				leafHash := txscript.NewBaseTapLeaf(leafScript.Script).TapHash()
				leafHashes = append(leafHashes, leafHash[:])
			}

			xonlypubkey := schnorr.SerializePubKey(managedAddress.PubKey())

			packet.Inputs[idx].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
				{
					XOnlyPubKey:          xonlypubkey,
					MasterKeyFingerprint: bip32Infos.MasterKeyFingerprint,
					Bip32Path:            bip32Infos.Bip32Path,
					LeafHashes:           leafHashes,
				},
			}
		}
	}

	ins, err := s.wallet.SignPsbt(packet)
	if err != nil {
		return nil, err
	}

	// delete derivation paths to avoid duplicate keys error
	for idx := range signedInputs {
		packet.Inputs[idx].Bip32Derivation = nil
		packet.Inputs[idx].TaprootBip32Derivation = nil
	}

	return ins, nil
}

func derivationPathForAddress(addr waddrmgr.ManagedPubKeyAddress) *psbt.Bip32Derivation {
	keyscope, derivationInfos, _ := addr.DerivationInfo()

	return &psbt.Bip32Derivation{
		PubKey:               addr.PubKey().SerializeCompressed(),
		MasterKeyFingerprint: derivationInfos.MasterKeyFingerprint,
		Bip32Path: []uint32{
			keyscope.Purpose + hdkeychain.HardenedKeyStart,
			keyscope.Coin + hdkeychain.HardenedKeyStart,
			derivationInfos.Account,
			derivationInfos.Branch,
			derivationInfos.Index,
		},
	}
}
