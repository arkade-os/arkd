package batchsessionhandler

import (
	"bytes"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func addSignatureToTxTree(
	event clientlib.TreeSignatureEvent, txTree *tree.TxTree,
) error {
	if event.BatchIndex != 0 {
		return fmt.Errorf("batch index %d is not 0", event.BatchIndex)
	}

	decodedSig, err := hex.DecodeString(event.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %s", err)
	}

	sig, err := schnorr.ParseSignature(decodedSig)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %s", err)
	}

	return txTree.Apply(func(g *tree.TxTree) (bool, error) {
		if g.Root.UnsignedTx.TxID() != event.Txid {
			return true, nil
		}

		g.Root.Inputs[0].TaprootKeySpendSig = sig.Serialize()
		return false, nil
	})
}

func getBatchExpiryLocktime(expiry uint32) arklib.RelativeLocktime {
	if expiry >= 512 {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: expiry}
	}
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: expiry}
}

func validateReceivers(
	network arklib.Network, ptx *psbt.Packet, receivers []clientlib.Receiver, vtxoTree *tree.TxTree,
) error {
	netParams := clientlib.ToBitcoinNetwork(network)
	for _, receiver := range receivers {
		isOnChain, onchainScript, err := clientlib.ParseBitcoinAddress(receiver.To, netParams)
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
	ptx *psbt.Packet, receiver clientlib.Receiver, onchainScript []byte,
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

func validateOffchainReceiver(vtxoTree *tree.TxTree, receiver clientlib.Receiver) error {
	found := false

	rcvAddr, err := arklib.DecodeAddressV0(receiver.To)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(rcvAddr.VtxoTapKey)

	leaves := vtxoTree.Leaves()
	for _, leaf := range leaves {
		for outputIndex, output := range leaf.UnsignedTx.TxOut {
			if len(output.PkScript) == 0 {
				continue
			}

			if bytes.Equal(output.PkScript[2:], vtxoTapKey) {
				if output.Value != int64(receiver.Amount) {
					continue
				}

				found = true
				if len(receiver.Assets) > 0 {
					if err := validateAssetOutputs(leaf.UnsignedTx, outputIndex, receiver); err != nil {
						return err
					}
				}
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

func validateAssetOutputs(tx *wire.MsgTx, outputIndex int, receiver clientlib.Receiver) error {
	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil {
		return err
	}
	assetPacket := ext.GetAssetPacket()
	if len(assetPacket) == 0 {
		return fmt.Errorf("no asset packet found in transaction")
	}

	// For each expected asset, verify the asset group exists and contains the correct output
	for _, expectedAsset := range receiver.Assets {
		found := false
		for _, assetGroup := range assetPacket {
			// Skip issuances
			if assetGroup.IsIssuance() {
				continue
			}

			if assetGroup.AssetId.String() == expectedAsset.AssetId {
				if err := validateAssetGroupOutput(assetGroup.Outputs, outputIndex, expectedAsset); err != nil {
					return err
				}
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("asset group not found in batch leaf")
		}
	}

	return nil
}

func validateAssetGroupOutput(
	outputs []asset.AssetOutput,
	outputIndex int,
	expectedAsset clientlib.Asset,
) error {
	found := false
	for _, output := range outputs {
		if int(output.Vout) != outputIndex {
			continue
		}

		if output.Amount != expectedAsset.Amount {
			return fmt.Errorf(
				"invalid asset output amount: got %d, want %d",
				output.Amount,
				expectedAsset.Amount,
			)
		}
		found = true
		break
	}

	if !found {
		return fmt.Errorf("asset output not found in asset group: %s", expectedAsset.AssetId)
	}
	return nil
}

func isOnchainOnly(receivers []clientlib.Receiver) bool {
	for _, receiver := range receivers {
		if !receiver.IsOnchain() {
			return false
		}
	}

	return true
}
