package txbuilder

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func sweepTransaction(
	ctx context.Context, wallet ports.WalletService, inputs []ports.TxInput,
) (txid string, txhex string, err error) {
	ins := make([]*wire.OutPoint, 0)
	sequences := make([]uint32, 0)

	for _, input := range inputs {
		hash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return "", "", err
		}

		ins = append(ins, &wire.OutPoint{
			Hash:  *hash,
			Index: input.Index,
		})

		sequence := wire.MaxTxInSequenceNum

		if input.TapscriptLeaf != nil {
			tapscriptBytes, err := hex.DecodeString(input.TapscriptLeaf.Tapscript)
			if err != nil {
				return "", "", err
			}

			sweepClosure := script.CSVMultisigClosure{}
			valid, err := sweepClosure.Decode(tapscriptBytes)
			if err != nil {
				return "", "", err
			}

			if !valid {
				return "", "", fmt.Errorf("invalid csv script, cannot build sweep transaction")
			}

			sequence, err = arklib.BIP68Sequence(sweepClosure.Locktime)
			if err != nil {
				return "", "", err
			}
		}

		sequences = append(sequences, sequence)
	}

	ptx, err := psbt.New(ins, nil, 2, 0, sequences)
	if err != nil {
		return "", "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", "", err
	}

	amount := int64(0)

	tapscriptInputIndexes := make([]int, 0)

	for i, input := range inputs {
		if input.TapscriptLeaf != nil {
			tapscriptBytes, err := hex.DecodeString(input.TapscriptLeaf.Tapscript)
			if err != nil {
				return "", "", err
			}

			controlBlock, err := hex.DecodeString(input.TapscriptLeaf.ControlBlock)
			if err != nil {
				return "", "", err
			}

			internalKeyBytes, err := hex.DecodeString(input.TapscriptLeaf.InternalKey)
			if err != nil {
				return "", "", err
			}
			internalKey, err := btcec.ParsePubKey(internalKeyBytes)
			if err != nil {
				return "", "", err
			}

			ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
				{
					ControlBlock: controlBlock,
					Script:       tapscriptBytes,
					LeafVersion:  txscript.BaseLeafVersion,
				},
			}

			ptx.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(
				internalKey,
			)

			tapscriptInputIndexes = append(tapscriptInputIndexes, i)
		}

		inputAmount := int64(input.Value)
		amount += inputAmount

		prevoutScript, err := hex.DecodeString(input.Script)
		if err != nil {
			return "", "", err
		}

		prevout := &wire.TxOut{
			Value:    inputAmount,
			PkScript: prevoutScript,
		}

		if err := updater.AddInWitnessUtxo(prevout, i); err != nil {
			return "", "", err
		}
	}

	sweepAddress, err := wallet.DeriveAddresses(ctx, 1)
	if err != nil {
		return "", "", err
	}

	addr, err := btcutil.DecodeAddress(sweepAddress[0], nil)
	if err != nil {
		return "", "", err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", "", err
	}

	ptx.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    amount,
		PkScript: script,
	})
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})

	b64, err := ptx.B64Encode()
	if err != nil {
		return "", "", err
	}

	fees, err := wallet.EstimateFees(ctx, b64)
	if err != nil {
		return "", "", err
	}

	dustLimit, err := wallet.GetDustAmount(ctx)
	if err != nil {
		return "", "", err
	}

	if amount-int64(fees) < int64(dustLimit) {
		return "", "", fmt.Errorf(
			"insufficient funds (%d) to cover fees (%d) for sweep transaction (dust limit: %d)",
			amount,
			fees,
			dustLimit,
		)
	}

	ptx.UnsignedTx.TxOut[0].Value = amount - int64(fees)

	sweepPsbtBase64, err := ptx.B64Encode()
	if err != nil {
		return "", "", err
	}

	if len(tapscriptInputIndexes) > 0 {
		sweepPsbtBase64, err = wallet.SignTransactionTapscript(
			ctx,
			sweepPsbtBase64,
			tapscriptInputIndexes,
		)
		if err != nil {
			return "", "", err
		}
	}

	signedTxHex, err := wallet.SignTransaction(ctx, sweepPsbtBase64, true)
	if err != nil {
		return "", "", err
	}

	return ptx.UnsignedTx.TxID(), signedTxHex, nil
}
