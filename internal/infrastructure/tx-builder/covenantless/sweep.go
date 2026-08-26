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

// sweepInputLocktime derives the nSequence and the required nLockTime for a
// sweep input from its tapscript leaf.
//
// A legacy CSV leaf needs only a BIP68 sequence. An epoch leaf needs that plus an
// nLockTime at or after its expiry date. Both sequences are BIP68-encoded and so
// are non-final, which is also what CHECKLOCKTIMEVERIFY requires of its input.
func sweepInputLocktime(tapscript []byte) (sequence uint32, lockTime uint32, err error) {
	epoch := script.CLTVCSVMultisigClosure{}
	if valid, decodeErr := epoch.Decode(tapscript); decodeErr == nil && valid {
		seq, err := arklib.BIP68Sequence(epoch.UnrollGrace)
		if err != nil {
			return 0, 0, err
		}
		return seq, uint32(epoch.ExpiryDate), nil
	}

	legacy := script.CSVMultisigClosure{}
	valid, err := legacy.Decode(tapscript)
	if err != nil {
		return 0, 0, err
	}
	if !valid {
		return 0, 0, fmt.Errorf("unsupported sweep tapscript, cannot build sweep transaction")
	}

	seq, err := arklib.BIP68Sequence(legacy.Locktime)
	if err != nil {
		return 0, 0, err
	}
	return seq, 0, nil
}

func sweepTransaction(
	ctx context.Context, wallet ports.WalletService, inputs []ports.TxInput,
) (txid string, txhex string, err error) {
	ins := make([]*wire.OutPoint, 0)
	sequences := make([]uint32, 0)

	// One transaction carries one nLockTime, so it must satisfy the latest expiry
	// date among its inputs. Callers group inputs by maturity class: mixing a
	// future-dated epoch input into a batch of ready ones would stall them all.
	maxLockTime := uint32(0)

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

			seq, lockTime, err := sweepInputLocktime(tapscriptBytes)
			if err != nil {
				return "", "", err
			}

			sequence = seq
			if lockTime > maxLockTime {
				maxLockTime = lockTime
			}
		}

		sequences = append(sequences, sequence)
	}

	ptx, err := psbt.New(ins, nil, 2, maxLockTime, sequences)
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
