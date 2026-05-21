package batchsession

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

// SettleArgs configures a Settle call: the BoardingUtxos and Vtxos to settle
// into a fresh vtxo at ReceiverAddr. ExpiryThreshold (in seconds) filters out
// vtxos expiring later than the threshold. FeeEstimator sizes the change
// output; SignTx signs the intent proof; Client/ServerInfo are used to talk
// to the server.
type SettleArgs struct {
	Client        clientlib.Client
	ServerInfo    clientlib.Info
	SignTx        clientlib.SignFn
	BoardingUtxos []clientlib.Utxo
	Vtxos         []clientlib.Vtxo
	ReceiverAddr  string
}

func (a SettleArgs) validate() error {
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx function")
	}
	if len(a.Vtxos) <= 0 && len(a.BoardingUtxos) <= 0 {
		return fmt.Errorf("missing funds to settle")
	}
	if len(a.ReceiverAddr) <= 0 {
		return fmt.Errorf("missing receiver")
	}
	if a.ServerInfo.Dust == 0 {
		return fmt.Errorf("missing server info")
	}
	return nil
}

// Settle performs the full lifecycle of refreshing vtxos and/or boarding utxos
// into a new vtxo via a batch session: selects funds, then builds, signs,
// submits the register intent, handles batch events, and finalizes the
// commitment transaction via JoinBatch.
func Settle(ctx context.Context, args SettleArgs, opts ...Option) (*BatchTxRes, error) {
	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	o := newOptions()
	for _, opt := range opts {
		if err := opt.apply(o); err != nil {
			return nil, err
		}
	}

	feeEstimator, err := arkfee.New(args.ServerInfo.Fees.IntentFees)
	if err != nil {
		return nil, err
	}

	vtxos, boardingUtxos, outputs, err := selectFunds(
		ctx, feeEstimator, args.Vtxos, args.BoardingUtxos,
		nil, args.ReceiverAddr, o.expiryThreshold, args.ServerInfo.Dust,
	)
	if err != nil {
		return nil, err
	}

	return joinBatchWithRetry(ctx, JoinBatchArgs{
		BaseArgs: BaseArgs{
			Vtxos:         vtxos,
			BoardingUtxos: boardingUtxos,
			Outputs:       outputs,
			SignTx:        args.SignTx,
		},
		Client:     args.Client,
		ServerInfo: args.ServerInfo,
	}, opts...)
}

func selectFunds(
	ctx context.Context, feeEstimator *arkfee.Estimator,
	vtxos []clientlib.Vtxo, boardingUtxos []clientlib.Utxo, outputs []clientlib.Receiver,
	receiverAddr string, expiryThreshold int64, dust uint64,
) ([]clientlib.Vtxo, []clientlib.Utxo, []clientlib.Receiver, error) {
	if expiryThreshold > 0 {
		vtxos = filterVtxosByExpiry(vtxos, expiryThreshold)
	}

	outs := make([]clientlib.Receiver, len(outputs))
	copy(outs, outputs)

	// No outputs means settle vtxos or boarding utxos, therefore we have to create the
	// clientlib.Receiver output from the receiver address passed in Settle or RedeemNotes args
	if len(outputs) <= 0 {
		// Gather all asset balances from inputs to carry them forward
		assetBalances := make(map[string]uint64)
		for _, vtxo := range vtxos {
			for _, a := range vtxo.Assets {
				assetBalances[a.AssetId] += a.Amount
			}
		}
		for _, utxo := range boardingUtxos {
			for _, a := range utxo.Assets {
				assetBalances[a.AssetId] += a.Amount
			}
		}

		assets := make([]clientlib.Asset, 0, len(assetBalances))
		for assetId, amount := range assetBalances {
			assets = append(assets, clientlib.Asset{
				AssetId: assetId,
				Amount:  amount,
			})
		}

		outs = []clientlib.Receiver{{
			To:     receiverAddr,
			Amount: 0,
			Assets: assets,
		}}
	}

	if len(outs) == 1 && outs[0].Amount <= 0 {
		totalAmount, totalFeeAmount := uint64(0), uint64(0)
		for _, utxo := range boardingUtxos {
			totalAmount += utxo.Amount
			fees, err := feeEstimator.EvalOnchainInput(utxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, nil, err
			}
			totalFeeAmount += uint64(fees.ToSatoshis())
		}

		for _, vtxo := range vtxos {
			totalAmount += vtxo.Amount
			fees, err := feeEstimator.EvalOffchainInput(vtxo.ToArkFeeInput())
			if err != nil {
				return nil, nil, nil, err
			}
			totalFeeAmount += uint64(fees.ToSatoshis())
		}
		if totalFeeAmount >= totalAmount {
			return nil, nil, nil, fmt.Errorf(
				"fees (%d) exceed total amount (%d)", totalFeeAmount, totalAmount,
			)
		}
		outs[0].Amount = totalAmount - totalFeeAmount
	}

	selectedBoardingUtxos, selectedVtxos, changeAmount, err := clientlib.CoinSelect(
		boardingUtxos, vtxos, outs, dust, feeEstimator,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	if changeAmount > 0 {
		outs = append(outs, clientlib.Receiver{
			To:     receiverAddr,
			Amount: changeAmount,
		})
	}
	return selectedVtxos, selectedBoardingUtxos, outs, nil
}
