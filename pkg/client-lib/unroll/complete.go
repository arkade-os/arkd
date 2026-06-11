package unroll

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// CompleteUnrollArgs configures CompleteUnroll: spends the user's matured
// onchain Ark UTXOs (those past their exit delay) to Receiver and broadcasts
// the resulting transaction.
type CompleteUnrollArgs struct {
	Explorer   clientlib.Explorer
	SignTx     clientlib.SignFn
	ServerInfo clientlib.Info
	Utxos      []clientlib.Utxo
	Receiver   string
}

func (a CompleteUnrollArgs) validate() error {
	if a.Explorer == nil {
		return fmt.Errorf("missing explorer")
	}
	if a.SignTx == nil {
		return fmt.Errorf("missing sign tx function")
	}
	if len(a.ServerInfo.Network) <= 0 {
		return fmt.Errorf("missing server info")
	}
	if a.ServerInfo.Dust == 0 {
		return fmt.Errorf("missing server info")
	}
	if len(a.Utxos) <= 0 {
		return fmt.Errorf("missing utxos")
	}
	if len(a.Receiver) <= 0 {
		return fmt.Errorf("missing receiver address")
	}
	netParams := clientlib.ToBitcoinNetwork(clientlib.NetworkFromString(a.ServerInfo.Network))
	if _, err := btcutil.DecodeAddress(a.Receiver, &netParams); err != nil {
		return fmt.Errorf("invalid receiver address")
	}
	return nil
}

// CompleteUnroll spends the user's matured onchain Ark UTXOs (those past their
// exit delay) to args.Receiver, signs the resulting transaction and broadcasts
// it. Returns the broadcast response from the explorer.
func CompleteUnroll(ctx context.Context, args CompleteUnrollArgs) (string, error) {
	if err := args.validate(); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}

	network := clientlib.NetworkFromString(args.ServerInfo.Network)

	pkscript, err := toOutputScript(args.Receiver, network)
	if err != nil {
		return "", err
	}

	targetAmount := uint64(0)
	for _, u := range args.Utxos {
		targetAmount += u.Amount
	}

	if targetAmount == 0 {
		return "", fmt.Errorf("no mature funds available")
	}

	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    int64(targetAmount),
		PkScript: pkscript,
	})
	updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})

	if err := addInputs(updater, args.Utxos); err != nil {
		return "", err
	}

	vbytes := computeVSize(updater.Upsbt.UnsignedTx)
	feeRate, err := args.Explorer.GetFeeRate()
	if err != nil {
		return "", err
	}

	feeAmount := uint64(math.Ceil(float64(vbytes)*feeRate) + 100)

	if targetAmount-feeAmount <= args.ServerInfo.Dust {
		return "", fmt.Errorf("not enough funds to cover network fees")
	}

	updater.Upsbt.UnsignedTx.TxOut[0].Value -= int64(feeAmount)

	unsignedTx, err := ptx.B64Encode()
	if err != nil {
		return "", err
	}

	signedTx, err := args.SignTx(ctx, unsignedTx)
	if err != nil {
		return "", err
	}

	ptx, err = psbt.NewFromRawBytes(strings.NewReader(signedTx), true)
	if err != nil {
		return "", err
	}

	for i := range ptx.Inputs {
		if err := psbt.Finalize(ptx, i); err != nil {
			return "", err
		}
	}

	tx, err := psbt.Extract(ptx)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	if err := tx.Serialize(buf); err != nil {
		return "", err
	}

	txHex := hex.EncodeToString(buf.Bytes())
	return args.Explorer.Broadcast(txHex)
}
