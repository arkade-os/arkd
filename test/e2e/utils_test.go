package e2e_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/go-sdk/explorer"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type arkBalance struct {
	Offchain struct {
		Total int `json:"total"`
	} `json:"offchain_balance"`
	Onchain struct {
		Spendable int `json:"spendable_amount"`
		Locked    []struct {
			Amount      int    `json:"amount"`
			SpendableAt string `json:"spendable_at"`
		} `json:"locked_amount"`
	} `json:"onchain_balance"`
}

type arkReceive struct {
	Offchain string `json:"offchain_address"`
	Boarding string `json:"boarding_address"`
	Onchain  string `json:"onchain_address"`
}

func generateBlock() error {
	_, err := runCommand("nigiri", "rpc", "--generate", "1")
	return err
}

func generateBlocks(n int) error {
	for i := 0; i < n; i++ {
		err := generateBlock()
		if err != nil {
			return err
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}
func getBlockHeight() (uint32, error) {
	out, err := runCommand("nigiri", "rpc", "getblockcount")
	if err != nil {
		return 0, err
	}
	height, err := strconv.ParseUint(strings.TrimSpace(out), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(height), nil
}

func runDockerExec(container string, arg ...string) (string, error) {
	args := append([]string{"exec", "-t", container}, arg...)
	return runCommand("docker", args...)
}

func runCommand(name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := newCommand(name, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}
	output := new(strings.Builder)
	errorb := new(strings.Builder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(output, stdout); err != nil {
			fmt.Fprintf(errb, "error reading stdout: %s", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(errorb, stderr); err != nil {
			fmt.Fprintf(errb, "error reading stderr: %s", err)
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if errMsg := errorb.String(); len(errMsg) > 0 {
			return "", fmt.Errorf("%s", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("%s", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("%s", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}

func bumpAndBroadcastTx(t *testing.T, tx string, explorer explorer.Explorer) {
	var transaction wire.MsgTx
	err := transaction.Deserialize(hex.NewDecoder(strings.NewReader(tx)))
	require.NoError(t, err)

	childTx := bumpAnchorTx(t, &transaction, explorer)

	_, err = explorer.Broadcast(tx, childTx)
	require.NoError(t, err)

	err = generateBlocks(1)
	require.NoError(t, err)
}

// bumpAnchorTx is crafting and signing a transaction bumping the fees for a given tx with P2A output
// it is using the onchain P2TR account to select UTXOs
func bumpAnchorTx(t *testing.T, parent *wire.MsgTx, explorerSvc explorer.Explorer) string {
	randomPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	tapKey := txscript.ComputeTaprootKeyNoScript(randomPrivKey.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	anchor, err := txutils.FindAnchorOutpoint(parent)
	require.NoError(t, err)

	fees := uint64(10000)

	// send 1_000_000 sats to the address
	_, err = runCommand("nigiri", "faucet", addr.EncodeAddress(), "0.01")
	require.NoError(t, err)

	changeAmount := 1_000_000 - fees

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	inputs := []*wire.OutPoint{anchor}
	sequences := []uint32{
		wire.MaxTxInSequenceNum,
	}

	time.Sleep(5 * time.Second)

	selectedCoins, err := explorerSvc.GetUtxos(addr.EncodeAddress())
	require.NoError(t, err)
	require.Len(t, selectedCoins, 1)

	utxo := selectedCoins[0]
	txid, err := chainhash.NewHashFromStr(utxo.Txid)
	require.NoError(t, err)
	inputs = append(inputs, &wire.OutPoint{
		Hash:  *txid,
		Index: utxo.Vout,
	})
	sequences = append(sequences, wire.MaxTxInSequenceNum)

	ptx, err := psbt.New(
		inputs,
		[]*wire.TxOut{
			{
				Value:    int64(changeAmount),
				PkScript: pkScript,
			},
		},
		3,
		0,
		sequences,
	)
	require.NoError(t, err)

	ptx.Inputs[0].WitnessUtxo = txutils.AnchorOutput()
	ptx.Inputs[1].WitnessUtxo = &wire.TxOut{
		Value:    int64(selectedCoins[0].Amount),
		PkScript: pkScript,
	}

	coinTxHash, err := chainhash.NewHashFromStr(selectedCoins[0].Txid)
	require.NoError(t, err)

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		*anchor: txutils.AnchorOutput(),
		{
			Hash:  *coinTxHash,
			Index: selectedCoins[0].Vout,
		}: {
			Value:    int64(selectedCoins[0].Amount),
			PkScript: pkScript,
		},
	})

	txsighashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	preimage, err := txscript.CalcTaprootSignatureHash(
		txsighashes,
		txscript.SigHashDefault,
		ptx.UnsignedTx,
		1,
		prevoutFetcher,
	)
	require.NoError(t, err)

	sig, err := schnorr.Sign(txscript.TweakTaprootPrivKey(*randomPrivKey, nil), preimage)
	require.NoError(t, err)

	ptx.Inputs[1].TaprootKeySpendSig = sig.Serialize()

	for inIndex := range ptx.Inputs[1:] {
		_, err := psbt.MaybeFinalize(ptx, inIndex+1)
		require.NoError(t, err)
	}

	childTx, err := txutils.ExtractWithAnchors(ptx)
	require.NoError(t, err)

	var serializedTx bytes.Buffer
	require.NoError(t, childTx.Serialize(&serializedTx))

	return hex.EncodeToString(serializedTx.Bytes())
}
