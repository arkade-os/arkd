package wallet

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/unroll"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (w *wallet) Unroll(ctx context.Context, opts ...UnrollOption) ([]UnrollRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	o := newDefaultUnrollOptions()
	for _, opt := range opts {
		if err := opt.applyUnroll(o); err != nil {
			return nil, err
		}
	}

	w.txLock.Lock()
	defer w.txLock.Unlock()

	vtxos := o.vtxos
	if len(vtxos) <= 0 {
		var err error
		vtxos, err = w.getSpendableVtxos(ctx, &getVtxosFilter{excludeRecoverableVtxos: true})
		if err != nil {
			return nil, err
		}
	}

	if len(vtxos) == 0 {
		return nil, fmt.Errorf("no vtxos to unroll")
	}

	onchainAddr, _, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	keyRef, err := w.identity.GetKey(ctx, "")
	if err != nil {
		return nil, err
	}

	return unroll.Unroll(ctx, unroll.UnrollArgs{
		Explorer:     w.explorer,
		Indexer:      w.indexer,
		SignTx:       w.SignTransaction,
		ServerParams: *w.ServerParams,
		Vtxos:        vtxos,
		BumpAddr:     onchainAddr.Address,
		BumpPubKey:   keyRef.PubKey,
	})
}

func (w *wallet) CompleteUnroll(ctx context.Context, opts ...UnrollOption) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	options := newDefaultUnrollOptions()
	for _, opt := range opts {
		if err := opt.applyUnroll(options); err != nil {
			return "", err
		}
	}

	utxos, err := w.getMatureUtxos(ctx)
	if err != nil {
		return "", err
	}

	if len(utxos) <= 0 {
		return "", fmt.Errorf("no mature funds available")
	}

	to := options.receiver
	if len(to) <= 0 {
		onchainAddr, _, _, _, err := w.getAddresses(ctx)
		if err != nil {
			return "", err
		}
		to = onchainAddr.Address
	}

	return unroll.CompleteUnroll(ctx, unroll.CompleteUnrollArgs{
		Explorer:     w.explorer,
		SignTx:       w.SignTransaction,
		ServerParams: *w.ServerParams,
		Utxos:        utxos,
		Receiver:     to,
	})
}

func (w *wallet) WithdrawFromAllExpiredBoardings(
	ctx context.Context, opts ...UnrollOption,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	o := newDefaultUnrollOptions()
	for _, opt := range opts {
		if err := opt.applyUnroll(o); err != nil {
			return "", err
		}
	}

	to := o.receiver
	if len(to) <= 0 {
		onchainAddr, _, _, _, err := w.getAddresses(ctx)
		if err != nil {
			return "", err
		}

		to = onchainAddr.Address
	}
	if _, err := btcutil.DecodeAddress(to, nil); err != nil {
		return "", fmt.Errorf("invalid receiver address '%s': must be onchain", to)
	}

	return w.sendExpiredBoardingUtxos(ctx, to)
}

func (w *wallet) OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	if w.UtxoMaxAmount == 0 {
		return "", fmt.Errorf("operation not allowed by the server")
	}

	_, _, boardingAddr, _, err := w.getAddresses(ctx)
	if err != nil {
		return "", err
	}

	return w.sendExpiredBoardingUtxos(ctx, boardingAddr.Address)
}

func (w *wallet) getMatureUtxos(ctx context.Context) ([]clientlib.Utxo, error) {
	_, _, _, addr, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	fetchedUtxos, err := w.explorer.GetUtxos([]string{addr.Address})
	if err != nil {
		return nil, err
	}

	signingClosure, err := addr.ExitClosure()
	if err != nil {
		return nil, err
	}

	utxos := make([]clientlib.Utxo, 0, len(fetchedUtxos))
	for _, utxo := range fetchedUtxos {
		u := utxo.ToUtxo(w.UnilateralExitDelay, addr.Tapscripts, signingClosure)
		if u.RedeemableAt.Before(now) {
			utxos = append(utxos, u)
		}
	}

	return utxos, nil
}

func (w *wallet) sendExpiredBoardingUtxos(ctx context.Context, to string) (string, error) {
	pkscript, err := toOutputScript(to, w.Network)
	if err != nil {
		return "", err
	}

	w.txLock.Lock()
	defer w.txLock.Unlock()

	utxos, err := w.getExpiredBoardingUtxos(ctx)
	if err != nil {
		return "", err
	}

	targetAmount := uint64(0)
	for _, u := range utxos {
		targetAmount += u.Amount
	}

	if targetAmount == 0 {
		return "", fmt.Errorf("no expired boarding funds available")
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

	if err := w.addInputs(ctx, updater, utxos); err != nil {
		return "", err
	}

	vbytes := computeVSize(updater.Upsbt.UnsignedTx)
	feeRate, err := w.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}
	feeAmount := uint64(math.Ceil(float64(vbytes)*feeRate) + 50)

	if targetAmount-feeAmount <= w.Dust {
		return "", fmt.Errorf("not enough funds to cover network fees")
	}

	updater.Upsbt.UnsignedTx.TxOut[0].Value -= int64(feeAmount)

	unsignedTx, err := ptx.B64Encode()
	if err != nil {
		return "", err
	}

	signedTx, err := w.identity.SignTransaction(ctx, unsignedTx, nil)
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

	return ptx.B64Encode()
}

func (w *wallet) getExpiredBoardingUtxos(ctx context.Context) ([]clientlib.Utxo, error) {
	_, _, boardingAddr, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	utxos, err := w.getUtxos(ctx, *boardingAddr, getUtxosFilter{expired: true})
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiredUtxos := make([]clientlib.Utxo, 0, len(utxos))
	for _, u := range utxos {
		if u.RedeemableAt.Before(now) || u.RedeemableAt.Equal(now) {
			expiredUtxos = append(expiredUtxos, u)
		}
	}

	return expiredUtxos, nil
}

func (w *wallet) addInputs(
	ctx context.Context, updater *psbt.Updater, utxos []clientlib.Utxo,
) error {
	for _, utxo := range utxos {
		vtxoScript, err := script.ParseVtxoScript(utxo.Tapscripts)
		if err != nil {
			return err
		}

		previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return err
		}

		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		pkScript, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return err
		}

		updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *previousHash,
				Index: utxo.VOut,
			},
			Sequence: sequence,
		})

		exitClosures := vtxoScript.ExitClosures()
		if len(exitClosures) <= 0 {
			return fmt.Errorf("no exit closures found")
		}

		exitClosure := exitClosures[0]

		exitScript, err := exitClosure.Script()
		if err != nil {
			return err
		}

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return err
		}

		exitLeaf := txscript.NewBaseTapLeaf(exitScript)
		leafProof, err := taprootTree.GetTaprootMerkleProof(exitLeaf.TapHash())
		if err != nil {
			return fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value:    int64(utxo.Amount),
				PkScript: pkScript,
			},
			TaprootLeafScript: []*psbt.TaprootTapLeafScript{
				{
					ControlBlock: leafProof.ControlBlock,
					Script:       leafProof.Script,
					LeafVersion:  txscript.BaseLeafVersion,
				},
			},
		})
	}

	return nil
}

type getUtxosFilter struct {
	expired   bool
	claimable bool
}

func (w *wallet) getUtxos(
	_ context.Context, addr clientlib.Address, opts getUtxosFilter,
) ([]clientlib.Utxo, error) {
	rawScript, err := addr.RawScript()
	if err != nil {
		return nil, err
	}

	var signingClosure script.Closure
	if opts.expired {
		signingClosure, err = addr.ExitClosure()
		if err != nil {
			return nil, err
		}
	}
	if opts.claimable {
		signingClosure, err = addr.CollaborativeClosure()
		if err != nil {
			return nil, err
		}
	}

	exitDelay, err := rawScript.SmallestExitDelay()
	if err != nil {
		return nil, err
	}

	fetchedUtxos, err := w.explorer.GetUtxos([]string{addr.Address})
	if err != nil {
		return nil, err
	}

	utxos := make([]clientlib.Utxo, 0, len(fetchedUtxos))
	for _, u := range fetchedUtxos {
		utxos = append(utxos, u.ToUtxo(*exitDelay, addr.Tapscripts, signingClosure))
	}

	now := time.Now()
	if opts.expired {
		filtered := make([]clientlib.Utxo, 0)
		for _, u := range utxos {
			if !u.RedeemableAt.After(now) {
				filtered = append(filtered, u)
			}
		}
		utxos = filtered
	}
	if opts.claimable {
		filtered := make([]clientlib.Utxo, 0)
		for _, u := range utxos {
			if u.RedeemableAt.After(now) {
				filtered = append(filtered, u)
			}
		}
		utxos = filtered
	}

	return utxos, nil
}
