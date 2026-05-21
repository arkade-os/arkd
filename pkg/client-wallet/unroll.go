package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/redemption"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	log "github.com/sirupsen/logrus"
)

var ErrWaitingForConfirmation = fmt.Errorf("waiting for confirmation(s), please retry later")

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

	totalVtxosAmount := uint64(0)
	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.Amount
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	branches, err := w.getBranchesToUnroll(ctx, vtxos)
	if err != nil {
		return nil, err
	}

	isWaitingForConfirmation := false

	for _, branch := range branches {
		nextTx, err := branch.NextRedeemTx()
		if err != nil {
			if err, ok := err.(redemption.ErrPendingConfirmation); ok {
				// the branch tx is in the mempool, we must wait for confirmation
				// print only, do not make the function to fail
				// continue to try other branches
				log.Debug(err.Error())
				isWaitingForConfirmation = true
				continue
			}

			return nil, err
		}

		if _, ok := transactionsMap[nextTx]; !ok {
			transactions = append(transactions, nextTx)
			transactionsMap[nextTx] = struct{}{}
		}
	}

	if len(transactions) == 0 {
		if isWaitingForConfirmation {
			return nil, ErrWaitingForConfirmation
		}

		return nil, nil
	}

	res := make([]UnrollRes, 0, len(transactions))
	for _, parent := range transactions {
		var parentTx wire.MsgTx
		if err := parentTx.Deserialize(hex.NewDecoder(strings.NewReader(parent))); err != nil {
			return nil, err
		}

		childTxid, child, err := w.bumpAnchorTx(ctx, &parentTx)
		if err != nil {
			return nil, err
		}

		// broadcast the package (parent + child)
		packageResponse, err := w.explorer.Broadcast(parent, child)
		if err != nil {
			return nil, err
		}

		res = append(res, UnrollRes{
			ParentTx:   parent,
			ParentTxid: parentTx.TxID(),
			ChildTx:    child,
			ChildTxid:  childTxid,
		})
		log.Debugf("package broadcasted: %s", packageResponse)
	}

	return res, nil
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

	to := options.receiver
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

	return w.completeUnroll(ctx, to)
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

// bumpAnchorTx builds and signs a transaction bumping the fees for a given tx with P2A output.
// Makes use of the onchain P2TR account to select UTXOs to pay fees for parent.
func (w *wallet) bumpAnchorTx(ctx context.Context, parent *wire.MsgTx) (string, string, error) {
	anchor, err := txutils.FindAnchorOutpoint(parent)
	if err != nil {
		return "", "", err
	}

	// estimate for the size of the bump transaction
	weightEstimator := input.TxWeightEstimator{}

	// WeightEstimator doesn't support P2A size, using P2WSH will lead to a small overestimation
	// TODO use the exact P2A size
	weightEstimator.AddNestedP2WSHInput(lntypes.VByte(3).ToWU())

	// We assume only one UTXO will be selected to have a correct estimation
	weightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault)
	weightEstimator.AddP2TROutput()

	childVSize := weightEstimator.Weight().ToVB()

	packageSize := childVSize + computeVSize(parent)
	feeRate, err := w.explorer.GetFeeRate()
	if err != nil {
		return "", "", err
	}

	fees := uint64(math.Ceil(float64(packageSize) * feeRate))

	onchainAddr, _, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return "", "", err
	}

	addr := onchainAddr.Address
	pkScript, err := toOutputScript(addr, w.Network)
	if err != nil {
		return "", "", err
	}

	keyRef, err := w.identity.GetKey(ctx, "")
	if err != nil {
		return "", "", err
	}

	selectedCoins := make([]clientlib.ExplorerUtxo, 0)
	selectedAmount := uint64(0)
	amountToSelect := int64(fees) - txutils.ANCHOR_VALUE

	utxos, err := w.explorer.GetUtxos([]string{addr})
	if err != nil {
		return "", "", err
	}

	for _, utxo := range utxos {
		selectedCoins = append(selectedCoins, utxo)
		selectedAmount += utxo.Amount
		amountToSelect -= int64(utxo.Amount)
		if amountToSelect <= 0 {
			break
		}
	}

	if amountToSelect > 0 {
		return "", "", fmt.Errorf("not enough funds to select %d", amountToSelect)
	}

	changeAmount := selectedAmount - fees

	inputs := []*wire.OutPoint{anchor}
	sequences := []uint32{
		wire.MaxTxInSequenceNum,
	}
	outputs := []*wire.TxOut{
		{
			Value:    int64(changeAmount),
			PkScript: pkScript,
		},
	}

	for _, utxo := range selectedCoins {
		txid, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return "", "", err
		}
		inputs = append(inputs, &wire.OutPoint{
			Hash:  *txid,
			Index: utxo.Vout,
		})
		sequences = append(sequences, wire.MaxTxInSequenceNum)
	}

	ptx, err := psbt.New(inputs, outputs, 3, 0, sequences)
	if err != nil {
		return "", "", err
	}

	ptx.Inputs[0].WitnessUtxo = txutils.AnchorOutput()

	for i, utxo := range selectedCoins {
		pkScript, err := hex.DecodeString(utxo.Script)
		if err != nil {
			return "", "", err
		}

		ptx.Inputs[i+1].WitnessUtxo = &wire.TxOut{
			Value:    int64(utxo.Amount),
			PkScript: pkScript,
		}
		ptx.Inputs[i+1].TaprootInternalKey = schnorr.SerializePubKey(keyRef.PubKey)
	}

	b64, err := ptx.B64Encode()
	if err != nil {
		return "", "", err
	}

	tx, err := w.identity.SignTransaction(ctx, b64, nil)
	if err != nil {
		return "", "", err
	}

	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", "", err
	}

	for inIndex := range signedPtx.Inputs[1:] {
		if _, err := psbt.MaybeFinalize(signedPtx, inIndex+1); err != nil {
			return "", "", err
		}
	}

	childTx, err := txutils.ExtractWithAnchors(signedPtx)
	if err != nil {
		return "", "", err
	}

	var serializedTx bytes.Buffer
	if err := childTx.Serialize(&serializedTx); err != nil {
		return "", "", err
	}

	return childTx.TxID(), hex.EncodeToString(serializedTx.Bytes()), nil
}

func (w *wallet) completeUnroll(
	ctx context.Context, to string,
) (string, error) {
	pkscript, err := toOutputScript(to, w.Network)
	if err != nil {
		return "", err
	}

	utxos, err := w.getMatureUtxos(ctx)
	if err != nil {
		return "", err
	}

	targetAmount := uint64(0)
	for _, u := range utxos {
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

	if err := w.addInputs(ctx, updater, utxos); err != nil {
		return "", err
	}

	vbytes := computeVSize(updater.Upsbt.UnsignedTx)
	feeRate, err := w.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}

	feeAmount := uint64(math.Ceil(float64(vbytes)*feeRate) + 100)

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

	tx, err := psbt.Extract(ptx)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	if err := tx.Serialize(buf); err != nil {
		return "", err
	}

	txHex := hex.EncodeToString(buf.Bytes())
	return w.explorer.Broadcast(txHex)
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

func (w *wallet) getMatureUtxos(ctx context.Context) ([]clientlib.Utxo, error) {
	_, _, _, addr, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	rawScript, err := addr.RawScript()
	if err != nil {
		return nil, err
	}

	signingClosure, err := addr.ExitClosure()
	if err != nil {
		return nil, err
	}

	exitDelay, err := rawScript.SmallestExitDelay()
	if err != nil {
		return nil, err
	}

	now := time.Now()

	addrTapscripts := make(map[string][]string)
	// nolint
	script, _ := toOutputScript(addr.Address, w.Network)
	addrTapscripts[hex.EncodeToString(script)] = addr.Tapscripts

	fetchedUtxos, err := w.explorer.GetUtxos([]string{addr.Address})
	if err != nil {
		return nil, err
	}

	utxos := make([]clientlib.Utxo, 0)
	for _, utxo := range fetchedUtxos {
		tapscripts := addrTapscripts[utxo.Script]
		u := utxo.ToUtxo(*exitDelay, tapscripts, signingClosure)
		if u.RedeemableAt.Before(now) {
			utxos = append(utxos, u)
		}
	}
	return utxos, nil
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

func (w *wallet) getBranchesToUnroll(
	ctx context.Context, vtxos []clientlib.Vtxo,
) (map[string]*redemption.RedeemBranch, error) {
	redeemBranches := make(map[string]*redemption.RedeemBranch, 0)

	for _, vtxo := range vtxos {
		redeemBranch, err := redemption.NewRedeemBranch(ctx, w.explorer, w.indexer, vtxo)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}
