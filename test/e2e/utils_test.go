package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/arkade-os/go-sdk/explorer"
	"github.com/arkade-os/go-sdk/indexer"
	grpcindexer "github.com/arkade-os/go-sdk/indexer/grpc"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
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

func setupArkSDK(t *testing.T) (arksdk.ArkClient, client.TransportClient) {
	alice, _, grpcAlice := setupArkSDKwithPublicKey(t)
	return alice, grpcAlice
}

func setupWalletService(t *testing.T) (wallet.WalletService, *btcec.PublicKey, error) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
		AppDataStoreType: types.KVStore,
	})
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)
	require.NotNil(t, walletStore)

	wallet, err := singlekeywallet.NewBitcoinWallet(appDataStore.ConfigStore(), walletStore)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkeyHex := hex.EncodeToString(privkey.Serialize())

	password := "password"
	ctx := context.Background()
	_, err = wallet.Create(ctx, password, privkeyHex)
	require.NoError(t, err)

	_, err = wallet.Unlock(ctx, password)
	require.NoError(t, err)

	return wallet, privkey.PubKey(), nil
}

func setupArkSDKwithPublicKey(
	t *testing.T,
) (arksdk.ArkClient, *btcec.PublicKey, client.TransportClient) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
		AppDataStoreType: types.KVStore,
	})
	require.NoError(t, err)

	client, err := arksdk.NewArkClient(appDataStore)
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)
	require.NotNil(t, walletStore)

	wallet, err := singlekeywallet.NewBitcoinWallet(appDataStore.ConfigStore(), walletStore)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkeyHex := hex.EncodeToString(privkey.Serialize())

	err = client.InitWithWallet(context.Background(), arksdk.InitWithWalletArgs{
		Wallet:     wallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  "localhost:7070",
		Password:   password,
		Seed:       privkeyHex,
	})
	require.NoError(t, err)

	err = client.Unlock(context.Background(), password)
	require.NoError(t, err)

	grpcClient, err := grpcclient.NewClient("localhost:7070")
	require.NoError(t, err)

	return client, privkey.PubKey(), grpcClient
}

func setupIndexer(t *testing.T) indexer.Indexer {
	svc, err := grpcindexer.NewClient("localhost:7070")
	require.NoError(t, err)
	return svc
}

func generateNote(t *testing.T, amount uint32) string {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", "http://localhost:7070/v1/admin/note", reqBody)
	if err != nil {
		t.Fatalf("failed to prepare note request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	resp, err := adminHttpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create note: %s", err)
	}

	var noteResp struct {
		Notes []string `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&noteResp); err != nil {
		t.Fatalf("failed to parse response: %s", err)
	}

	return noteResp.Notes[0]
}

func faucetOffchainAddress(t *testing.T, address string) (types.Vtxo, error) {
	client, _ := setupArkSDK(t)

	ctx := context.Background()
	_, offchainAddr, boardingAddr, err := client.Receive(ctx)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddr, "0.0002")
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	go func() {
		_, err := client.Settle(ctx)
		require.NoError(t, err)
	}()

	vtxos, err := client.NotifyIncomingFunds(ctx, offchainAddr)
	require.NoError(t, err)
	require.NotEmpty(t, vtxos)
	require.Len(t, vtxos, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)

	var receivedVtxo types.Vtxo

	go func() {
		defer wg.Done()
		vtxos, err = client.NotifyIncomingFunds(ctx, address)
		require.NoError(t, err)
		receivedVtxo = vtxos[0]
	}()

	_, err = client.SendOffChain(ctx, false, []types.Receiver{
		{
			To:     address,
			Amount: vtxos[0].Amount,
		},
	})
	require.NoError(t, err)

	wg.Wait()

	return receivedVtxo, nil
}

type delegateBatchEventsHandler struct {
	intentId         string
	signerSession    tree.SignerSession
	partialForfeitTx string
	delegatorWallet  wallet.WalletService
	client           client.TransportClient
	signerPubKey     *btcec.PublicKey
	vtxoTreeExpiry   arklib.RelativeLocktime

	cacheBatchId string
}

func (h *delegateBatchEventsHandler) OnBatchStarted(
	ctx context.Context,
	event client.BatchStartedEvent,
) (bool, error) {
	buf := sha256.Sum256([]byte(h.intentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, hash := range event.HashedIntentIds {
		if hash == hashedIntentId {
			if err := h.client.ConfirmRegistration(ctx, h.intentId); err != nil {
				return false, err
			}
			h.cacheBatchId = event.Id
			return false, nil
		}
	}

	return true, nil
}

func (h *delegateBatchEventsHandler) OnBatchFinalized(
	ctx context.Context,
	event client.BatchFinalizedEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnBatchFailed(
	ctx context.Context,
	event client.BatchFailedEvent,
) error {
	if event.Id == h.cacheBatchId {
		return fmt.Errorf("batch failed: %s", event.Reason)
	}
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeTxEvent(
	ctx context.Context,
	event client.TreeTxEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSignatureEvent(
	ctx context.Context,
	event client.TreeSignatureEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSigningStarted(
	ctx context.Context,
	event client.TreeSigningStartedEvent,
	vtxoTree *tree.TxTree,
) (bool, error) {
	pubkeyFound := false
	myPubkey := h.signerSession.GetPublicKey()
	for _, cosigner := range event.CosignersPubkeys {
		if cosigner == myPubkey {
			pubkeyFound = true
			break
		}
	}

	if !pubkeyFound {
		return true, nil
	}

	sweepClosure := script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{h.signerPubKey}},
		Locktime:        h.vtxoTreeExpiry,
	}

	script, err := sweepClosure.Script()
	if err != nil {
		return false, err
	}

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}

	batchOutput := commitmentTx.UnsignedTx.TxOut[0]
	batchOutputAmount := batchOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	generateAndSendNonces := func(session tree.SignerSession) error {
		if err := session.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
			return err
		}

		nonces, err := session.GetNonces()
		if err != nil {
			return err
		}

		return h.client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces)
	}

	if err := generateAndSendNonces(h.signerSession); err != nil {
		return false, err
	}

	return false, nil
}

func (h *delegateBatchEventsHandler) OnTreeNoncesAggregated(
	ctx context.Context,
	event client.TreeNoncesAggregatedEvent,
) error {
	sign := func(session tree.SignerSession) error {
		session.SetAggregatedNonces(event.Nonces)

		sigs, err := session.Sign()
		if err != nil {
			return err
		}

		return h.client.SubmitTreeSignatures(
			ctx,
			event.Id,
			session.GetPublicKey(),
			sigs,
		)
	}

	if err := sign(h.signerSession); err != nil {
		return err
	}

	return nil
}

func (h *delegateBatchEventsHandler) OnBatchFinalization(
	ctx context.Context,
	event client.BatchFinalizationEvent,
	vtxoTree *tree.TxTree,
	connectorTree *tree.TxTree,
) error {
	forfeitPtx, err := psbt.NewFromRawBytes(strings.NewReader(h.partialForfeitTx), true)
	if err != nil {
		return err
	}

	updater, err := psbt.NewUpdater(forfeitPtx)
	if err != nil {
		return err
	}

	// add the connector input to the forfeit tx
	connectors := connectorTree.Leaves()
	connector := connectors[0]
	updater.Upsbt.UnsignedTx.TxIn = append(updater.Upsbt.UnsignedTx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  connector.UnsignedTx.TxHash(),
			Index: 0,
		},
		Sequence: wire.MaxTxInSequenceNum,
	})
	updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    connector.UnsignedTx.TxOut[0].Value,
			PkScript: connector.UnsignedTx.TxOut[0].PkScript,
		},
	})

	if err := updater.AddInSighashType(txscript.SigHashDefault, 0); err != nil {
		return err
	}

	encodedForfeitTx, err := updater.Upsbt.B64Encode()
	if err != nil {
		return err
	}

	// sign the forfeit tx
	signedForfeitTx, err := h.delegatorWallet.SignTransaction(
		context.Background(),
		nil,
		encodedForfeitTx,
	)
	if err != nil {
		return err
	}

	return h.client.SubmitSignedForfeitTxs(
		ctx, []string{signedForfeitTx}, "",
	)
}
