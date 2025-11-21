package e2e_test

import (
	"bytes"
	"context"
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

const adminUrl = "http://127.0.0.1:7071"
const serverUrl = "127.0.0.1:7070"

func generateBlocks(n int) error {
	_, err := runCommand("nigiri", "rpc", "--generate", fmt.Sprintf("%d", n))
	return err
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
	out, err := runCommand("docker", args...)
	if err != nil {
		return "", err
	}
	idx := strings.Index(out, "{")
	if idx == -1 {
		return out, nil
	}
	return out[idx:], nil
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

func setupArkSDK(t *testing.T) arksdk.ArkClient {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
		AppDataStoreType: types.KVStore,
	})
	require.NoError(t, err)

	client, err := arksdk.NewArkClient(appDataStore)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkeyHex := hex.EncodeToString(privkey.Serialize())

	err = client.Init(t.Context(), arksdk.InitArgs{
		WalletType:           arksdk.SingleKeyWallet,
		ClientType:           arksdk.GrpcClient,
		ServerUrl:            serverUrl,
		Password:             password,
		Seed:                 privkeyHex,
		ExplorerPollInterval: time.Second,
	})
	require.NoError(t, err)

	err = client.Unlock(t.Context(), password)
	require.NoError(t, err)

	return client
}

func setupArkSDKWithTransport(t *testing.T) (arksdk.ArkClient, client.TransportClient) {
	client := setupArkSDK(t)
	transportClient, err := grpcclient.NewClient(serverUrl)
	require.NoError(t, err)
	return client, transportClient
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
) (arksdk.ArkClient, wallet.WalletService, *btcec.PublicKey, client.TransportClient) {
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
		ServerUrl:  serverUrl,
		Password:   password,
		Seed:       privkeyHex,
	})
	require.NoError(t, err)

	err = client.Unlock(context.Background(), password)
	require.NoError(t, err)

	grpcClient, err := grpcclient.NewClient(serverUrl)
	require.NoError(t, err)

	return client, wallet, privkey.PubKey(), grpcClient
}

func setupIndexer(t *testing.T) indexer.Indexer {
	svc, err := grpcindexer.NewClient(serverUrl)
	require.NoError(t, err)
	return svc
}

func faucet(t *testing.T, client arksdk.ArkClient, amount float64) {
	// Faucet offchain with note
	faucetOffchain(t, client, amount)

	onchainAddr, _, _, err := client.Receive(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, onchainAddr)
	// Faucet onchain addr to cover network fees for the unroll.
	faucetOnchain(t, onchainAddr, 0.00001)
}

func generateNote(t *testing.T, amount uint64) string {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", "http://localhost:7071/v1/admin/note", reqBody)
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

func faucetOnchain(t *testing.T, address string, amount float64) {
	_, err := runCommand("nigiri", "faucet", address, fmt.Sprintf("%.8f", amount))
	require.NoError(t, err)
}

func faucetOffchain(t *testing.T, client arksdk.ArkClient, amount float64) types.Vtxo {
	_, offchainAddr, _, err := client.Receive(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, offchainAddr)

	note := generateNote(t, uint64(amount*1e8))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingFunds []types.Vtxo
	var incomingErr error
	go func() {
		incomingFunds, incomingErr = client.NotifyIncomingFunds(t.Context(), offchainAddr)
		wg.Done()
	}()

	txid, err := client.RedeemNotes(t.Context(), []string{note})
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()

	require.NoError(t, incomingErr)
	require.NotEmpty(t, incomingFunds)

	time.Sleep(time.Second)
	return incomingFunds[0]
}

func getBatchExpiryLocktime(batchExpiry uint32) arklib.RelativeLocktime {
	if batchExpiry >= 512 {
		return arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: batchExpiry,
		}
	}
	return arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeBlock,
		Value: batchExpiry,
	}
}

// lock the wallet, wait 10s and unlock it
func restartArkd() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	// down arkd container
	if _, err := runCommand("docker", "container", "stop", "arkd"); err != nil {
		return err
	}

	time.Sleep(5 * time.Second)

	if _, err := runCommand("docker", "container", "start", "arkd"); err != nil {
		return err
	}

	time.Sleep(5 * time.Second)

	url := fmt.Sprintf("%s/v1/admin/wallet/unlock", adminUrl)
	body := fmt.Sprintf(`{"password": "%s"}`, password)
	if err := post(adminHttpClient, url, body, "unlock"); err != nil {
		return err
	}

	return nil
}

func setupArkd() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/status", adminUrl)
	status, err := get[statusResp](adminHttpClient, url, "status")
	if err != nil {
		return err
	}

	if status.Initialized && !status.Unlocked {
		url := fmt.Sprintf("%s/v1/admin/wallet/unlock", adminUrl)
		body := fmt.Sprintf(`{"password": "%s"}`, password)
		if err := post(adminHttpClient, url, body, "unlock"); err != nil {
			return err
		}

		if err := waitUntilReady(adminHttpClient); err != nil {
			return err
		}

		return refill(adminHttpClient)
	}

	if status.Initialized && status.Unlocked && status.Synced {
		return refill(adminHttpClient)
	}

	url = fmt.Sprintf("%s/v1/admin/wallet/seed", adminUrl)
	seed, err := get[seedResp](adminHttpClient, url, "seed")
	if err != nil {
		return err
	}

	url = fmt.Sprintf("%s/v1/admin/wallet/create", adminUrl)
	body := fmt.Sprintf(`{"seed": "%s", "password": "%s"}`, seed.Seed, password)
	if err := post(adminHttpClient, url, body, "create"); err != nil {
		return err
	}

	url = fmt.Sprintf("%s/v1/admin/wallet/unlock", adminUrl)
	body = fmt.Sprintf(`{"password": "%s"}`, password)
	if err := post(adminHttpClient, url, body, "unlock"); err != nil {
		return err
	}

	if err := waitUntilReady(adminHttpClient); err != nil {
		return err
	}

	return refill(adminHttpClient)
}

type statusResp struct {
	Initialized bool `json:"initialized"`
	Unlocked    bool `json:"unlocked"`
	Synced      bool `json:"synced"`
}
type seedResp struct {
	Seed string `json:"seed"`
}
type addressResp struct {
	Address string `json:"address"`
}
type balanceResp struct {
	MainAccount struct {
		Available float64 `json:"available,string"`
	} `json:"mainAccount"`
}

func get[T any](httpClient *http.Client, url, name string) (*T, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare %s request: %s", name, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s: %s", name, err)
	}
	var data T
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse %s response: %s", name, err)
	}
	return &data, nil
}

func post(httpClient *http.Client, url, body, name string) error {
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(body)))
	if err != nil {
		return fmt.Errorf("failed to prepare %s request: %s", name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if _, err := httpClient.Do(req); err != nil {
		return fmt.Errorf("failed to %s wallet: %s", name, err)
	}
	return nil
}

func waitUntilReady(httpClient *http.Client) error {
	ticker := time.NewTicker(2 * time.Second)
	url := fmt.Sprintf("%s/v1/admin/wallet/status", adminUrl)
	for range ticker.C {
		status, err := get[statusResp](httpClient, url, "status")
		if err != nil {
			return err
		}

		if status.Initialized && status.Unlocked && status.Synced {
			ticker.Stop()
			break
		}
	}
	return nil
}

func refill(httpClient *http.Client) error {
	url := fmt.Sprintf("%s/v1/admin/wallet/balance", adminUrl)
	balance, err := get[balanceResp](httpClient, url, "balance")
	if err != nil {
		return err
	}

	if delta := 15 - balance.MainAccount.Available; delta > 0 {
		url = fmt.Sprintf("%s/v1/admin/wallet/address", adminUrl)
		address, err := get[addressResp](httpClient, url, "address")
		if err != nil {
			return err
		}

		for range int(delta) {
			if _, err := runCommand("nigiri", "faucet", address.Address); err != nil {
				return err
			}
		}
	}
	return nil
}
