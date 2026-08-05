package e2e_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	singlekeyidentity "github.com/arkade-os/arkd/pkg/client-wallet/identity"
	identityinmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-wallet/store"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	adminUrl    = "http://127.0.0.1:7071"
	serverUrl   = "127.0.0.1:7070"
	explorerUrl = "http://127.0.0.1:3000"
)

// Timeouts for the wait helpers below. They are upper bounds on how long a
// condition may take to become true, not delays: a helper returns as soon as
// its condition holds, so raising a bound costs nothing on a healthy run.
const (
	// pollInterval is how often the wait helpers re-check their condition.
	pollInterval = 250 * time.Millisecond
	// indexerWait bounds waits on the indexer projection catching up with a
	// change the client has already been notified about.
	indexerWait = 30 * time.Second
	// chainWait bounds waits on the explorer indexing new onchain activity.
	chainWait = 60 * time.Second
	// serverWait bounds waits on arkd reacting to a newly confirmed tx.
	serverWait = 60 * time.Second
	// notifyWait bounds waits for funds to arrive at an address. A settle
	// spans at least one batch session, so this is generous.
	notifyWait = 90 * time.Second
	// sweepWait bounds waits on the block-scheduled sweeper acting on expired
	// batch outputs. The sweeper polls the chain tip on its own schedule, so
	// the lag between mining the expiring blocks and the vtxo table reflecting
	// the sweep can be considerably longer than a single round.
	sweepWait = 4 * time.Minute
)

// testExplorer is a shared read-only explorer used by the wait helpers to
// observe onchain state the way the client wallets do.
var testExplorer clientlib.Explorer

// waitUntil polls cond every pollInterval until it returns nil, failing the
// test if timeout elapses first. Prefer this over a fixed sleep: the systems
// under test (explorer indexing, the indexer projection, the sweeper) settle
// after an unpredictable delay that varies with CI load.
//
// cond returns an error rather than a bool so that a condition which never
// holds because of a persistent fault reports that fault, instead of an
// anonymous timeout that looks like a merely slow system. Each call runs in
// its own goroutine so a hung cond cannot outlive the deadline.
func waitUntil(t *testing.T, timeout time.Duration, what string, cond func() error) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error

	fail := func() {
		t.Helper()
		if lastErr == nil {
			lastErr = fmt.Errorf("condition did not complete before the deadline")
		}
		require.FailNowf(
			t, "timed out waiting",
			"timed out after %s waiting for %s; last error: %v", timeout, what, lastErr,
		)
	}

	for {
		done := make(chan error, 1)
		go func() { done <- cond() }()

		select {
		case err := <-done:
			if err == nil {
				return
			}
			lastErr = err
		case <-time.After(time.Until(deadline)):
			fail()
			return
		}

		if !time.Now().Before(deadline) {
			fail()
			return
		}
		time.Sleep(pollInterval)
	}
}

// notifyIncomingFunds waits for funds to land at addr, bounded so that a
// transfer which never arrives fails its own test with a legible message.
//
// client.NotifyIncomingFunds returns only when funds arrive or its context is
// cancelled. Callers pass the test context and then block on a WaitGroup, so
// that context cannot be cancelled while they are waiting: an uncredited
// address deadlocks the test, and the deadlock consumes the whole `go test`
// budget and takes every other test in the package down with it.
func notifyIncomingFunds(
	ctx context.Context, client wallet.Wallet, addr string,
) ([]clientlib.Vtxo, error) {
	notifyCtx, cancel := context.WithTimeout(ctx, notifyWait)
	defer cancel()

	funds, err := client.NotifyIncomingFunds(notifyCtx, addr)
	if err != nil {
		if notifyCtx.Err() != nil && ctx.Err() == nil {
			return nil, fmt.Errorf("no funds received at %s within %s", addr, notifyWait)
		}
		return nil, err
	}
	if len(funds) == 0 {
		return nil, fmt.Errorf("no funds received at %s within %s", addr, notifyWait)
	}
	return funds, nil
}

// waitForOnchainUtxos blocks until the explorer reports at least n utxos for
// addr and returns them.
func waitForOnchainUtxos(t *testing.T, addr string, n int) []clientlib.ExplorerUtxo {
	t.Helper()

	var utxos []clientlib.ExplorerUtxo
	waitUntil(t, chainWait, fmt.Sprintf("%d utxo(s) at %s", n, addr), func() error {
		found, err := testExplorer.GetUtxos([]string{addr})
		if err != nil {
			return err
		}
		utxos = found
		if len(found) < n {
			return fmt.Errorf("only %d utxo(s) indexed", len(found))
		}
		return nil
	})
	return utxos
}

// faucetOnchainAndWait faucets addr and blocks until the explorer has indexed
// the new utxo, so that a wallet reading the explorer can actually see it.
func faucetOnchainAndWait(t *testing.T, addr string, amount float64) {
	t.Helper()

	before, err := testExplorer.GetUtxos([]string{addr})
	require.NoError(t, err)

	faucetOnchain(t, addr, amount)
	waitForOnchainUtxos(t, addr, len(before)+1)
}

// waitForOffchainBalance blocks until the wallet reports at least min sats
// offchain.
func waitForOffchainBalance(t *testing.T, client wallet.Wallet, min uint64) {
	t.Helper()

	waitForBalance(
		t, client, fmt.Sprintf("offchain balance >= %d", min),
		func(b *types.Balance) bool { return b.OffchainBalance.Total >= min },
	)
}

// waitForEmptyOffchainBalance blocks until the wallet has no offchain funds
// left, e.g. after they have been unrolled onchain.
func waitForEmptyOffchainBalance(t *testing.T, client wallet.Wallet) *types.Balance {
	t.Helper()

	return waitForBalance(
		t, client, "offchain balance to drain",
		func(b *types.Balance) bool { return b.OffchainBalance.Total == 0 },
	)
}

// waitForBalance blocks until the wallet's balance satisfies cond.
func waitForBalance(
	t *testing.T, client wallet.Wallet, what string, cond func(*types.Balance) bool,
) *types.Balance {
	t.Helper()

	var balance *types.Balance
	waitUntil(t, indexerWait, what, func() error {
		b, err := client.Balance(t.Context())
		if err != nil {
			return err
		}
		balance = b
		if !cond(b) {
			return fmt.Errorf(
				"balance not settled: offchain %d, onchain spendable %d, locked entries %d",
				b.OffchainBalance.Total, b.OnchainBalance.SpendableAmount,
				len(b.OnchainBalance.LockedAmount),
			)
		}
		return nil
	})
	return balance
}

// waitForUnrolledOnchainFunds blocks until the wallet's offchain funds have
// moved onchain and are still locked by the exit delay.
func waitForUnrolledOnchainFunds(t *testing.T, client wallet.Wallet) *types.Balance {
	t.Helper()

	return waitForBalance(t, client, "offchain funds to move onchain", func(b *types.Balance) bool {
		return b.OffchainBalance.Total == 0 && len(b.OnchainBalance.LockedAmount) > 0 &&
			b.OnchainBalance.LockedAmount[0].Amount > 0
	})
}

// waitForMatureOnchainFunds blocks until unrolled funds have aged past the
// unilateral exit delay and become claimable.
//
// Maturity has to be observed as the funds leaving LockedAmount, not as
// SpendableAmount going positive: SpendableAmount also covers the plain
// onchain utxo the wallet holds for unroll fees, so it is non-zero from the
// start and would make this return immediately.
func waitForMatureOnchainFunds(t *testing.T, client wallet.Wallet) {
	t.Helper()

	waitForBalance(t, client, "unrolled funds to mature", func(b *types.Balance) bool {
		return len(b.OnchainBalance.LockedAmount) == 0 && b.OnchainBalance.SpendableAmount > 0
	})
}

// waitForOnchainSpendable blocks until the wallet reports exactly amount sats
// spendable onchain. Used when funds are sent to a wallet's onchain address,
// which it only sees once the explorer has indexed the new utxo.
func waitForOnchainSpendable(t *testing.T, client wallet.Wallet, amount uint64) *types.Balance {
	t.Helper()

	return waitForBalance(
		t, client, fmt.Sprintf("onchain spendable balance of %d", amount),
		func(b *types.Balance) bool { return b.OnchainBalance.SpendableAmount == amount },
	)
}

// waitForSpendableVtxos blocks until the wallet reports exactly n spendable
// vtxos and returns them.
func waitForSpendableVtxos(t *testing.T, client wallet.Wallet, n int) []clientlib.Vtxo {
	t.Helper()

	var vtxos []clientlib.Vtxo
	waitUntil(t, indexerWait, fmt.Sprintf("%d spendable vtxo(s)", n), func() error {
		spendable, _, err := client.ListVtxos(t.Context())
		if err != nil {
			return err
		}
		vtxos = spendable
		if len(spendable) != n {
			return fmt.Errorf("have %d spendable vtxo(s)", len(spendable))
		}
		return nil
	})
	return vtxos
}

// waitForAnySpendableVtxo blocks until the wallet reports at least one
// spendable vtxo and returns the full set.
func waitForAnySpendableVtxo(t *testing.T, client wallet.Wallet) []clientlib.Vtxo {
	t.Helper()

	var vtxos []clientlib.Vtxo
	waitUntil(t, indexerWait, "at least one spendable vtxo", func() error {
		spendable, _, err := client.ListVtxos(t.Context())
		if err != nil {
			return err
		}
		vtxos = spendable
		if len(spendable) == 0 {
			return fmt.Errorf("no spendable vtxos yet")
		}
		return nil
	})
	return vtxos
}

// waitForAnySpentVtxo blocks until the wallet reports at least one spent vtxo
// and returns the full set.
func waitForAnySpentVtxo(t *testing.T, client wallet.Wallet) []clientlib.Vtxo {
	t.Helper()

	var vtxos []clientlib.Vtxo
	waitUntil(t, indexerWait, "at least one spent vtxo", func() error {
		_, spent, err := client.ListVtxos(t.Context())
		if err != nil {
			return err
		}
		vtxos = spent
		if len(spent) == 0 {
			return fmt.Errorf("no spent vtxos yet")
		}
		return nil
	})
	return vtxos
}

// waitForSweptVtxos blocks until every spendable vtxo held by client is marked
// swept.
func waitForSweptVtxos(t *testing.T, client wallet.Wallet) []clientlib.Vtxo {
	t.Helper()

	var vtxos []clientlib.Vtxo
	waitUntil(t, sweepWait, "all vtxos to be swept", func() error {
		spendable, _, err := client.ListVtxos(t.Context())
		if err != nil {
			return err
		}
		if len(spendable) == 0 {
			return fmt.Errorf("no spendable vtxos to sweep")
		}
		unswept := 0
		for _, v := range spendable {
			if !v.Swept {
				unswept++
			}
		}
		if unswept > 0 {
			return fmt.Errorf("%d of %d vtxo(s) not swept", unswept, len(spendable))
		}
		vtxos = spendable
		return nil
	})
	return vtxos
}

// waitForVtxosInIndexer blocks until all the given vtxos are queryable as
// spendable. NotifyIncomingFunds returns off the subscription stream, which
// runs ahead of the indexer projection that ListVtxos and Balance read from.
func waitForVtxosInIndexer(t *testing.T, client wallet.Wallet, vtxos ...clientlib.Vtxo) {
	t.Helper()

	want := make(map[clientlib.Outpoint]struct{}, len(vtxos))
	for _, v := range vtxos {
		want[v.Outpoint] = struct{}{}
	}

	waitUntil(t, indexerWait, "vtxos to appear in the indexer", func() error {
		spendable, _, err := client.ListVtxos(t.Context())
		if err != nil {
			return err
		}
		found := 0
		for _, v := range spendable {
			if _, ok := want[v.Outpoint]; ok {
				found++
			}
		}
		if found != len(want) {
			return fmt.Errorf("%d of %d vtxo(s) visible", found, len(want))
		}
		return nil
	})
}

// waitForOutspendsIndexed blocks until the explorer knows about the given tx
// and can report the spent status of its output vout.
func waitForOutspendsIndexed(
	t *testing.T, explorer clientlib.Explorer, txid string, vout uint32,
) []clientlib.SpentStatus {
	t.Helper()

	var spentStatus []clientlib.SpentStatus
	waitUntil(t, chainWait, fmt.Sprintf("the explorer to index %s", txid), func() error {
		found, err := explorer.GetTxOutspends(txid)
		if err != nil {
			return err
		}
		spentStatus = found
		if len(found) <= int(vout) {
			return fmt.Errorf("tx has %d outspend entries, need index %d", len(found), vout)
		}
		return nil
	})
	return spentStatus
}

// waitForOutspend blocks until the explorer reports the given output as spent.
func waitForOutspend(t *testing.T, explorer clientlib.Explorer, txid string, vout uint32) {
	t.Helper()

	waitUntil(t, serverWait, fmt.Sprintf("%s:%d to be spent", txid, vout), func() error {
		spentStatus, err := explorer.GetTxOutspends(txid)
		if err != nil {
			return err
		}
		if len(spentStatus) <= int(vout) {
			return fmt.Errorf("tx has %d outspend entries, need index %d", len(spentStatus), vout)
		}
		if !spentStatus[vout].Spent {
			return fmt.Errorf("output not spent yet")
		}
		return nil
	})
}

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
	return runCommandWithEnv(nil, name, arg...)
}

func runCommandWithEnv(extraEnv []string, name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := newCommand(name, arg...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}

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

func bumpAndBroadcastTx(t *testing.T, tx string, explorer clientlib.Explorer) {
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
func bumpAnchorTx(t *testing.T, parent *wire.MsgTx, explorerSvc clientlib.Explorer) string {
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

	var selectedCoins []clientlib.ExplorerUtxo
	waitUntil(t, chainWait, "faucet utxo for the anchor bump", func() error {
		found, err := explorerSvc.GetUtxos([]string{addr.EncodeAddress()})
		if err != nil {
			return err
		}
		selectedCoins = found
		if len(found) != 1 {
			return fmt.Errorf("explorer reports %d utxo(s), want 1", len(found))
		}
		return nil
	})

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

func setupClientWallet(t *testing.T, prvkey ...string) wallet.Wallet {
	appDataStore, err := store.NewStore(wallet.InMemoryStore, "")
	require.NoError(t, err)

	client, err := wallet.NewWallet(appDataStore)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privkeyHex := hex.EncodeToString(privkey.Serialize())
	if len(prvkey) > 0 {
		privkeyHex = prvkey[0]
	}

	err = client.Init(t.Context(), wallet.InitArgs{
		ServerUrl:   serverUrl,
		Password:    password,
		Seed:        privkeyHex,
		ExplorerURL: explorerUrl,
	})
	require.NoError(t, err)

	err = client.Unlock(t.Context(), password)
	require.NoError(t, err)

	t.Cleanup(client.Stop)

	return client
}

func setupIdentity(t *testing.T) (clientlib.Identity, *btcec.PublicKey, error) {
	store, err := identityinmemorystore.NewStore()
	require.NoError(t, err)
	require.NotNil(t, store)

	identity, err := singlekeyidentity.NewIdentity(store)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkeyHex := hex.EncodeToString(privkey.Serialize())

	password := "password"
	ctx := t.Context()
	_, err = identity.Create(ctx, arklib.BitcoinRegTest, password, privkeyHex)
	require.NoError(t, err)

	_, err = identity.Unlock(ctx, password)
	require.NoError(t, err)

	return identity, privkey.PubKey(), nil
}

func faucet(t *testing.T, client wallet.Wallet, amount float64) {
	// Faucet offchain with note
	faucetOffchain(t, client, amount)

	onchainAddr, _, _, err := client.Receive(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, onchainAddr)
	// Faucet onchain addr to cover network fees for the unroll.
	faucetOnchainAndWait(t, onchainAddr, 0.00001)
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

func faucetOffchain(t *testing.T, client wallet.Wallet, amount float64) clientlib.Vtxo {
	_, offchainAddr, _, err := client.Receive(t.Context())
	require.NoError(t, err)

	note := generateNote(t, uint64(amount*1e8))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingFunds []clientlib.Vtxo
	var incomingErr error
	go func() {
		incomingFunds, incomingErr = notifyIncomingFunds(t.Context(), client, offchainAddr.Address)
		wg.Done()
	}()

	txid, err := client.RedeemNotes(t.Context(), []string{note})
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()

	require.NoError(t, incomingErr)
	require.NotEmpty(t, incomingFunds)

	waitForVtxosInIndexer(t, client, incomingFunds[0])
	return incomingFunds[0]
}

func faucetOffchainWithAddress(t *testing.T, addr string, amount float64) clientlib.Vtxo {
	client := setupClientWallet(t)

	_, offchainAddr, _, err := client.Receive(t.Context())
	require.NoError(t, err)

	note := generateNote(t, uint64(amount*1e8))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingFunds []clientlib.Vtxo
	var incomingErr error
	go func() {
		incomingFunds, incomingErr = notifyIncomingFunds(t.Context(), client, offchainAddr.Address)
		wg.Done()
	}()

	txid, err := client.RedeemNotes(t.Context(), []string{note})
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()

	require.NoError(t, incomingErr)
	require.NotEmpty(t, incomingFunds)

	waitForVtxosInIndexer(t, client, incomingFunds[0])

	wg.Add(1)
	incomingFunds = nil
	incomingErr = nil
	go func() {
		incomingFunds, incomingErr = notifyIncomingFunds(t.Context(), client, addr)
		wg.Done()
	}()

	res, err := client.SendOffChain(t.Context(), []clientlib.Receiver{{
		To:     addr,
		Amount: uint64(amount * 1e8),
	}})
	require.NoError(t, err)
	require.NotEmpty(t, res.Txid)

	wg.Wait()
	require.NoError(t, incomingErr)
	require.NotEmpty(t, incomingFunds)

	return incomingFunds[0]
}

func settleVtxo(t *testing.T, ctx context.Context, client wallet.Wallet, offchainAddr string) {
	t.Helper()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingFunds []clientlib.Vtxo
	var incomingErr error
	go func() {
		incomingFunds, incomingErr = notifyIncomingFunds(ctx, client, offchainAddr)
		wg.Done()
	}()

	_, err := client.Settle(ctx)
	require.NoError(t, err)

	wg.Wait()
	require.NoError(t, incomingErr)
	require.NotEmpty(t, incomingFunds)

	waitForVtxosInIndexer(t, client, incomingFunds[0])
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

type intentFees struct {
	IntentOffchainInputFeeProgram  string `json:"offchainInputFee"`
	IntentOnchainInputFeeProgram   string `json:"onchainInputFee"`
	IntentOffchainOutputFeeProgram string `json:"offchainOutputFee"`
	IntentOnchainOutputFeeProgram  string `json:"onchainOutputFee"`
}

type intentFeesResponse struct {
	Fees intentFees `json:"fees"`
}

func getIntentFees() (*intentFees, error) {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	url := fmt.Sprintf("%s/v1/admin/intentFees", adminUrl)
	resp, err := get[intentFeesResponse](adminHttpClient, url, "intent fees")
	if err != nil {
		return nil, fmt.Errorf("failed to get intent fees: %w", err)
	}

	return &resp.Fees, nil
}

func isEmptyIntentFees(fees intentFees) bool {
	return fees.IntentOffchainInputFeeProgram == "" &&
		fees.IntentOnchainInputFeeProgram == "" &&
		fees.IntentOffchainOutputFeeProgram == "" &&
		fees.IntentOnchainOutputFeeProgram == ""
}

func updateIntentFees(intentFees intentFees) error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	feesJson, err := json.Marshal(intentFees)
	if err != nil {
		return fmt.Errorf("failed to marshal intent fees: %s", err)
	}

	body := fmt.Sprintf(`{"fees": %s}`, feesJson)

	url := fmt.Sprintf("%s/v1/admin/intentFees", adminUrl)
	if err := post(adminHttpClient, url, body, "updateIntentFees"); err != nil {
		return fmt.Errorf("failed to update intent fees: %s", err)
	}

	return nil
}

type collectedFeesResponse struct {
	CollectedFees uint64 `json:"collectedFees,string"`
}

func getCollectedFees(after, before int64) (uint64, error) {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	url := fmt.Sprintf("%s/v1/admin/fees/collected?after=%d&before=%d", adminUrl, after, before)
	resp, err := get[collectedFeesResponse](adminHttpClient, url, "collected fees")
	if err != nil {
		return 0, fmt.Errorf("failed to get collected fees: %w", err)
	}

	return resp.CollectedFees, nil
}

func clearIntentFees() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	url := fmt.Sprintf("%s/v1/admin/intentFees/clear", adminUrl)
	if err := post(adminHttpClient, url, "", "clearIntentFees"); err != nil {
		return fmt.Errorf("failed to clear intent fees: %s", err)
	}

	return nil
}

// restart the arkd container and unlock its wallet
func restartArkd() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	// docker stop/start block until the container has changed state, so the
	// only thing left to wait on is the admin API accepting requests again.
	if _, err := runCommand("docker", "container", "stop", "arkd"); err != nil {
		return err
	}

	if _, err := runCommand("docker", "container", "start", "arkd"); err != nil {
		return err
	}

	if err := unlockArkd(adminHttpClient); err != nil {
		return err
	}

	// wait until the wallet is synced again before returning, otherwise RPCs
	// racing the restart get "server not ready".
	if err := waitUntilReady(adminHttpClient); err != nil {
		return err
	}

	// The admin wallet status and the gRPC readiness gate are separate
	// signals: the public service keeps rejecting calls with "server not
	// ready" until the app service has started, which happens after the
	// wallet reports ready.
	return waitUntilArkServiceReady()
}

// waitUntilArkServiceReady polls the public gRPC surface until it stops
// rejecting calls through the readiness interceptor.
func waitUntilArkServiceReady() error {
	client, err := grpcclient.NewClient(serverUrl, "")
	if err != nil {
		return err
	}
	defer client.Close()

	deadline := time.Now().Add(2 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, lastErr = client.GetInfo(context.Background()); lastErr == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the ark service to be ready: %w", lastErr)
}

// unlockArkd posts the unlock request, retrying until the admin API is
// listening again after a container restart.
func unlockArkd(httpClient *http.Client) error {
	url := fmt.Sprintf("%s/v1/admin/wallet/unlock", adminUrl)
	body := fmt.Sprintf(`{"password": "%s"}`, password)
	return postWithRetry(httpClient, url, body, "unlock", time.Minute)
}

// postWithRetry retries post until it succeeds or timeout elapses. The admin
// API refuses connections for an unpredictable stretch after a restart.
func postWithRetry(
	httpClient *http.Client, url, body, name string, timeout time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = post(httpClient, url, body, name); lastErr == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s retrying %s: %w", timeout, name, lastErr)
}

// recreate the arkd-wallet container with overridden signer keys, reusing the
// named data volume so the seed persists, then unlock it and restart arkd so it
// re-fetches the signer pubkey.
func recreateArkdWallet(signerKey, deprecated string) error {
	env := []string{
		"ARKD_WALLET_SIGNER_KEY=" + signerKey,
		"ARKD_WALLET_DEPRECATED_SIGNER_KEYS=" + deprecated,
	}
	args := []string{
		"compose", "-f", "../../../docker-compose.regtest.yml",
		"up", "-d", "--force-recreate", "--no-deps", "arkd-wallet",
	}
	if _, err := runCommandWithEnv(env, "docker", args...); err != nil {
		return fmt.Errorf("failed to recreate arkd-wallet: %w", err)
	}

	if err := unlockArkdWallet(); err != nil {
		return err
	}

	// restartArkd waits for arkd to report ready, so there is nothing to wait
	// on here beyond the wallet accepting the unlock.
	return restartArkd()
}

func unlockArkdWallet() error {
	adminHttpClient := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("%s/v1/admin/wallet/unlock", adminUrl)
	body := fmt.Sprintf(`{"password": "%s"}`, password)
	return postWithRetry(adminHttpClient, url, body, "unlock", time.Minute)
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

	if status.Initialized {
		if !status.Unlocked {
			if err := unlockArkd(adminHttpClient); err != nil {
				return err
			}
		}

		// An initialised wallet is never re-created, even when it is still
		// syncing; wait for it instead.
		if err := waitUntilReady(adminHttpClient); err != nil {
			return err
		}

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

	if err := unlockArkd(adminHttpClient); err != nil {
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

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to %s wallet: %s", name, err)
	}
	defer resp.Body.Close()

	// The status has to be checked: a wallet that is listening but not yet
	// able to serve the request answers with a 5xx, and treating that as
	// success lets callers proceed against a wallet that is not ready.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf(
			"failed to %s wallet: status %d: %s",
			name, resp.StatusCode, strings.TrimSpace(string(msg)),
		)
	}
	return nil
}

func waitUntilReady(httpClient *http.Client) error {
	url := fmt.Sprintf("%s/v1/admin/wallet/status", adminUrl)
	deadline := time.Now().Add(2 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		status, err := get[statusResp](httpClient, url, "status")
		if err != nil {
			// The admin API refuses connections until arkd is listening again.
			lastErr = err
		} else if status.Initialized && status.Unlocked && status.Synced {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("timed out waiting for arkd to be ready: %w", lastErr)
	}
	return fmt.Errorf("timed out waiting for arkd to be ready")
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

func listVtxosWithAsset(t *testing.T, client wallet.Wallet, assetID string) []clientlib.Vtxo {
	t.Helper()
	vtxos, _, err := client.ListVtxos(t.Context())
	require.NoError(t, err)

	assetVtxos := make([]clientlib.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		for _, asset := range vtxo.Assets {
			if asset.AssetId == assetID {
				assetVtxos = append(assetVtxos, vtxo)
				break
			}
		}
	}
	return assetVtxos
}

// waitForAssetVtxos blocks until the wallet holds exactly n vtxos carrying the
// given asset and returns them.
func waitForAssetVtxos(
	t *testing.T, client wallet.Wallet, assetID string, n int,
) []clientlib.Vtxo {
	t.Helper()

	var assetVtxos []clientlib.Vtxo
	waitUntil(t, indexerWait, fmt.Sprintf("%d vtxo(s) with asset %s", n, assetID), func() error {
		vtxos, _, err := client.ListVtxos(t.Context())
		if err != nil {
			return err
		}
		assetVtxos = assetVtxos[:0]
		for _, vtxo := range vtxos {
			if _, ok := findAssetInVtxo(vtxo, assetID); ok {
				assetVtxos = append(assetVtxos, vtxo)
			}
		}
		if len(assetVtxos) != n {
			return fmt.Errorf("have %d vtxo(s) with the asset", len(assetVtxos))
		}
		return nil
	})
	return assetVtxos
}

// waitForAssetBalance blocks until the wallet reports the given asset balance.
func waitForAssetBalance(t *testing.T, client wallet.Wallet, assetID string, amount uint64) {
	t.Helper()

	waitUntil(t, indexerWait, fmt.Sprintf("asset %s balance of %d", assetID, amount), func() error {
		balance, err := client.Balance(t.Context())
		if err != nil {
			return err
		}
		if got := balance.AssetBalances[assetID]; got != amount {
			return fmt.Errorf("asset balance is %d", got)
		}
		return nil
	})
}

func findAssetInVtxo(vtxo clientlib.Vtxo, assetID string) (clientlib.Asset, bool) {
	for _, asset := range vtxo.Assets {
		if asset.AssetId == assetID {
			return asset, true
		}
	}
	return clientlib.Asset{}, false
}

// requireVtxoHasAsset asserts that the given VTXO contains an asset with the given ID and amount.
func requireVtxoHasAsset(t *testing.T, vtxo clientlib.Vtxo, assetID string, expectedAmount uint64) {
	t.Helper()
	asset, found := findAssetInVtxo(vtxo, assetID)
	require.True(t, found)
	require.Equal(t, expectedAmount, asset.Amount, assetID)
}

func churnWorkerBackoff(workerID int) time.Duration {
	return time.Duration(5+workerID%11) * time.Millisecond
}

// isTransientProducerError reports whether err is the tx producer losing a
// race with its own wallet state rather than a failure of the fanout under
// test. The producer sends every few hundred milliseconds and each send spends
// the change vtxo of the previous one, so it can outrun the indexer: the
// wallet then either cannot select coins yet, or resubmits a tx the server has
// already seen. Neither says anything about the listener behaviour the churn
// tests exist to exercise.
func isTransientProducerError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())
	signatures := []string{
		"not enough funds",
		"missing funds",
		"duplicated offchain tx",
		"duplicated input",
	}

	for _, sig := range signatures {
		if strings.Contains(errMsg, sig) {
			return true
		}
	}
	return false
}

func isRetryableChurnError(err error) bool {
	if err == nil {
		return false
	}

	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded:
			return true
		}
	}

	errMsg := strings.ToLower(err.Error())
	// edge cases not caught by gRPC status codes
	signatures := []string{
		"assign requested address",
		"error reading server preface",
		"connection reset by peer",
		"transport is closing",
		"broken pipe",
		"eof",
	}

	for _, sig := range signatures {
		if strings.Contains(errMsg, sig) {
			return true
		}
	}

	return false
}

func waitForVTXOs(
	ch <-chan clientlib.ScriptEvent, atLeastN int, timeout time.Duration,
) ([]clientlib.Vtxo, error) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(timeout))
	defer cancel()
	vtxos := make([]clientlib.Vtxo, 0)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out - %d/%d received", len(vtxos), atLeastN)
		case evt, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("vtxo event channel closed")
			}
			if evt.Connection != nil {
				continue
			}

			if evt.Err != nil {
				return nil, evt.Err
			}
			vtxos = append(vtxos, evt.Data.NewVtxos...)
		}

		if len(vtxos) >= atLeastN {
			return vtxos, nil
		}
	}
}
