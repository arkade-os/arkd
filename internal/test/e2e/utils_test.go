package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	singlekeyidentity "github.com/arkade-os/arkd/pkg/client-wallet/identity"
	identityinmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-wallet/store"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
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
	// batchWait bounds a single batch-session call: Settle, CollaborativeExit,
	// RedeemNotes, or a hand-rolled JoinBatch. Such a call returns only when
	// the server's event stream carries the batch to a terminal state, and
	// that stream has no deadline of its own. A batch spans at least one
	// session (ARKD_SESSION_DURATION=10s) plus tree signing, and a
	// participant that arrives mid-session waits for the next one, so a
	// healthy call finishes in tens of seconds even on a loaded runner. The
	// bound is an order of magnitude above that: it only fires when nothing
	// is coming.
	batchWait = 4 * time.Minute
	// offchainWait bounds a single offchain-tx round trip (SendOffChain).
	// These are request/response calls that complete in tens of
	// milliseconds when healthy; the churn tests already give their own
	// sends a 20s budget. This is deliberately far above that so that only a
	// genuinely stuck call trips it.
	offchainWait = 90 * time.Second
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
func waitUntil(
	t *testing.T, timeout time.Duration, what string, cond func(context.Context) error,
) {
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
		// Each poll runs on its own cancellable context. A call still in
		// flight when the deadline passes is aborted rather than left running
		// after the test goroutine has been stopped by FailNow, which would
		// leak the goroutine and keep writing to variables the condition
		// captured.
		iterCtx, cancelIter := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- cond(iterCtx) }()

		select {
		case err := <-done:
			cancelIter()
			if err == nil {
				return
			}
			lastErr = err
		case <-time.After(time.Until(deadline)):
			cancelIter()
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

	// An empty result is not an error: some callers deliberately spend
	// everything so that nothing lands back at addr. Callers that require
	// funds assert that themselves.
	funds, err := client.NotifyIncomingFunds(notifyCtx, addr)
	if err != nil {
		if notifyCtx.Err() != nil && ctx.Err() == nil {
			return nil, fmt.Errorf("no funds received at %s within %s", addr, notifyWait)
		}
		return nil, err
	}
	return funds, nil
}

// runBounded runs call under a context of its own that expires after bound, so
// a client call which would otherwise block forever fails its own test with a
// legible message instead of hanging the whole package.
//
// The two ways the call context can end are reported differently on purpose.
// If our own bound expired, that is a fault worth naming: what timed out, on
// which wallet, and after how long. If the parent context went away instead —
// the test ended, or the caller imposed a shorter round deadline — the
// underlying error is returned untouched, because attributing someone else's
// cancellation to our bound sends the reader after the wrong problem.
//
// The underlying error is wrapped, never replaced, so assertions that match on
// the server's own message still see it.
func runBounded[T any](
	ctx context.Context, bound time.Duration, what string,
	call func(context.Context) (T, error),
) (T, error) {
	callCtx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()

	res, err := call(callCtx)
	if err != nil && callCtx.Err() != nil && ctx.Err() == nil {
		return res, fmt.Errorf("%s did not complete within %s: %w", what, bound, err)
	}
	return res, err
}

// walletID names a wallet in an error message, so that a timeout in a test
// driving several wallets says which one got stuck. The identity is held in
// memory and ignores the context, so this neither blocks nor needs a live one.
func walletID(client wallet.Wallet) string {
	key, err := client.Identity().GetKey(context.Background(), "")
	if err != nil || key == nil || key.PubKey == nil {
		return "an unidentified wallet"
	}
	return "wallet " + hex.EncodeToString(key.PubKey.SerializeCompressed())[:8]
}

// The wrappers below bound the client calls that have no deadline of their
// own. Callers routinely run one of these on a goroutine and then block on a
// WaitGroup; the context they share is the test context, which is cancelled
// only when the test ends. A call that never returns therefore holds the
// WaitGroup, the WaitGroup holds the test, and the test holds the context that
// would have released the call — an unbreakable cycle that burns the entire
// `go test` budget and discards every other test's result with it.
//
// Their names deliberately do not mirror the methods they wrap
// (settleBounded, not settle): a wrapper named after its own method can be
// turned into an infinite self-call by a search and replace over the method
// name, which neither the compiler nor go vet would catch. Each body below
// calls the wallet method exactly once and calls no wrapper at all.

// settleBounded bounds client.Settle, which joins a batch session and returns
// only when the server's event stream reaches a terminal state.
func settleBounded(
	ctx context.Context, client wallet.Wallet, opts ...batchsession.Option,
) (*wallet.SettleRes, error) {
	return runBounded(
		ctx, batchWait, fmt.Sprintf("settle for %s", walletID(client)),
		func(callCtx context.Context) (*wallet.SettleRes, error) {
			return client.Settle(callCtx, opts...)
		},
	)
}

// collaborativeExitBounded bounds client.CollaborativeExit, which joins a
// batch session paying out to an onchain address.
func collaborativeExitBounded(
	ctx context.Context, client wallet.Wallet, addr string, amount uint64,
	opts ...batchsession.Option,
) (*wallet.CollaborativeExitRes, error) {
	return runBounded(
		ctx, batchWait,
		fmt.Sprintf("collaborative exit of %d sats to %s by %s", amount, addr, walletID(client)),
		func(callCtx context.Context) (*wallet.CollaborativeExitRes, error) {
			return client.CollaborativeExit(callCtx, addr, amount, opts...)
		},
	)
}

// redeemNotesBounded bounds client.RedeemNotes, which joins a batch session
// with the notes as inputs.
func redeemNotesBounded(
	ctx context.Context, client wallet.Wallet, notes []string, opts ...batchsession.Option,
) (*wallet.RedeemNotesRes, error) {
	return runBounded(
		ctx, batchWait,
		fmt.Sprintf("redemption of %d note(s) by %s", len(notes), walletID(client)),
		func(callCtx context.Context) (*wallet.RedeemNotesRes, error) {
			return client.RedeemNotes(callCtx, notes, opts...)
		},
	)
}

// batchSettleBounded bounds the SDK-level batchsession.Settle, used by the
// tests that present hand-built boarding inputs the wallet would not select.
func batchSettleBounded(
	ctx context.Context, args batchsession.SettleArgs, opts ...batchsession.Option,
) (*batchsession.BatchTxRes, error) {
	return runBounded(
		ctx, batchWait, fmt.Sprintf("batch settle paying %s", args.ReceiverAddr),
		func(callCtx context.Context) (*batchsession.BatchTxRes, error) {
			return batchsession.Settle(callCtx, args, opts...)
		},
	)
}

// joinBatchBounded bounds batchsession.JoinBatch, used by the tests that drive
// the batch flow through their own event handler. Those handlers deliberately
// misbehave, which makes reaching a terminal state the server's job alone —
// exactly the case where a missing event would hang forever.
func joinBatchBounded(
	ctx context.Context, args batchsession.JoinBatchArgs, opts ...batchsession.Option,
) (*batchsession.BatchTxRes, error) {
	return runBounded(
		ctx, batchWait, fmt.Sprintf("batch session for intent %s", args.IntentId),
		func(callCtx context.Context) (*batchsession.BatchTxRes, error) {
			return batchsession.JoinBatch(callCtx, args, opts...)
		},
	)
}

// sendOffChainBounded bounds client.SendOffChain. Unlike the batch calls this
// is a request/response round trip, but it still carries no deadline, and it
// is the call most often paired with a notifyIncomingFunds goroutine.
func sendOffChainBounded(
	ctx context.Context, client wallet.Wallet, receivers []clientlib.Receiver,
	opts ...offchaintx.Option,
) (*wallet.SendOffChainRes, error) {
	return runBounded(
		ctx, offchainWait,
		fmt.Sprintf("offchain send of %d output(s) by %s", len(receivers), walletID(client)),
		func(callCtx context.Context) (*wallet.SendOffChainRes, error) {
			return client.SendOffChain(callCtx, receivers, opts...)
		},
	)
}

// waitForOnchainUtxos blocks until the explorer reports at least n utxos for
// addr and returns them.
func waitForOnchainUtxos(t *testing.T, addr string, n int) []clientlib.ExplorerUtxo {
	t.Helper()

	var utxos []clientlib.ExplorerUtxo
	waitUntil(t, chainWait, fmt.Sprintf("%d utxo(s) at %s", n, addr), func(ctx context.Context) error {
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
		t, client, indexerWait, fmt.Sprintf("offchain balance >= %d", min),
		func(b *types.Balance) bool { return b.OffchainBalance.Total >= min },
	)
}

// waitForEmptyOffchainBalance blocks until the wallet has no offchain funds
// left, e.g. after they have been unrolled onchain.
func waitForEmptyOffchainBalance(t *testing.T, client wallet.Wallet) *types.Balance {
	t.Helper()

	return waitForBalance(
		t, client, indexerWait, "offchain balance to drain",
		func(b *types.Balance) bool { return b.OffchainBalance.Total == 0 },
	)
}

// waitForBalance blocks until the wallet's balance satisfies cond.
// waitForBalance polls the wallet balance until cond holds. The bound is the
// caller's: offchain totals settle with the indexer projection, while onchain
// figures are the wallet re-reading the explorer, which is slower.
func waitForBalance(
	t *testing.T, client wallet.Wallet, bound time.Duration, what string,
	cond func(*types.Balance) bool,
) *types.Balance {
	t.Helper()

	var balance *types.Balance
	waitUntil(t, bound, what, func(ctx context.Context) error {
		b, err := client.Balance(ctx)
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

	return waitForBalance(t, client, chainWait, "offchain funds to move onchain",
		func(b *types.Balance) bool {
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

	waitForBalance(t, client, chainWait, "unrolled funds to mature",
		func(b *types.Balance) bool {
			return len(b.OnchainBalance.LockedAmount) == 0 && b.OnchainBalance.SpendableAmount > 0
		})
}

// waitForOnchainSpendable blocks until the wallet reports exactly amount sats
// spendable onchain. Used when funds are sent to a wallet's onchain address,
// which it only sees once the explorer has indexed the new utxo.
func waitForOnchainSpendable(t *testing.T, client wallet.Wallet, amount uint64) *types.Balance {
	t.Helper()

	return waitForBalance(
		t, client, chainWait, fmt.Sprintf("onchain spendable balance of %d", amount),
		func(b *types.Balance) bool { return b.OnchainBalance.SpendableAmount == amount },
	)
}

// waitForSpendableVtxos blocks until the wallet reports exactly n spendable
// vtxos and returns them.
func waitForSpendableVtxos(t *testing.T, client wallet.Wallet, n int) []clientlib.Vtxo {
	t.Helper()

	var vtxos []clientlib.Vtxo
	waitUntil(t, indexerWait, fmt.Sprintf("%d spendable vtxo(s)", n), func(ctx context.Context) error {
		spendable, _, err := client.ListVtxos(ctx)
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
	waitUntil(t, indexerWait, "at least one spendable vtxo", func(ctx context.Context) error {
		spendable, _, err := client.ListVtxos(ctx)
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
	waitUntil(t, indexerWait, "at least one spent vtxo", func(ctx context.Context) error {
		_, spent, err := client.ListVtxos(ctx)
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
	waitUntil(t, sweepWait, "all vtxos to be swept", func(ctx context.Context) error {
		spendable, _, err := client.ListVtxos(ctx)
		if err != nil {
			return err
		}
		if len(spendable) == 0 {
			return fmt.Errorf("no spendable vtxos yet")
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

	waitUntil(t, indexerWait, "vtxos to appear in the indexer", func(ctx context.Context) error {
		spendable, _, err := client.ListVtxos(ctx)
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
	waitUntil(t, chainWait, fmt.Sprintf("the explorer to index %s", txid), func(ctx context.Context) error {
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

	waitUntil(t, serverWait, fmt.Sprintf("%s:%d to be spent", txid, vout), func(ctx context.Context) error {
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
	waitUntil(t, chainWait, "faucet utxo for the anchor bump", func(ctx context.Context) error {
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

	txid, err := redeemNotesBounded(t.Context(), client, []string{note})
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

	txid, err := redeemNotesBounded(t.Context(), client, []string{note})
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

	res, err := sendOffChainBounded(t.Context(), client, []clientlib.Receiver{{
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

	_, err := settleBounded(ctx, client)
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

		// The wallet reporting ready is not the same signal as the public
		// gRPC surface accepting calls, which is gated separately on the app
		// service having started. Clients created before that gate opens fail
		// with "server not ready".
		if err := waitUntilArkServiceReady(); err != nil {
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

	if err := waitUntilArkServiceReady(); err != nil {
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
	defer resp.Body.Close()

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
	waitUntil(t, indexerWait, fmt.Sprintf("%d vtxo(s) with asset %s", n, assetID), func(ctx context.Context) error {
		vtxos, _, err := client.ListVtxos(ctx)
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

	waitUntil(t, indexerWait, fmt.Sprintf("asset %s balance of %d", assetID, amount), func(ctx context.Context) error {
		balance, err := client.Balance(ctx)
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

	// These match server and client-lib error text rather than status codes,
	// because both arrive as InvalidArgument and only the message separates
	// "the producer outran its own wallet" from a real rejection. If any is
	// reworded these stop classifying and the churn tests will report the
	// error as a fanout failure, which is the safe direction to fail.
	//   "not enough funds"/"missing funds" - coin selection in
	//     pkg/client-lib, the change vtxo of the previous send is not
	//     spendable yet
	//   "duplicated offchain tx"/"duplicated input" - the server has already
	//     seen this tx or one of its inputs
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

// boardingSurplusBatch is the outcome of a batch made of one offchain intent and one boarding
// intent, see settleBoardingSurplusBatch.
type boardingSurplusBatch struct {
	aliceVtxo    clientlib.Vtxo
	bobVtxo      clientlib.Vtxo
	commitmentTx *wire.MsgTx
}

// batchOutput returns the value of the commitment tx output funding the vtxo tree, ie. the one
// at index 0.
func (b boardingSurplusBatch) batchOutput() int64 {
	return b.commitmentTx.TxOut[0].Value
}

// connectorOutput returns the value of the commitment tx output funding the connectors tree, ie.
// the one at index 1.
func (b boardingSurplusBatch) connectorOutput() int64 {
	return b.commitmentTx.TxOut[1].Value
}

// boardingSurplus returns the boarding input value the coin selection target doesn't account
// for, ie. what is left of the boarding input once it has funded the batch and connector
// outputs.
func (b boardingSurplusBatch) boardingSurplus(boardingAmount int64) int64 {
	return boardingAmount - (b.batchOutput() + b.connectorOutput())
}

// settleBoardingSurplusBatch charges onchainInputFee on every boarding input, funds bob offchain
// and alice's boarding address, then makes them settle together in the same batch.
func settleBoardingSurplusBatch(
	t *testing.T, onchainInputFee, bobVtxoAmount, aliceBoardingAmount uint64,
) boardingSurplusBatch {
	t.Helper()

	// only the boarding input is charged, so bob's vtxo and both vtxo outputs keep their
	// nominal amount and the arithmetic of the batch stays predictable.
	require.NoError(t, updateIntentFees(intentFees{
		IntentOffchainInputFeeProgram:  "0.0",
		IntentOnchainInputFeeProgram:   fmt.Sprintf("%d.0", onchainInputFee),
		IntentOffchainOutputFeeProgram: "0.0",
		IntentOnchainOutputFeeProgram:  "0.0",
	}))

	ctx := t.Context()

	// the clients cache the fee programs at init time, so they must be created after the update
	alice := setupClientWallet(t)
	bob := setupClientWallet(t)

	_, aliceOffchainAddr, aliceBoardingAddr, err := alice.Receive(ctx)
	require.NoError(t, err)
	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	faucetOffchain(t, bob, float64(bobVtxoAmount)/1e8)
	faucetOnchainAndWait(t, aliceBoardingAddr.Address, float64(aliceBoardingAmount)/1e8)

	wg := &sync.WaitGroup{}
	wg.Add(4)

	var aliceFunds, bobFunds []clientlib.Vtxo
	var aliceFundsErr, bobFundsErr error
	go func() {
		aliceFunds, aliceFundsErr = notifyIncomingFunds(ctx, alice, aliceOffchainAddr.Address)
		wg.Done()
	}()
	go func() {
		bobFunds, bobFundsErr = notifyIncomingFunds(ctx, bob, bobOffchainAddr.Address)
		wg.Done()
	}()

	var aliceRes, bobRes *batchsession.BatchTxRes
	var aliceErr, bobErr error
	go func() {
		aliceRes, aliceErr = settleBounded(ctx, alice)
		wg.Done()
	}()
	go func() {
		bobRes, bobErr = settleBounded(ctx, bob)
		wg.Done()
	}()

	wg.Wait()

	require.NoError(t, aliceErr)
	require.NoError(t, bobErr)
	require.NoError(t, aliceFundsErr)
	require.NoError(t, bobFundsErr)
	require.NotNil(t, aliceRes)
	require.NotNil(t, bobRes)
	require.NotEmpty(t, aliceRes.CommitmentTxid)
	// both intents must land in the same batch, otherwise the boarding input is alone in its
	// commitment tx and the case under test is not the one being exercised
	require.Equal(t, aliceRes.CommitmentTxid, bobRes.CommitmentTxid)
	require.Len(t, aliceFunds, 1)
	require.Len(t, bobFunds, 1)

	return boardingSurplusBatch{
		aliceVtxo:    aliceFunds[0],
		bobVtxo:      bobFunds[0],
		commitmentTx: fetchTx(t, aliceRes.CommitmentTxid),
	}
}

// getServerDust returns the dust limit advertised by the server.
func getServerDust(t *testing.T) uint64 {
	t.Helper()

	info, err := setupClientWallet(t).Client().GetInfo(t.Context())
	require.NoError(t, err)

	return info.Dust
}

// fetchTx returns the onchain tx with the given txid, waiting for the explorer to see it.
func fetchTx(t *testing.T, txid string) *wire.MsgTx {
	t.Helper()

	var txHex string
	waitUntil(t, chainWait, fmt.Sprintf("the explorer to index tx %s", txid), func(ctx context.Context) error {
		hex, err := testExplorer.GetTxHex(txid)
		if err != nil {
			return err
		}
		txHex = hex
		return nil
	})

	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))))

	return &tx
}


// overwriteStage selects which of alice's entries mallory replaces.
type overwriteStage int

const (
	overwriteNothing overwriteStage = iota
	overwriteNonces
	overwriteSignatures
)

type overwriteResult struct {
	forged         bool
	victims        []string
	forgeErr       error
	aliceErr       error
	roundId        string
	convictions    []roundConviction
	convictionsRaw string
	// input scripts of each participant, so a conviction can be attributed
	aliceScript   string
	malloryScript string
}

// runCosignerOverwrite puts alice and mallory in one batch, both driving the production
// handler, and has mallory overwrite alice's entry at the given stage.
func runCosignerOverwrite(t *testing.T, stage overwriteStage) overwriteResult {
	t.Helper()

	alice := setupClientWallet(t)
	mallory := setupClientWallet(t)
	aliceClient, malloryClient := alice.Client(), mallory.Client()

	_, aliceAddr, _, err := alice.Receive(t.Context())
	require.NoError(t, err)
	_, malloryAddr, _, err := mallory.Receive(t.Context())
	require.NoError(t, err)

	faucetOffchain(t, alice, 0.001)
	faucetOffchain(t, mallory, 0.001)

	// faucetOffchain's vtxo carries no tapscripts, which the forfeit step needs
	aliceVtxos, _, err := alice.ListVtxos(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, aliceVtxos)
	malloryVtxos, _, err := mallory.ListVtxos(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, malloryVtxos)

	aliceVtxo, malloryVtxo := aliceVtxos[0], malloryVtxos[0]
	require.NotEmpty(t, aliceVtxo.Tapscripts, "alice's vtxo carries no tapscripts")
	require.NotEqual(t, aliceVtxo.Script, malloryVtxo.Script,
		"alice and mallory share an input script, convictions could not be attributed")

	aliceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	malloryKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	aliceSigner := tree.NewTreeSignerSession(aliceKey)
	mallorySigner := tree.NewTreeSignerSession(malloryKey)

	cfgData, err := alice.GetConfigData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, cfgData)

	// registered up front so both sit in the queue when the window closes
	aliceIntentId, err := alice.RegisterIntent(
		t.Context(),
		[]clientlib.Vtxo{aliceVtxo}, []clientlib.Utxo{}, nil,
		[]clientlib.Receiver{{Amount: aliceVtxo.Amount, To: aliceAddr.Address}},
		[]string{aliceSigner.GetPublicKey()},
	)
	require.NoError(t, err)

	malloryIntentId, err := mallory.RegisterIntent(
		t.Context(),
		[]clientlib.Vtxo{malloryVtxo}, []clientlib.Utxo{}, nil,
		[]clientlib.Receiver{{Amount: malloryVtxo.Amount, To: malloryAddr.Address}},
		[]string{mallorySigner.GetPublicKey()},
	)
	require.NoError(t, err)

	aliceArgs := batchsession.JoinBatchArgs{
		BaseArgs: batchsession.BaseArgs{
			SignTx: alice.SignTransaction,
			Vtxos:  []clientlib.Vtxo{aliceVtxo},
			Outputs: []clientlib.Receiver{{
				To: aliceAddr.Address, Amount: aliceVtxo.Amount,
			}},
		},
		TreeSigners:  []tree.SignerSession{aliceSigner},
		IntentId:     aliceIntentId,
		Client:       aliceClient,
		ServerParams: *cfgData,
	}
	malloryArgs := batchsession.JoinBatchArgs{
		BaseArgs: batchsession.BaseArgs{
			SignTx: mallory.SignTransaction,
			Vtxos:  []clientlib.Vtxo{malloryVtxo},
			Outputs: []clientlib.Receiver{{
				To: malloryAddr.Address, Amount: malloryVtxo.Amount,
			}},
		},
		TreeSigners:  []tree.SignerSession{mallorySigner},
		IntentId:     malloryIntentId,
		Client:       malloryClient,
		ServerParams: *cfgData,
	}

	aliceBase, err := batchsessionhandler.NewDefaultHandler(defaultHandlerArgs(aliceArgs))
	require.NoError(t, err)
	malloryBase, err := batchsessionhandler.NewDefaultHandler(defaultHandlerArgs(malloryArgs))
	require.NoError(t, err)

	var (
		mu       sync.Mutex
		res      overwriteResult
		aliceRnd string
	)

	// closed once alice has submitted the set mallory is about to overwrite
	aliceSubmitted := make(chan struct{})
	var closeOnce sync.Once
	signalAlice := func() { closeOnce.Do(func() { close(aliceSubmitted) }) }

	// forge once, after alice has submitted
	var forgeOnce sync.Once

	forge := func(ctx context.Context, submit func(pubkey string) error) error {
		var outer error
		forgeOnce.Do(func() {
			if err := waitFor(ctx, aliceSubmitted); err != nil {
				outer = err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, pubkey := range res.victims {
				res.forged = true
				res.forgeErr = submit(pubkey)
			}
		})
		return outer
	}

	// learned from the broadcast cosigner list
	recordVictims := func(event clientlib.TreeSigningStartedEvent, mine string) {
		mu.Lock()
		defer mu.Unlock()
		if res.victims != nil {
			return
		}
		for _, pubkey := range event.CosignersPubkeys {
			if pubkey != mine {
				res.victims = append(res.victims, pubkey)
			}
		}
	}

	aliceHandler := &interposingHandler{
		Handler: aliceBase, mu: &mu, roundId: &aliceRnd,
		afterNonces: func() {
			if stage == overwriteNonces {
				signalAlice()
			}
		},
		afterSigs: func() {
			if stage == overwriteSignatures {
				signalAlice()
			}
		},
	}

	malloryHandler := &interposingHandler{
		Handler: malloryBase, mu: &mu, roundId: &res.roundId,
		beforeNonces: func(ctx context.Context, event clientlib.TreeSigningStartedEvent, vtxoTree *tree.TxTree) error {
			mine := mallorySigner.GetPublicKey()
			recordVictims(event, mine)
			if stage != overwriteNonces {
				return nil
			}
			txids, err := cosignedTxids(vtxoTree, mine)
			if err != nil {
				return err
			}
			return forge(ctx, func(pubkey string) error {
				nonces, err := forgedNonces(txids, malloryKey.PubKey())
				if err != nil {
					return err
				}
				return malloryClient.SubmitTreeNonces(ctx, event.Id, pubkey, nonces)
			})
		},
		beforeSigs: func(ctx context.Context, event clientlib.TreeNoncesEvent, vtxoTree *tree.TxTree) error {
			if stage != overwriteSignatures {
				return nil
			}
			txids, err := cosignedTxids(vtxoTree, mallorySigner.GetPublicKey())
			if err != nil {
				return err
			}
			return forge(ctx, func(pubkey string) error {
				sigs, err := forgedSigs(txids)
				if err != nil {
					return err
				}
				return malloryClient.SubmitTreeSignatures(ctx, event.Id, pubkey, sigs)
			})
		},
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer signalAlice() // never strand mallory's gate
		_, res.aliceErr = joinBatchBounded(
			t.Context(), aliceArgs, batchsession.WithHandler(aliceHandler),
		)
	}()

	go func() {
		defer wg.Done()
		// nolint:errcheck
		joinBatchBounded(t.Context(), malloryArgs, batchsession.WithHandler(malloryHandler))
	}()

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if res.roundId != "" {
		res.convictions, res.convictionsRaw = convictionsByRound(t, res.roundId)
	}
	res.aliceScript, res.malloryScript = aliceVtxo.Script, malloryVtxo.Script
	return res
}

// interposingHandler wraps the production handler, running a hook around the step it
// delegates to. Everything else is the real client, so a participant is correct by
// construction rather than by imitation.
type interposingHandler struct {
	batchsessionhandler.Handler

	mu      *sync.Mutex
	roundId *string
	// captured at signing start so the signature hook can see it
	vtxoTree *tree.TxTree

	beforeNonces func(context.Context, clientlib.TreeSigningStartedEvent, *tree.TxTree) error
	afterNonces  func()
	beforeSigs   func(context.Context, clientlib.TreeNoncesEvent, *tree.TxTree) error
	afterSigs    func()
}

func (h *interposingHandler) OnBatchStarted(
	ctx context.Context, event clientlib.BatchStartedEvent,
) (bool, time.Duration, error) {
	skip, expiry, err := h.Handler.OnBatchStarted(ctx, event)
	if !skip && err == nil {
		h.mu.Lock()
		*h.roundId = event.Id
		h.mu.Unlock()
	}
	return skip, expiry, err
}

// OnBatchFailed ignores other rounds; the default errors on any failed round, including the
// "not enough intents" aborts firing while we wait for the other participant.
func (h *interposingHandler) OnBatchFailed(
	ctx context.Context, event clientlib.BatchFailedEvent,
) error {
	h.mu.Lock()
	mine := *h.roundId
	h.mu.Unlock()
	if event.Id != mine {
		return nil
	}
	return h.Handler.OnBatchFailed(ctx, event)
}

func (h *interposingHandler) OnTreeSigningStarted(
	ctx context.Context, event clientlib.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	h.vtxoTree = vtxoTree
	if h.beforeNonces != nil {
		if err := h.beforeNonces(ctx, event, vtxoTree); err != nil {
			return false, err
		}
	}
	skip, err := h.Handler.OnTreeSigningStarted(ctx, event, vtxoTree)
	if h.afterNonces != nil && !skip && err == nil {
		h.afterNonces()
	}
	return skip, err
}

func (h *interposingHandler) OnTreeNonces(
	ctx context.Context, event clientlib.TreeNoncesEvent,
) (bool, error) {
	if h.beforeSigs != nil {
		if err := h.beforeSigs(ctx, event, h.vtxoTree); err != nil {
			return false, err
		}
	}
	signed, err := h.Handler.OnTreeNonces(ctx, event)
	if h.afterSigs != nil && signed && err == nil {
		h.afterSigs()
	}
	return signed, err
}

// defaultHandlerArgs mirrors what JoinBatch builds internally.
func defaultHandlerArgs(args batchsession.JoinBatchArgs) batchsessionhandler.Args {
	return batchsessionhandler.Args{
		Client:         args.Client,
		ServerParams:   args.ServerParams,
		SignTx:         args.SignTx,
		IntentId:       args.IntentId,
		Vtxos:          args.Vtxos,
		BoardingUtxos:  args.BoardingUtxos,
		Receivers:      args.Outputs,
		SignerSessions: args.TreeSigners,
	}
}

// cosignedTxids lists the txs the given cosigner must sign. The tree was rebuilt from
// topic-filtered events, so another participant's leaf is not in it.
func cosignedTxids(vtxoTree *tree.TxTree, pubkey string) ([]string, error) {
	if vtxoTree == nil {
		return nil, fmt.Errorf("no vtxo tree captured")
	}

	txids := make([]string, 0)
	err := vtxoTree.Apply(func(g *tree.TxTree) (bool, error) {
		keys, err := txutils.ParseCosignerKeysFromArkPsbt(g.Root, 0)
		if err != nil {
			return false, err
		}
		for _, key := range keys {
			if hex.EncodeToString(key.SerializeCompressed()) == pubkey {
				txids = append(txids, g.Root.UnsignedTx.TxID())
				break
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if len(txids) == 0 {
		return nil, fmt.Errorf("no txs cosigned by %s in the visible tree", pubkey)
	}
	return txids, nil
}

// forgedNonces builds a well-formed nonce set from a secret only the forger knows.
func forgedNonces(txids []string, pubkey *btcec.PublicKey) (tree.TreeNonces, error) {
	nonces := make(tree.TreeNonces, len(txids))
	for _, txid := range txids {
		nonce, err := musig2.GenNonces(musig2.WithPublicKey(pubkey))
		if err != nil {
			return nil, err
		}
		nonces[txid] = &tree.Musig2Nonce{PubNonce: nonce.PubNonce}
	}
	return nonces, nil
}

// forgedSigs builds a well-formed but meaningless partial-signature set.
func forgedSigs(txids []string) (tree.TreePartialSigs, error) {
	sigs := make(tree.TreePartialSigs, len(txids))
	for _, txid := range txids {
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		var s btcec.ModNScalar
		s.SetBytes(&buf)
		sigs[txid] = &musig2.PartialSignature{S: &s}
	}
	return sigs, nil
}

// waitFor bounds a gate so it can never strand a handler for the whole batch timeout.
func waitFor(ctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(60 * time.Second):
		return fmt.Errorf("timed out waiting for the other participant to submit")
	}
}

// convictionsByRound returns the raw admin-API conviction list for a round, so a test
// can show who the operator punished and why.
func convictionsByRound(t *testing.T, roundId string) ([]roundConviction, string) {
	t.Helper()

	req, err := http.NewRequest(
		"GET", fmt.Sprintf("%s/v1/admin/convictionsByRound/%s", adminUrl, roundId), nil,
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Sprintf("query failed: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Sprintf("read failed: %s", err)
	}

	var parsed struct {
		Convictions []roundConviction `json:"convictions"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Sprintf("parse failed: %s (%s)", err, body)
	}
	return parsed.Convictions, string(body)
}

type roundConviction struct {
	Script    string `json:"script"`
	CrimeType string `json:"crimeType"`
	Reason    string `json:"reason"`
}

const crimeBadMusig2Sig = "CRIME_TYPE_MUSIG2_INVALID_SIGNATURE"

// bannedFor reports whether a script was banned for a specific crime.
func bannedFor(convictions []roundConviction, script, crimeType string) bool {
	for _, c := range convictions {
		if c.Script == script && c.CrimeType == crimeType {
			return true
		}
	}
	return false
}
