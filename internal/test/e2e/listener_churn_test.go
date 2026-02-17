package e2e_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	arksdk "github.com/arkade-os/go-sdk"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTxListenerChurn(t *testing.T) {
	const (
		testDuration           = 30 * time.Second
		churnWorkers           = 8
		txProducerDelay        = 200 * time.Millisecond
		minimumTxEvents        = 1
		sendAmount      uint64 = 1000
	)

	ctx := t.Context()

	// Step 1: capture container identity and baseline health before churn starts.
	t.Log("Step 1: capture node baseline health")
	containerName := resolveArkdContainer(t)
	restartsBefore := getContainerRestartCount(t, containerName)
	logsSince := time.Now().Add(-1 * time.Second)

	// Step 2: bootstrap sender/receiver clients and fund sender for repeated tx production.
	t.Log("Step 2: initialize clients and fund sender")
	sender := setupArkSDK(t)
	receiver := setupArkSDK(t)
	_, transport := setupArkSDKWithTransport(t)
	t.Cleanup(func() { transport.Close() })

	faucetOffchain(t, sender, 0.01)

	stressCtx, cancel := context.WithTimeout(ctx, testDuration)
	defer cancel()
	t.Logf(
		"churn config: duration=%s churnWorkers=%d txProducerDelay=%s",
		testDuration,
		churnWorkers,
		txProducerDelay,
	)

	// Step 3: keep one long-lived sentinel subscription active during the full stress window.
	t.Log("Step 3: start sentinel subscription")
	stream, closeSentinelStream, err := transport.GetTransactionsStream(stressCtx)
	require.NoError(t, err)

	var sentinelTxEvents atomic.Int64
	var producedTxEvents atomic.Int64
	var retryableSubscribeErrors atomic.Int64
	sentinelDone := make(chan struct{})
	errCh := make(chan error, churnWorkers+8)

	reportErr := func(err error) {
		t.Logf("worker error: %v", err)
		select {
		case errCh <- err:
		default:
		}
	}

	go func() {
		defer close(sentinelDone)
		// Step 4: monitor sentinel stream continuity and count observed tx events.
		for {
			select {
			case <-stressCtx.Done():
				return
			case ev, ok := <-stream:
				if !ok {
					return
				}
				if ev.Err != nil {
					reportErr(ev.Err)
					return
				}
				if ev.ArkTx != nil {
					sentinelTxEvents.Add(1)
				}
				if ev.CommitmentTx != nil {
					sentinelTxEvents.Add(1)
				}
			}
		}
	}()

	var wg sync.WaitGroup

	// Step 5: churn subscriptions by rapidly opening/closing tx streams in parallel.
	t.Log("Step 5: start churn workers")
	wg.Add(churnWorkers)
	for i := range churnWorkers {
		go func(workerID int) {
			defer wg.Done()

			streamClient, err := grpcclient.NewClient(serverUrl)
			if err != nil {
				if stressCtx.Err() != nil {
					return
				}
				if isRetryableChurnError(err) {
					retryableSubscribeErrors.Add(1)
					time.Sleep(churnWorkerBackoff(workerID))
				} else {
					reportErr(fmt.Errorf("churn worker %d create client: %w", workerID, err))
					return
				}
			}
			defer func() {
				if streamClient != nil {
					streamClient.Close()
				}
			}()

			for {
				select {
				case <-stressCtx.Done():
					return
				default:
				}

				if streamClient == nil {
					streamClient, err = grpcclient.NewClient(serverUrl)
					if err != nil {
						if stressCtx.Err() != nil {
							return
						}
						if isRetryableChurnError(err) {
							retryableSubscribeErrors.Add(1)
							time.Sleep(churnWorkerBackoff(workerID))
							continue
						}
						reportErr(fmt.Errorf("churn worker %d create client: %w", workerID, err))
						return
					}
				}

				churnStream, closeChurnStream, err := streamClient.GetTransactionsStream(stressCtx)
				if err != nil {
					if stressCtx.Err() != nil {
						return
					}
					if isRetryableChurnError(err) {
						retryableSubscribeErrors.Add(1)
						streamClient.Close()
						streamClient = nil
						time.Sleep(churnWorkerBackoff(workerID))
						continue
					}
					reportErr(fmt.Errorf("churn worker %d subscribe: %w", workerID, err))
					return
				}

				select {
				case <-stressCtx.Done():
				case <-time.After(10 * time.Millisecond):
				case <-churnStream:
				}

				closeChurnStream()
				time.Sleep(churnWorkerBackoff(workerID))
			}
		}(i)
	}

	// Step 6: continuously generate offchain tx events while churn is in-flight.
	t.Log("Step 6: start tx producer loop")
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(txProducerDelay)
		defer ticker.Stop()

		for {
			select {
			case <-stressCtx.Done():
				return
			case <-ticker.C:
				_, receiverOffchainAddr, _, err := receiver.Receive(stressCtx)
				if err != nil {
					reportErr(fmt.Errorf("tx producer receive address: %w", err))
					return
				}

				txid, err := sender.SendOffChain(stressCtx, []types.Receiver{{
					To:     receiverOffchainAddr,
					Amount: sendAmount,
				}})
				if err != nil {
					if stressCtx.Err() != nil {
						return
					}
					reportErr(fmt.Errorf("tx producer send offchain: %w", err))
					return
				}
				if txid == "" {
					reportErr(fmt.Errorf("tx producer got empty txid"))
					return
				}
				producedTxEvents.Add(1)
			}
		}
	}()

	// Step 7: stop all workers, then gather post-run process/log health signals.
	t.Log("Step 7: wait for workers and collect node health evidence")
	<-stressCtx.Done()
	wg.Wait()
	closeSentinelStream()
	<-sentinelDone

	restartsAfter := getContainerRestartCount(t, containerName)
	logs := getContainerLogsSince(t, containerName, logsSince)
	panicDetected, panicSignature := hasPanicSignature(logs)
	t.Logf(
		"final metrics: produced=%d sentinel=%d retryable_subscribe_errors=%d restarts_before=%d restarts_after=%d panic_detected=%t panic_signature=%q",
		producedTxEvents.Load(),
		sentinelTxEvents.Load(),
		retryableSubscribeErrors.Load(),
		restartsBefore,
		restartsAfter,
		panicDetected,
		panicSignature,
	)

	var firstRunErr error
	select {
	case runErr := <-errCh:
		firstRunErr = runErr
	default:
	}

	// Step 8: assert node did not crash/restart and panic signatures are absent.
	require.Equal(
		t,
		restartsBefore,
		restartsAfter,
		"arkd restarted during churn; subscriptions were disrupted",
	)

	require.False(
		t,
		panicDetected,
		"panic detected in arkd logs during churn: %s",
		panicSignature,
	)

	// Step 9: assert that tx production and subscription activity both happened.
	require.GreaterOrEqual(
		t,
		producedTxEvents.Load(),
		int64(minimumTxEvents),
		"producer did not submit tx events during churn",
	)

	require.GreaterOrEqual(
		t,
		sentinelTxEvents.Load(),
		int64(minimumTxEvents),
		"sentinel subscription did not observe tx events during churn",
	)

	require.NoError(t, firstRunErr)

	for {
		select {
		case runErr := <-errCh:
			require.NoError(t, runErr)
		default:
			return
		}
	}
}

func TestEventListenerChurn(t *testing.T) {
	const (
		testDuration      = 40 * time.Second
		churnWorkers      = 16
		participantsCount = 4
		producerLoopDelay = 250 * time.Millisecond
		roundTimeout      = 20 * time.Second
		minimumRounds     = 1
	)

	ctx := t.Context()

	t.Log("Step 1: capture node baseline health")
	containerName := resolveArkdContainer(t)
	restartsBefore := getContainerRestartCount(t, containerName)
	logsSince := time.Now().Add(-1 * time.Second)

	t.Log("Step 2: initialize round participants and fund wallets")
	sentinelClient, eventTransport := setupArkSDKWithTransport(t)
	t.Cleanup(func() { eventTransport.Close() })

	participants := make([]arksdk.ArkClient, 0, participantsCount)
	offchainAddrs := make([]string, 0, participantsCount)

	participants = append(participants, sentinelClient)
	for i := 1; i < participantsCount; i++ {
		participants = append(participants, setupArkSDK(t))
	}

	for i, participant := range participants {
		_, offchainAddr, _, err := participant.Receive(ctx)
		require.NoError(t, err)
		offchainAddrs = append(offchainAddrs, offchainAddr)
		faucetOffchain(t, participant, 0.001)
		t.Logf("participant %d ready", i)
	}

	stressCtx, cancel := context.WithTimeout(ctx, testDuration)
	defer cancel()
	t.Logf(
		"churn config: duration=%s churnWorkers=%d participants=%d producerLoopDelay=%s roundTimeout=%s",
		testDuration,
		churnWorkers,
		participantsCount,
		producerLoopDelay,
		roundTimeout,
	)

	t.Log("Step 3: start sentinel event stream")
	sentinelStream, closeSentinelStream, err := eventTransport.GetEventStream(stressCtx, nil)
	require.NoError(t, err)

	var sentinelEvents atomic.Int64
	var sentinelErrors atomic.Int64
	var producedRounds atomic.Int64
	var retryableSubscribeErrors atomic.Int64
	sentinelDone := make(chan struct{})

	go func() {
		defer close(sentinelDone)
		for {
			select {
			case <-stressCtx.Done():
				return
			case ev, ok := <-sentinelStream:
				if !ok {
					return
				}
				if ev.Err != nil {
					sentinelErrors.Add(1)
					return
				}
				if ev.Event == nil {
					continue
				}
				sentinelEvents.Add(1)
			}
		}
	}()

	var wg sync.WaitGroup

	t.Log("Step 4: start event stream churn workers")
	wg.Add(churnWorkers)
	for i := range churnWorkers {
		go func(workerID int) {
			defer wg.Done()

			streamClient, err := grpcclient.NewClient(serverUrl)
			if err != nil {
				if stressCtx.Err() != nil {
					return
				}
				if isRetryableChurnError(err) {
					retryableSubscribeErrors.Add(1)
					time.Sleep(churnWorkerBackoff(workerID))
				} else {
					return
				}
			}
			defer func() {
				if streamClient != nil {
					streamClient.Close()
				}
			}()

			for {
				select {
				case <-stressCtx.Done():
					return
				default:
				}

				if streamClient == nil {
					streamClient, err = grpcclient.NewClient(serverUrl)
					if err != nil {
						if stressCtx.Err() != nil {
							return
						}
						if isRetryableChurnError(err) {
							retryableSubscribeErrors.Add(1)
							time.Sleep(churnWorkerBackoff(workerID))
							continue
						}
						return
					}
				}

				churnCtx, cancelChurn := context.WithTimeout(stressCtx, 3*time.Second)
				churnStream, closeChurnStream, err := streamClient.GetEventStream(churnCtx, nil)
				if err != nil {
					cancelChurn()
					if stressCtx.Err() != nil {
						return
					}
					if isRetryableChurnError(err) {
						retryableSubscribeErrors.Add(1)
						streamClient.Close()
						streamClient = nil
						time.Sleep(churnWorkerBackoff(workerID))
						continue
					}
					continue
				}

				select {
				case <-stressCtx.Done():
				case <-time.After(10 * time.Millisecond):
				case <-churnStream:
				}

				closeChurnStream()
				cancelChurn()
				time.Sleep(churnWorkerBackoff(workerID))
			}
		}(i)
	}

	t.Log("Step 5: start round producer loop")
	runRoundProducer := func() {
		defer wg.Done()

		for {
			if stressCtx.Err() != nil {
				return
			}

			roundCtx, cancelRound := context.WithTimeout(stressCtx, roundTimeout)
			notifyErrors := make([]error, len(participants))
			settleErrors := make([]error, len(participants))
			commitmentTxids := make([]string, len(participants))

			roundWG := &sync.WaitGroup{}
			roundWG.Add(len(participants) * 2)
			for i := range participants {
				idx := i
				go func() {
					defer roundWG.Done()
					_, notifyErrors[idx] = participants[idx].NotifyIncomingFunds(
						roundCtx,
						offchainAddrs[idx],
					)
				}()
				go func() {
					defer roundWG.Done()
					commitmentTxids[idx], settleErrors[idx] = participants[idx].Settle(roundCtx)
				}()
			}

			roundDone := make(chan struct{})
			go func() {
				roundWG.Wait()
				close(roundDone)
			}()

			select {
			case <-roundDone:
			case <-time.After(roundTimeout + 2*time.Second):
				cancelRound()
				continue
			}
			cancelRound()

			if stressCtx.Err() != nil {
				return
			}

			for i, notifyErr := range notifyErrors {
				if notifyErr != nil {
					t.Logf("round producer notify participant %d failed: %v", i, notifyErr)
					continue
				}
			}

			var expectedCommitmentTxid string
			roundOK := true
			for i, settleErr := range settleErrors {
				if settleErr != nil {
					t.Logf("round producer settle participant %d failed: %v", i, settleErr)
					roundOK = false
					break
				}
				if commitmentTxids[i] == "" {
					t.Logf("round producer got empty commitment txid for participant %d", i)
					roundOK = false
					break
				}
				if expectedCommitmentTxid == "" {
					expectedCommitmentTxid = commitmentTxids[i]
					continue
				}
				if commitmentTxids[i] != expectedCommitmentTxid {
					t.Logf(
						"round producer got mismatched commitment txids: expected=%s participant=%d txid=%s",
						expectedCommitmentTxid,
						i,
						commitmentTxids[i],
					)
					roundOK = false
					break
				}
			}

			if roundOK {
				producedRounds.Add(1)
			}

			select {
			case <-stressCtx.Done():
				return
			case <-time.After(producerLoopDelay):
			}
		}
	}
	wg.Add(1)
	go runRoundProducer()

	t.Log("Step 6: wait for workers to stop and collect node health evidence")
	<-stressCtx.Done()
	wg.Wait()
	closeSentinelStream()
	<-sentinelDone

	restartsAfter := getContainerRestartCount(t, containerName)
	logs := getContainerLogsSince(t, containerName, logsSince)
	panicDetected, panicSignature := hasPanicSignature(logs)

	t.Logf(
		"final metrics: rounds=%d events=%d sentinel_errors=%d retryable_subscribe_errors=%d container=%q restarts_before=%d restarts_after=%d panic_detected=%t panic_signature=%q",
		producedRounds.Load(),
		sentinelEvents.Load(),
		sentinelErrors.Load(),
		retryableSubscribeErrors.Load(),
		containerName,
		restartsBefore,
		restartsAfter,
		panicDetected,
		panicSignature,
	)

	require.Equal(t, restartsBefore, restartsAfter, "arkd restarted during churn")

	require.False(
		t,
		panicDetected,
		"panic detected in arkd logs during churn: %s",
		panicSignature,
	)

	require.GreaterOrEqual(
		t,
		producedRounds.Load(),
		int64(minimumRounds),
		"round producer did not complete rounds during churn",
	)

	require.Greater(
		t,
		sentinelEvents.Load(),
		int64(0),
		"sentinel event stream did not observe events during churn",
	)

	require.Equal(
		t,
		int64(0),
		sentinelErrors.Load(),
		"sentinel event stream returned errors during churn",
	)
}

func resolveArkdContainer(t *testing.T) string {
	t.Helper()

	candidates := []string{"arkd", "ark"}
	for _, name := range candidates {
		if _, err := runCommand("docker", "inspect", name); err == nil {
			return name
		}
	}

	require.FailNow(t, "failed to resolve ark container name (tried arkd, ark)")
	return ""
}

func getContainerRestartCount(t *testing.T, container string) int {
	t.Helper()

	out, err := runCommand("docker", "inspect", "-f", "{{.RestartCount}}", container)
	require.NoError(t, err)

	count, err := strconv.Atoi(strings.TrimSpace(out))
	require.NoError(t, err)
	return count
}

func getContainerLogsSince(t *testing.T, container string, since time.Time) string {
	t.Helper()

	out, err := runCommand(
		"bash",
		"-lc",
		fmt.Sprintf("docker logs --since '%s' %s 2>&1", since.Format(time.RFC3339), container),
	)
	require.NoError(t, err)
	return out
}

func hasPanicSignature(logs string) (bool, string) {
	signatures := []string{
		"panic:",
		"fatal error:",
		"concurrent map iteration and map write",
		"send on closed channel",
	}

	for _, sig := range signatures {
		if strings.Contains(logs, sig) {
			return true, sig
		}
	}

	return false, ""
}

func churnWorkerBackoff(workerID int) time.Duration {
	return time.Duration(5+workerID%11) * time.Millisecond
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
	signatures := []string{
		"can't assign requested address",
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
