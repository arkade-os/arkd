package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The projection of a finished batch is written by a handler the event store
// dispatches in its own goroutine, so startRound has to wait for it before it
// releases the batch's intent claims. These pin the two halves of that: the
// wait itself, and the handler that ends it.
func TestBatchSessionManager(t *testing.T) {
	t.Run("waitForProjections", func(t *testing.T) {
		t.Run("returns at once when the batch is already projected", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.markProjected(projectedRoundId)

			start := time.Now()
			require.Equal(
				t, []string{projectedRoundId}, m.waitForProjections(t.Context(), 5*time.Second),
			)
			require.Less(t, time.Since(start), time.Second)
		})

		t.Run("waits until the batch is projected", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			waited := make(chan []string, 1)
			go func() { waited <- m.waitForProjections(t.Context(), 5*time.Second) }()
			requireBlocked(t, waited)

			m.markProjected(projectedRoundId)
			select {
			case released := <-waited:
				require.Equal(t, []string{projectedRoundId}, released)
			case <-time.After(5 * time.Second):
				require.FailNow(t, "the wait did not end when the round was projected")
			}
		})

		// Every round event projects, not just the last one, so a wait must
		// only end once the batches it waits on are projected.
		t.Run("another batch being projected does not end the wait", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			waited := make(chan []string, 1)
			go func() { waited <- m.waitForProjections(t.Context(), 5*time.Second) }()

			m.track(endedRoundWithId(t, "another-round"))
			m.markProjected("another-round")
			requireBlocked(t, waited)

			m.markProjected(projectedRoundId)
			require.ElementsMatch(t, []string{"another-round", projectedRoundId}, <-waited)
		})

		t.Run("gives up on the timeout", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			start := time.Now()
			require.Empty(
				t, m.waitForProjections(t.Context(), 100*time.Millisecond),
				"a projection that never arrives must not stall the round loop",
			)
			require.Less(t, time.Since(start), 5*time.Second)
		})

		t.Run("gives up when the context is cancelled", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			ctx, cancel := context.WithCancel(t.Context())

			waited := make(chan []string, 1)
			go func() { waited <- m.waitForProjections(ctx, time.Minute) }()
			requireBlocked(t, waited)

			cancel()
			select {
			case released := <-waited:
				require.Empty(t, released, "shutdown must not be held up by the wait")
			case <-time.After(5 * time.Second):
				require.FailNow(t, "the wait did not end when the context was cancelled")
			}
		})

		// The reason for a map: when a projection is late several batches can be
		// in flight, and the wait covers all of them.
		t.Run("waits for every batch in flight", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.track(endedRoundWithId(t, "other-batch"))

			waited := make(chan []string, 1)
			go func() { waited <- m.waitForProjections(t.Context(), 5*time.Second) }()
			requireBlocked(t, waited)

			m.markProjected("other-batch")
			requireBlocked(t, waited, "one batch's projection must not end the wait for the other")

			m.markProjected(projectedRoundId)
			require.ElementsMatch(t, []string{"other-batch", projectedRoundId}, <-waited)
		})

		// The map holds the batches still missing their projection, so a
		// projected batch leaves nothing behind, a batch whose wait gave up is
		// waited on again, and a sweep of a batch long gone adds nothing.
		t.Run("tracks a batch until it is projected", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.markProjected(projectedRoundId)
			require.Equal(
				t, []string{projectedRoundId}, m.waitForProjections(t.Context(), time.Second),
			)
			requireNotTracked(t, m, projectedRoundId)

			m.track(endedRound(t))
			require.Empty(t, m.waitForProjections(t.Context(), 50*time.Millisecond))
			requireTracked(t, m, projectedRoundId, "a wait that gave up keeps the batch")

			m.markProjected(projectedRoundId)
			require.Equal(
				t, []string{projectedRoundId}, m.waitForProjections(t.Context(), time.Second),
			)
			requireNotTracked(t, m, projectedRoundId)

			m.markProjected(projectedRoundId)
			requireNotTracked(t, m, projectedRoundId, "a batch nothing waits on is not tracked")
		})

		// A batch stops being tracked as soon as a wait reports it, so of several
		// waits ending on the same projection exactly one carries the batch and
		// releases its claims. The rest are released too, with nothing to do.
		t.Run("releases every waiter, and only one carries the batch", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			var wg sync.WaitGroup
			results := make([][]string, concurrentWaiters)
			done := make(chan struct{})
			for i := range results {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					results[i] = m.waitForProjections(t.Context(), 5*time.Second)
				}(i)
			}

			m.markProjected(projectedRoundId)
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.FailNow(t, "a waiter was never released")
			}

			carried := 0
			for _, released := range results {
				if len(released) == 0 {
					continue
				}
				require.Equal(t, []string{projectedRoundId}, released)
				carried++
			}
			require.Equal(t, 1, carried, "the batch must be released exactly once")
		})

		// A round that failed writes no vtxo rows and never marks, so expecting
		// it would leave a wait nothing could end.
		t.Run("tracks nothing for a batch that did not end", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(startedRoundOf(t))

			start := time.Now()
			require.Empty(t, m.waitForProjections(t.Context(), 5*time.Second))
			require.Less(t, time.Since(start), time.Second)
		})

		// Every event of a round projects, so the same round is marked again
		// when it is later swept. That must not churn the wakeup.
		t.Run("marking the same batch again changes nothing", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.markProjected(projectedRoundId)

			m.lock.Lock()
			before := m.updated
			m.lock.Unlock()

			m.markProjected(projectedRoundId)

			m.lock.Lock()
			after, projected := m.updated, m.inflightBatches[projectedRoundId]
			m.lock.Unlock()

			require.True(t, projected, "the batch stays projected")
			require.True(t, before == after, "a repeat mark must not wake the waiters again")
		})

		// A round finished by a previous process is still in the cache after a
		// restart. Its projection was written before this process started, so
		// waiting for it here would stall every restart.
		t.Run("does not wait when no batch is tracked", func(t *testing.T) {
			m := newBatchSessionManager()

			start := time.Now()
			require.Empty(t, m.waitForProjections(t.Context(), 5*time.Second))
			require.Less(t, time.Since(start), time.Second)
		})
	})

	t.Run("registrations and the claim release exclude each other", func(t *testing.T) {
		t.Run("registrations run alongside each other", func(t *testing.T) {
			m := newBatchSessionManager()

			m.beginRegistration()
			second := make(chan struct{})
			go func() {
				m.beginRegistration()
				m.endRegistration()
				close(second)
			}()

			select {
			case <-second:
			case <-time.After(5 * time.Second):
				require.FailNow(t, "one registration must not block another")
			}
			m.endRegistration()
		})

		t.Run("the release waits for a registration in flight", func(t *testing.T) {
			m := newBatchSessionManager()
			m.beginRegistration()

			held := make(chan struct{})
			go func() {
				m.holdRegistrations()
				close(held)
			}()

			select {
			case <-held:
				require.FailNow(t, "the claims were released with a registration in flight")
			case <-time.After(100 * time.Millisecond):
			}

			m.endRegistration()
			select {
			case <-held:
				m.resumeRegistrations()
			case <-time.After(5 * time.Second):
				require.FailNow(t, "the release never happened after the registration finished")
			}
		})

		t.Run("a registration waits for the release to finish", func(t *testing.T) {
			m := newBatchSessionManager()
			m.holdRegistrations()

			registered := make(chan struct{})
			go func() {
				m.beginRegistration()
				m.endRegistration()
				close(registered)
			}()

			select {
			case <-registered:
				require.FailNow(t, "a registration ran while the claims were being released")
			case <-time.After(100 * time.Millisecond):
			}

			m.resumeRegistrations()
			select {
			case <-registered:
			case <-time.After(5 * time.Second):
				require.FailNow(t, "the registration never ran after the release finished")
			}
		})
	})

	// The db service dispatches the batch update handler only after the
	// projection writes have returned, which is why the handler is where the
	// round is marked.
	t.Run("the batch update handler marks a finished batch", func(t *testing.T) {
		svc, rm := newProjectionTestService(t)
		svc.batchSessions.track(endedRound(t))

		rm.batchHandler(sweptRound(t))

		require.Equal(
			t, []string{projectedRoundId},
			svc.batchSessions.waitForProjections(t.Context(), time.Second),
			"a finished round must be marked projected",
		)
	})

	// Both reads happen once for the whole intent now, and the loop decides from
	// what they returned. These pin that it reads the right answer per input.
	t.Run("the batched reads still decide input by input", func(t *testing.T) {
		// The proof commits to the encoded message, so the message has to be
		// complete before the proof is built.
		newProof := func(
			t *testing.T, message intent.RegisterMessage,
		) (*intent.Proof, domain.Outpoint) {
			t.Helper()

			encoded, err := message.Encode()
			require.NoError(t, err)
			proof := testNoteIntentProof(t, encoded, &wire.TxOut{
				Value: int64(testDust) * 2, PkScript: []byte{txscript.OP_TRUE},
			})

			outpoints := proof.GetOutpoints()
			require.Len(t, outpoints, 1)
			return proof, domain.Outpoint{
				Txid: outpoints[0].Hash.String(), VOut: outpoints[0].Index,
			}
		}

		registerMessage := func() intent.RegisterMessage {
			return intent.RegisterMessage{
				BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
			}
		}

		t.Run("an input the projection has as spent is refused", func(t *testing.T) {
			message := registerMessage()
			proof, outpoint := newProof(t, message)

			vtxos := &mockedVtxoRepo{}
			vtxos.On("GetVtxos", mock.Anything, mock.Anything).
				Return([]domain.Vtxo{{Outpoint: outpoint, Spent: true}}, nil)
			repos := &mockedRepoManager{}
			repos.On("Vtxos").Return(vtxos)

			svc := newRegisterIntentTestService(t, repos)
			_, appErr := svc.RegisterIntent(t.Context(), *proof, message)
			require.Error(t, appErr)
			require.Equal(t, errors.VTXO_ALREADY_SPENT.Code, appErr.Code())
			require.Contains(t, appErr.Error(), "input "+outpoint.String()+" already spent")
		})

		t.Run("an input an offchain tx is spending is refused", func(t *testing.T) {
			message := registerMessage()
			proof, outpoint := newProof(t, message)

			vtxos := &mockedVtxoRepo{}
			vtxos.On("GetVtxos", mock.Anything, mock.Anything).
				Return([]domain.Vtxo{{Outpoint: outpoint}}, nil)
			repos := &mockedRepoManager{}
			repos.On("Vtxos").Return(vtxos)

			svc := newRegisterIntentTestService(t, repos)
			svc.cache = testLiveStore{
				settings:    registerIntentTestSettings(t),
				offchainTxs: spendingOffchainTxStore{spending: outpoint},
			}

			_, appErr := svc.RegisterIntent(t.Context(), *proof, message)
			require.Error(t, appErr)
			require.Equal(t, errors.VTXO_ALREADY_SPENT.Code, appErr.Code())
			require.Contains(t, appErr.Error(), "vtxo(s) already spent")
		})

		// Every input is read in one call, and the loop still names the input
		// that is wrong rather than the first one.
		t.Run("a spent input after a valid one is refused by its own outpoint", func(t *testing.T) {
			message := registerMessage()
			encoded, err := message.Encode()
			require.NoError(t, err)
			proof := testNotesIntentProof(t, encoded, &wire.TxOut{
				Value: int64(testDust) * 2, PkScript: []byte{txscript.OP_TRUE},
			}, 2)
			inputs := proof.GetOutpoints()
			require.Len(t, inputs, 2)
			valid := domain.Outpoint{Txid: inputs[0].Hash.String(), VOut: inputs[0].Index}
			spent := domain.Outpoint{Txid: inputs[1].Hash.String(), VOut: inputs[1].Index}
			utxo := proof.Inputs[1].WitnessUtxo

			vtxos := &mockedVtxoRepo{}
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{valid, spent}).
				Return([]domain.Vtxo{
					{
						Outpoint: valid,
						Amount:   uint64(utxo.Value),
						PubKey:   hex.EncodeToString(utxo.PkScript[2:]),
					},
					{Outpoint: spent, Spent: true},
				}, nil).Once()
			repos := &mockedRepoManager{}
			repos.On("Vtxos").Return(vtxos)

			svc := newRegisterIntentTestService(t, repos)
			_, appErr := svc.RegisterIntent(t.Context(), *proof, message)
			require.Error(t, appErr)
			require.Equal(t, errors.VTXO_ALREADY_SPENT.Code, appErr.Code())
			require.Equal(t, spent.String(), appErr.Metadata()["vtxo_outpoint"])
			vtxos.AssertExpectations(t)
		})

		// An input the projection does not have is a boarding input, which an
		// intent declaring onchain outputs may not mix with. That refusal is
		// only reachable through the not-found branch, so it is what pins it.
		t.Run("an input the projection does not have is taken for boarding", func(t *testing.T) {
			message := registerMessage()
			message.OnchainOutputIndexes = []int{0}
			proof, _ := newProof(t, message)

			vtxos := &mockedVtxoRepo{}
			vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(nil, nil)
			repos := &mockedRepoManager{}
			repos.On("Vtxos").Return(vtxos)

			svc := newRegisterIntentTestService(t, repos)
			_, appErr := svc.RegisterIntent(t.Context(), *proof, message)
			require.NotNil(t, appErr)
			require.Equal(t, errors.INVALID_INTENT_PROOF.Code, appErr.Code())
			require.Contains(t, appErr.Error(), "cannot include onchain inputs and outputs")
		})

		// A known vtxo's taptree comes from the client and can be missing, a note
		// script or another vtxo's script, so the ban check has to read the script
		// stored for the vtxo.
		t.Run("a known input is checked for bans by its stored script", func(t *testing.T) {
			t.Run("without a taptree", func(t *testing.T) {
				message := registerMessage()
				proof, outpoint := newProof(t, message)
				pkScript := proof.Inputs[1].WitnessUtxo.PkScript

				appErr := registerWithBans(t, message, proof, []domain.Vtxo{{
					Outpoint: outpoint, PubKey: hex.EncodeToString(pkScript[2:]),
				}}, hex.EncodeToString(pkScript))
				require.Error(t, appErr)
				require.Equal(t, errors.VTXO_BANNED.Code, appErr.Code())
				require.Equal(t, outpoint.String(), appErr.Metadata()["vtxo_outpoint"])
			})

			t.Run("a note sending its note script as taptree", func(t *testing.T) {
				message := registerMessage()
				proof, outpoint := newProof(t, message)
				pkScript := proof.Inputs[1].WitnessUtxo.PkScript
				noteScript := proof.Inputs[1].TaprootLeafScript[0].Script
				require.NoError(t, txutils.SetArkPsbtField(
					&proof.Packet, 1, txutils.VtxoTaprootTreeField,
					txutils.TapTree{hex.EncodeToString(noteScript)},
				))

				appErr := registerWithBans(t, message, proof, []domain.Vtxo{{
					Outpoint: outpoint, PubKey: hex.EncodeToString(pkScript[2:]),
				}}, hex.EncodeToString(pkScript))
				require.Error(t, appErr)
				require.Equal(t, errors.VTXO_BANNED.Code, appErr.Code())
			})

			t.Run("a swept vtxo sending another vtxo's script as taptree", func(t *testing.T) {
				message := registerMessage()
				proof, outpoint := newProof(t, message)
				pkScript := proof.Inputs[1].WitnessUtxo.PkScript
				otherScript, err := script.NewDefaultVtxoScript(
					testPubkey(t), testPubkey(t),
					arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
				).Encode()
				require.NoError(t, err)
				require.NoError(t, txutils.SetArkPsbtField(
					&proof.Packet, 1, txutils.VtxoTaprootTreeField, txutils.TapTree(otherScript),
				))

				appErr := registerWithBans(t, message, proof, []domain.Vtxo{{
					Outpoint:           outpoint,
					PubKey:             hex.EncodeToString(pkScript[2:]),
					Swept:              true,
					CommitmentTxids:    []string{"commitmenttxid"},
					RootCommitmentTxid: "commitmenttxid",
				}}, hex.EncodeToString(pkScript))
				require.Error(t, appErr)
				require.Equal(t, errors.VTXO_BANNED.Code, appErr.Code())
			})
		})

		// A boarding input has nothing stored, so its ban script is the one its
		// taptree describes.
		t.Run("a boarding input is checked for bans by its taptree", func(t *testing.T) {
			message := registerMessage()
			proof, outpoint := newProof(t, message)
			boardingScript := script.NewDefaultVtxoScript(
				testPubkey(t), testPubkey(t),
				arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
			)
			tapscripts, err := boardingScript.Encode()
			require.NoError(t, err)
			require.NoError(t, txutils.SetArkPsbtField(
				&proof.Packet, 1, txutils.VtxoTaprootTreeField, txutils.TapTree(tapscripts),
			))
			tapKey, _, err := boardingScript.TapTree()
			require.NoError(t, err)
			pkScript, err := script.P2TRScript(tapKey)
			require.NoError(t, err)

			appErr := registerWithBans(t, message, proof, nil, hex.EncodeToString(pkScript))
			require.Error(t, appErr)
			require.Equal(t, errors.VTXO_BANNED.Code, appErr.Code())
			require.Equal(t, outpoint.String(), appErr.Metadata()["vtxo_outpoint"])
		})

		// A boarding input whose taptree gives no script is a malformed request, so
		// it is refused as an invalid script whether banning is on or off, never as
		// a ban or an internal error.
		t.Run("a boarding input whose taptree gives no script is refused as invalid", func(t *testing.T) {
			for _, banThreshold := range []uint64{0, 1} {
				t.Run(fmt.Sprintf("ban threshold %d", banThreshold), func(t *testing.T) {
					reg := newPushingRegistration(t)
					reg.vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(nil, nil)
					reg.repos.On("Convictions").Return(convictionRepoStub{})
					settings := registerIntentTestSettings(t)
					settings.settings.BanThreshold = banThreshold
					reg.svc.cache = testLiveStore{
						settings:    settings,
						offchainTxs: testOffchainTxStore{},
					}

					_, appErr := reg.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
					require.Error(t, appErr)
					require.Equal(t, errors.INVALID_VTXO_SCRIPT.Code, appErr.Code())
					require.Contains(t, appErr.Error(), reg.vtxo.Outpoint.String())
				})
			}
		})
	})

	// The registration side of the same call-site guarantee: while a batch is
	// releasing its claims, a registration does not get to read them.
	t.Run("a registration waits while the claims are being released", func(t *testing.T) {
		reads := make(chan string, 2)
		repos := &mockedRepoManager{}
		vtxos := &mockedVtxoRepo{}
		vtxos.On("GetVtxos", mock.Anything, mock.Anything).
			Run(func(mock.Arguments) {
				select {
				case reads <- "GetVtxos":
				default:
				}
			}).
			Return(nil, nil)
		repos.On("Vtxos").Return(vtxos)
		svc := newRegisterIntentTestService(t, repos)
		svc.cache = testLiveStore{
			settings:    registerIntentTestSettings(t),
			offchainTxs: readReportingOffchainTxStore{reads: reads},
		}
		svc.batchSessions.holdRegistrations()

		message := intent.RegisterMessage{
			BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		}
		encodedMessage, err := message.Encode()
		require.NoError(t, err)
		proof := testNoteIntentProof(t, encodedMessage, &wire.TxOut{
			Value: int64(testDust) * 2, PkScript: []byte{txscript.OP_TRUE},
		})

		registered := make(chan struct{})
		go func() {
			defer close(registered)
			// The proof is rejected on its own merits; what this pins is that
			// the call does not get that far while the claims are in flux.
			_, _ = svc.RegisterIntent(t.Context(), *proof, message)
		}()

		select {
		case read := <-reads:
			require.FailNow(t, "a registration read the claims while they were being released", read)
		case <-registered:
			require.FailNow(t, "a registration read the claims while they were being released")
		case <-time.After(200 * time.Millisecond):
		}

		svc.batchSessions.resumeRegistrations()
		select {
		case <-registered:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the registration never ran after the release finished")
		}
		require.Len(t, reads, 2, "the registration read its inputs once it ran")
		require.Equal(t, "IncludesAny", <-reads)
		require.Equal(t, "GetVtxos", <-reads)
	})

	// A registration that fails still gives the lock back, or the next release
	// would wait on it forever.
	t.Run("a failed registration releases the lock", func(t *testing.T) {
		repos := &mockedRepoManager{}
		vtxos := &mockedVtxoRepo{}
		vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(nil, nil)
		repos.On("Vtxos").Return(vtxos)
		svc := newRegisterIntentTestService(t, repos)

		message := intent.RegisterMessage{
			BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		}
		encodedMessage, err := message.Encode()
		require.NoError(t, err)
		proof := testNoteIntentProof(t, encodedMessage, &wire.TxOut{
			Value: int64(testDust) * 2, PkScript: []byte{txscript.OP_TRUE},
		})

		_, appErr := svc.RegisterIntent(t.Context(), *proof, message)
		require.Error(t, appErr)
		require.Equal(t, errors.INVALID_PKSCRIPT.Code, appErr.Code())

		held := make(chan struct{})
		go func() {
			svc.batchSessions.holdRegistrations()
			close(held)
		}()
		select {
		case <-held:
			svc.batchSessions.resumeRegistrations()
		case <-time.After(5 * time.Second):
			require.FailNow(t, "a failed registration kept the lock")
		}
	})

	// The other half of the same guarantee, at the call site: a registration
	// holds the release back from its first read until its push is done.
	t.Run("the next batch releases no claim until a registration has pushed", func(t *testing.T) {
		reg := newPushingRegistration(t)
		reg.repos.utxos = newFakeUtxoRepo()
		reg.vtxos.On("GetVtxos", mock.Anything, mock.Anything).
			Return([]domain.Vtxo{reg.vtxo}, nil)
		intents := pausingIntentStore{
			pushing:  make(chan struct{}),
			proceed:  make(chan struct{}),
			released: make(chan struct{}),
		}

		svc := reg.svc
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		svc.ctx = ctx
		svc.wg = &sync.WaitGroup{}
		svc.wg.Add(1)
		svc.wallet = &mockedWallet{}
		svc.cache = registrationRoundTestStore{
			startRoundTestStore: startRoundTestStore{
				LiveStore: newCosignTestLiveStore(),
				round:     endedRound(t),
			},
			settings:    registerIntentTestSettings(t),
			offchainTxs: testOffchainTxStore{},
			intents:     intents,
		}
		// Only a batch this process finished and saw projected has its claims
		// released, so this case tracks it to reach the release it is about.
		svc.batchSessions.track(endedRound(t))
		svc.batchSessions.markProjected(projectedRoundId)

		registered := make(chan errors.Error, 1)
		go func() {
			_, appErr := svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
			registered <- appErr
		}()
		select {
		case <-intents.pushing:
		case appErr := <-registered:
			require.FailNow(t, "the registration did not reach the push", "%v", appErr)
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the registration did not reach the push")
		}

		go func() {
			// startRound is driven with only the stores it touches before the
			// release, so recover keeps a later nil from failing the suite on
			// something this case does not assert.
			defer func() { _ = recover() }()
			svc.startRound()
		}()
		select {
		case <-intents.released:
			require.FailNow(t, "the claims were released while a registration was pushing")
		case <-time.After(200 * time.Millisecond):
		}

		close(intents.proceed)
		select {
		case appErr := <-registered:
			require.Nil(t, appErr)
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the registration never finished its push")
		}
		select {
		case <-intents.released:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the claims were never released after the registration pushed")
		}
	})

	// The offchain spend check runs again right before the push, so a spend that
	// lands while the inputs are being validated is still refused.
	t.Run("an input spent during validation is refused before pushing", func(t *testing.T) {
		reg := newPushingRegistration(t)
		intents := &registrationTestIntents{}
		cache := testLiveStore{
			settings:    registerIntentTestSettings(t),
			offchainTxs: testOffchainTxStore{},
			intents:     intents,
		}
		reg.svc.cache = cache

		reg.vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{reg.vtxo.Outpoint}).
			Return([]domain.Vtxo{reg.vtxo}, nil).
			Run(func(mock.Arguments) {
				// The first spend check has passed; a spend now appears in the cache.
				cache.offchainTxs = spendingOffchainTxStore{spending: reg.vtxo.Outpoint}
				reg.svc.cache = cache
			}).Once()

		id, appErr := reg.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
		require.False(t, intents.pushed, "the refused intent must not be pushed")
		require.Empty(t, id)
		require.Error(t, appErr)
		require.Equal(t, errors.VTXO_ALREADY_SPENT.Code, appErr.Code())
		reg.vtxos.AssertExpectations(t)
	})

	// The point of the wait: startRound must not release the finished batch's
	// intent claims until its spent marks are readable. Releasing first leaves
	// a window in which neither guard holds and a settled vtxo can be
	// registered again.
	t.Run("the next batch releases no claim before the projection lands", func(t *testing.T) {
		svc, released := newStartRoundTestService(t, endedRound(t))
		svc.batchSessions.track(endedRound(t))

		go func() {
			// startRound is driven with only the stores it touches before the
			// release, so recover keeps a later nil from failing the suite on
			// something this case does not assert.
			defer func() { _ = recover() }()
			svc.startRound()
		}()

		// Long enough to be meaningful against a wait bounded at 30s.
		select {
		case <-released:
			require.FailNow(t, "the claims were released before the projection landed")
		case <-time.After(200 * time.Millisecond):
		}

		svc.batchSessions.markProjected(projectedRoundId)
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the claims were never released after the projection landed")
		}
	})

	// A projection still missing when the wait gives up keeps the claims, and its
	// batch stays tracked, so a later start waits for it again and releases the
	// claims once it lands.
	t.Run("the next batch keeps the claims while a projection is missing", func(t *testing.T) {
		svc, released := newStartRoundTestService(t, endedRound(t))
		svc.batchSessions.track(endedRound(t))
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		svc.ctx = ctx

		ended := make(chan struct{})
		go func() {
			defer close(ended)
			// startRound is driven with only the stores it touches around the
			// release, so recover keeps a later nil from failing the suite on
			// something this case does not assert.
			defer func() { _ = recover() }()
			svc.startRound()
		}()
		select {
		case <-ended:
			require.FailNow(t, "the next batch did not wait for the projection")
		case <-time.After(200 * time.Millisecond):
		}

		// Cancelling ends the wait the way the timeout does, without sitting it out.
		cancel()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the next batch did not go on after the wait gave up")
		}
		select {
		case <-released:
			require.FailNow(t, "the claims were released with a projection still missing")
		default:
		}
		requireTracked(t, svc.batchSessions, projectedRoundId, "the batch stays tracked")

		svc.batchSessions.markProjected(projectedRoundId)
		nextCtx, stop := context.WithCancel(t.Context())
		t.Cleanup(stop)
		svc.ctx = nextCtx
		svc.wg.Add(1)
		go func() {
			defer func() { _ = recover() }()
			svc.startRound()
		}()
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the claims were never released after the projection landed")
		}
	})

	t.Run("an unfinished batch is not marked", func(t *testing.T) {
		svc, rm := newProjectionTestService(t)
		svc.batchSessions.track(endedRound(t))

		rm.batchHandler(startedRound(t))

		require.Empty(
			t, svc.batchSessions.waitForProjections(t.Context(), 100*time.Millisecond),
			"only the projection of a finished batch releases the next one",
		)
	})
}

// concurrentWaiters is the number of racing waiters used to check that marking
// a round releases all of them, not just one.
const concurrentWaiters = 8

const projectedRoundId = "projected-round-id"

// newProjectionTestService wires the real handler registration against a mock
// that captures the batch handler, so the test drives the same closure the db
// service calls. The channels are buffered because the handler publishes to
// them before it returns.
func newProjectionTestService(t *testing.T) (*service, *mockedRepoManager) {
	t.Helper()

	rm := &mockedRepoManager{}
	svc := &service{
		repoManager:         rm,
		batchSessions:       newBatchSessionManager(),
		eventsCh:            make(chan []domain.Event, 8),
		transactionEventsCh: make(chan TransactionEvent, 8),
		indexerTxEventsCh:   make(chan TransactionEvent, 8),
		wg:                  &sync.WaitGroup{},
		offchainTxMu:        &sync.Mutex{},
	}
	svc.registerEventHandlers()
	require.NotNil(t, rm.batchHandler, "the batch update handler must be registered")

	return svc, rm
}

// sweptRound is a finished batch that was then swept. The sweep is what the
// handler reads as its last event, which is the branch that returns without
// touching the stores a fuller round would need.
func sweptRound(t *testing.T) domain.Round {
	t.Helper()

	round := domain.NewRoundFromEvents(append(endedRoundEvents(), domain.BatchSwept{
		RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeBatchSwept},
		Txid:       "sweeptxid",
		FullySwept: true,
	}))
	require.True(t, round.IsEnded())
	return *round
}

func startedRoundOf(t *testing.T) *domain.Round {
	t.Helper()

	round := startedRound(t)
	return &round
}

func startedRound(t *testing.T) domain.Round {
	t.Helper()

	round := domain.NewRoundFromEvents([]domain.Event{domain.RoundStarted{
		RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeRoundStarted},
		Timestamp:  1767225600,
	}})
	require.False(t, round.IsEnded())
	return *round
}

func endedRoundEvents() []domain.Event {
	return []domain.Event{
		domain.RoundStarted{
			RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeRoundStarted},
			Timestamp:  1767225600,
		},
		domain.RoundFinalizationStarted{
			RoundEvent: domain.RoundEvent{
				Id:   projectedRoundId,
				Type: domain.EventTypeRoundFinalizationStarted,
			},
			CommitmentTxid: "commitmenttxid",
		},
		domain.RoundFinalized{
			RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeRoundFinalized},
			Timestamp:  1767225600,
		},
	}
}

// newStartRoundTestService builds a service holding round in its cache, with
// stubs for the stores startRound touches on its way to releasing the finished
// batch's claims. The returned channel is closed by that release.
func newStartRoundTestService(t *testing.T, round *domain.Round) (*service, <-chan struct{}) {
	t.Helper()

	released := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	wallet := &mockedWallet{}
	svc := &service{
		wallet:        wallet,
		batchSessions: newBatchSessionManager(),
		cache: startRoundTestStore{
			round:    round,
			released: released,
		},
		ctx: ctx,
		wg:  &sync.WaitGroup{},
	}
	svc.wg.Add(1)

	return svc, released
}

// startRoundTestStore serves the finished round and records the release of its
// claims. Every other store startRound touches before that point either
// tolerates an error or is a no-op, so they are stubbed as such.
type startRoundTestStore struct {
	ports.LiveStore
	round    *domain.Round
	released chan struct{}
}

func (s startRoundTestStore) Settings() ports.SettingsStore {
	return testSettingsStore{settings: &ports.Settings{
		Settings: domain.Settings{SessionDuration: time.Minute},
	}}
}

func (s startRoundTestStore) CurrentRound() ports.CurrentRoundStore {
	return startRoundTestCurrentRound{round: s.round}
}

func (s startRoundTestStore) Intents() ports.IntentStore {
	return startRoundTestIntents{released: s.released}
}

func (s startRoundTestStore) ForfeitTxs() ports.ForfeitTxsStore {
	return startRoundTestForfeitTxs{}
}

func (s startRoundTestStore) ConfirmationSessions() ports.ConfirmationSessionsStore {
	return startRoundTestConfirmations{}
}

func (s startRoundTestStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return startRoundTestTreeSigning{}
}

func (s startRoundTestStore) BoardingInputs() ports.BoardingInputsStore {
	return startRoundTestBoardingInputs{}
}

type startRoundTestCurrentRound struct {
	ports.CurrentRoundStore
	round *domain.Round
}

func (c startRoundTestCurrentRound) Get(context.Context) (*domain.Round, error) {
	return c.round, nil
}

// Upsert refuses, which stops startRound once it has passed the release this
// case is about, without it creating a round the stubs cannot serve.
func (c startRoundTestCurrentRound) Upsert(
	context.Context, func(*domain.Round) *domain.Round,
) error {
	return fmt.Errorf("no round is created in this test")
}

type startRoundTestIntents struct {
	ports.IntentStore
	released chan struct{}
}

func (i startRoundTestIntents) DeleteVtxos(context.Context, string) error {
	close(i.released)
	return nil
}

func (i startRoundTestIntents) ViewAll(
	context.Context, []string,
) ([]ports.TimedIntent, error) {
	return nil, fmt.Errorf("no intents in this test")
}

// The stores startRound resets alongside the claims. Each is a no-op: this case
// is about when the claims are released, not what else the reset does.
type startRoundTestForfeitTxs struct{ ports.ForfeitTxsStore }

func (startRoundTestForfeitTxs) Reset(context.Context) error { return nil }

type startRoundTestConfirmations struct {
	ports.ConfirmationSessionsStore
}

func (startRoundTestConfirmations) Reset(context.Context) error { return nil }

type startRoundTestTreeSigning struct{ ports.TreeSigningSessionsStore }

func (startRoundTestTreeSigning) Delete(context.Context, string) error { return nil }

type startRoundTestBoardingInputs struct{ ports.BoardingInputsStore }

func (startRoundTestBoardingInputs) DeleteSignatures(context.Context, string) error { return nil }

// endedRound is a finished batch as startRound finds it in the cache.
func endedRound(t *testing.T) *domain.Round {
	t.Helper()

	round := domain.NewRoundFromEvents(endedRoundEvents())
	require.True(t, round.IsEnded())
	return round
}

// newRegisterIntentTestService builds the service RegisterIntent needs to reach
// its input reads, which is as far as these cases go.
func newRegisterIntentTestService(t *testing.T, repos *mockedRepoManager) *service {
	t.Helper()

	return &service{
		repoManager:   repos,
		batchSessions: newBatchSessionManager(),
		offchainTxMu:  &sync.Mutex{},
		cache: testLiveStore{
			settings:    registerIntentTestSettings(t),
			offchainTxs: testOffchainTxStore{},
		},
	}
}

func registerIntentTestSettings(t *testing.T) testSettingsStore {
	t.Helper()

	return testSettingsStore{settings: &ports.Settings{
		Settings: domain.Settings{
			VtxoMaxAmount: -1,
			UtxoMaxAmount: -1,
			MaxTxWeight:   400_000,
		},
		DustAmount:   testDust,
		SignerPubkey: testPubkey(t),
	}}
}

// spendingOffchainTxStore reports one outpoint as being spent by a pending
// offchain tx, and every other one as free.
type spendingOffchainTxStore struct {
	ports.OffChainTxStore
	spending domain.Outpoint
}

func (s spendingOffchainTxStore) IncludesAny(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	spending := make([]domain.Outpoint, 0, 1)
	for _, outpoint := range outpoints {
		if outpoint == s.spending {
			spending = append(spending, outpoint)
		}
	}
	return spending, nil
}

// readReportingOffchainTxStore reports each IncludesAny call on reads and finds
// nothing spent.
type readReportingOffchainTxStore struct {
	ports.OffChainTxStore
	reads chan<- string
}

func (s readReportingOffchainTxStore) IncludesAny(
	context.Context, []domain.Outpoint,
) ([]domain.Outpoint, error) {
	select {
	case s.reads <- "IncludesAny":
	default:
	}
	return nil, nil
}

// pushingRegistration is a service and an intent that RegisterIntent accepts
// all the way to the push, once vtxos returns vtxo.
type pushingRegistration struct {
	svc     *service
	repos   *mockedRepoManager
	vtxos   *mockedVtxoRepo
	proof   *intent.Proof
	message intent.RegisterMessage
	vtxo    domain.Vtxo
}

func newPushingRegistration(t *testing.T) pushingRegistration {
	t.Helper()

	message := intent.RegisterMessage{
		BaseMessage:         intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		CosignersPublicKeys: []string{hex.EncodeToString(testPubkey(t).SerializeCompressed())},
	}
	encoded, err := message.Encode()
	require.NoError(t, err)
	proof := testNoteIntentProof(t, encoded, &wire.TxOut{
		Value: int64(testDust) * 2, PkScript: testP2TRScript(t),
	})
	input := proof.GetOutpoints()[0]
	utxo := proof.Inputs[1].WitnessUtxo

	vtxos := &mockedVtxoRepo{}
	repos := &mockedRepoManager{RepoManager: &mockRepoManagerForIndexer{}}
	repos.On("Vtxos").Return(vtxos)
	svc := newRegisterIntentTestService(t, repos)
	svc.operatorPubkey = testPubkey(t)
	svc.feeManager = registrationTestFees{}

	return pushingRegistration{
		svc:     svc,
		repos:   repos,
		vtxos:   vtxos,
		proof:   proof,
		message: message,
		vtxo: domain.Vtxo{
			Outpoint: domain.Outpoint{Txid: input.Hash.String(), VOut: input.Index},
			Amount:   uint64(utxo.Value),
			PubKey:   hex.EncodeToString(utxo.PkScript[2:]),
		},
	}
}

type registrationTestFees struct{ ports.FeeManager }

func (registrationTestFees) ComputeIntentFees(
	context.Context, []wire.TxOut, []domain.Vtxo, []wire.TxOut, []wire.TxOut,
) (int64, error) {
	return 0, nil
}

type registrationTestIntents struct {
	ports.IntentStore
	pushed bool
}

func (s *registrationTestIntents) Push(
	context.Context, domain.Intent, []ports.BoardingInput, []string,
) error {
	s.pushed = true
	return nil
}

// pausingIntentStore holds Push until proceed is closed, closing pushing once it
// is entered, and closes released when DeleteVtxos drops the claims.
type pausingIntentStore struct {
	ports.IntentStore
	pushing  chan struct{}
	proceed  chan struct{}
	released chan struct{}
}

func (s pausingIntentStore) Push(
	context.Context, domain.Intent, []ports.BoardingInput, []string,
) error {
	close(s.pushing)
	<-s.proceed
	return nil
}

func (s pausingIntentStore) DeleteVtxos(context.Context, string) error {
	close(s.released)
	return nil
}

func (s pausingIntentStore) ViewAll(context.Context, []string) ([]ports.TimedIntent, error) {
	return nil, fmt.Errorf("no intents in this test")
}

// registrationRoundTestStore serves a registration and the start of the next
// batch from one cache.
type registrationRoundTestStore struct {
	startRoundTestStore
	settings    ports.SettingsStore
	offchainTxs ports.OffChainTxStore
	intents     ports.IntentStore
}

func (s registrationRoundTestStore) Settings() ports.SettingsStore { return s.settings }

func (s registrationRoundTestStore) OffchainTxs() ports.OffChainTxStore { return s.offchainTxs }

func (s registrationRoundTestStore) Intents() ports.IntentStore { return s.intents }

// requireBlocked fails unless the wait is still running.
func requireBlocked(t *testing.T, waited <-chan []string, msg ...string) {
	t.Helper()

	reason := "the wait ended before the batch was projected"
	if len(msg) > 0 {
		reason = msg[0]
	}
	select {
	case <-waited:
		require.FailNow(t, reason)
	case <-time.After(100 * time.Millisecond):
	}
}

// requireNotTracked fails if the batch is still in flight.
func requireNotTracked(t *testing.T, m *batchSessionManager, batchId string, msg ...string) {
	t.Helper()

	m.lock.Lock()
	_, tracked := m.inflightBatches[batchId]
	m.lock.Unlock()

	reason := "the batch must stop being tracked"
	if len(msg) > 0 {
		reason = msg[0]
	}
	require.False(t, tracked, reason)
}

// requireTracked fails unless the batch is still in flight.
func requireTracked(t *testing.T, m *batchSessionManager, batchId string, msg string) {
	t.Helper()

	m.lock.Lock()
	_, tracked := m.inflightBatches[batchId]
	m.lock.Unlock()

	require.True(t, tracked, msg)
}

// endedRoundWithId is endedRound under another id, for the cases that need two
// batches in flight.
func endedRoundWithId(t *testing.T, id string) *domain.Round {
	t.Helper()

	events := endedRoundEvents()
	for i, event := range events {
		switch e := event.(type) {
		case domain.RoundStarted:
			e.Id = id
			events[i] = e
		case domain.RoundFinalizationStarted:
			e.Id = id
			events[i] = e
		case domain.RoundFinalized:
			e.Id = id
			events[i] = e
		}
	}
	round := domain.NewRoundFromEvents(events)
	require.True(t, round.IsEnded())
	require.Equal(t, id, round.Id)
	return round
}

// registerWithBans registers proof with banning on, vtxos stored and only
// bannedScript convicted.
func registerWithBans(
	t *testing.T, message intent.RegisterMessage, proof *intent.Proof,
	vtxos []domain.Vtxo, bannedScript string,
) errors.Error {
	t.Helper()

	vtxoRepo := &mockedVtxoRepo{}
	vtxoRepo.On("GetVtxos", mock.Anything, mock.Anything).Return(vtxos, nil)
	repos := &mockedRepoManager{}
	repos.On("Vtxos").Return(vtxoRepo)
	repos.On("Convictions").Return(convictionRepoStub{
		convictions: map[string][]domain.ScriptConviction{bannedScript: {{}}},
	})

	settings := registerIntentTestSettings(t)
	settings.settings.BanThreshold = 1
	svc := newRegisterIntentTestService(t, repos)
	svc.cache = testLiveStore{
		settings:    settings,
		offchainTxs: testOffchainTxStore{},
	}

	_, appErr := svc.RegisterIntent(t.Context(), *proof, message)
	return appErr
}
