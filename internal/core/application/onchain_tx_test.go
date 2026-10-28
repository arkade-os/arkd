package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
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
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCosignOnchainTx(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("cosigns broadcasts and records the utxos", func(t *testing.T) {
			f := newCosignFixture(t)
			tx := f.cosignTx(t)

			txid, vErr := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.NoError(t, vErr)
			require.Equal(t, tx.txid, txid)

			// Only the cosignable input is handed to the signer.
			require.Equal(t, 1, f.signer.calls)
			require.Equal(t, []int{0}, f.signer.lastIndexes)
			f.wallet.AssertNumberOfCalls(t, "BroadcastTransaction", 1)

			// The utxo is recorded as spent by the broadcast tx, unconfirmed.
			utxos, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
			require.NoError(t, vErr)
			require.Len(t, utxos, 1)
			require.Equal(t, f.utxo, utxos[0].Outpoint)
			require.Equal(t, f.amount, utxos[0].Amount)
			require.Equal(t, hex.EncodeToString(f.pkScript[2:]), utxos[0].PubKey)
			require.Equal(t, tx.txid, utxos[0].Spend.Txid)

			// The cache reservation is released once the request is served.
			reserved, err := f.svc.cache.CosignedUtxos().IncludesAny(
				t.Context(), []domain.Outpoint{f.utxo},
			)
			require.NoError(t, err)
			require.Empty(t, reserved)

			// The spend is confirmed once the broadcast tx is.
			require.Eventually(t, func() bool {
				utxos, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
				return err == nil && len(utxos) == 1 && utxos[0].Spend.IsConfirmed()
			}, 5*time.Second, 50*time.Millisecond)
			utxos, err = f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
			require.NoError(t, err)
			require.Equal(t, f.spendConfirmedAt.Time, utxos[0].Spend.ConfirmedAtTime)
			require.Equal(t, uint64(f.spendConfirmedAt.Height), utxos[0].Spend.ConfirmedAtHeight)

			// The signed tx is recorded along with its utxos. The fixture signer echoes the
			// tx it's given, so the recorded tx is the submitted one.
			txs, err := f.utxos.GetOnchainTxs(t.Context(), []string{txid})
			require.NoError(t, err)
			require.Equal(t, []string{tx.b64}, txs)

			// The tx lifecycle is recorded as events, keyed by its txid.
			events := f.events.events(txid)
			require.Len(t, events, 2)
			broadcasted, ok := events[0].(domain.OnchainTxBroadcasted)
			require.True(t, ok)
			require.Equal(t, txid, broadcasted.Id)
			require.Equal(t, map[string]struct{}{f.utxo.String(): {}}, broadcasted.SignedInputs)
			confirmed, ok := events[1].(domain.OnchainTxConfirmed)
			require.True(t, ok)
			require.Equal(t, txid, confirmed.Id)
			require.Equal(t, f.spendConfirmedAt.Time, confirmed.ConfirmedAtTime)
			require.Equal(t, uint64(f.spendConfirmedAt.Height), confirmed.ConfirmedAtHeight)
			onchainTx := domain.NewOnchainTxFromEvents(events)
			require.True(t, onchainTx.IsConfirmed())
		})

		// An unconfirmed funding tx is accepted, its exit closures can't be mature yet.
		t.Run("funding tx unconfirmed", func(t *testing.T) {
			f := newCosignFixture(t)
			delete(f.scanner.confirmed, f.fundingTxid)
			tx := f.cosignTx(t)

			txid, vErr := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.NoError(t, vErr)
			require.Equal(t, tx.txid, txid)
			utxos, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
			require.NoError(t, err)
			require.Len(t, utxos, 1)
			require.Equal(t, tx.txid, utxos[0].Spend.Txid)
		})

		// An unrolled vtxo still unspent is cosigned like a boarding utxo.
		t.Run("unrolled vtxo", func(t *testing.T) {
			f := newCosignFixture(t)
			f.vtxos.ExpectedCalls = nil
			f.vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return([]domain.Vtxo{{
				Outpoint: f.utxo, Unrolled: true, ExpiresAt: time.Now().Add(time.Hour).Unix(),
			}}, nil)
			tx := f.cosignTx(t)

			txid, vErr := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.NoError(t, vErr)
			require.Equal(t, tx.txid, txid)
			require.Equal(t, 1, f.signer.calls)
			f.wallet.AssertNumberOfCalls(t, "BroadcastTransaction", 1)
			utxos, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
			require.NoError(t, err)
			require.Len(t, utxos, 1)
			require.Equal(t, tx.txid, utxos[0].Spend.Txid)
			events := f.events.events(txid)
			require.NotEmpty(t, events)
			broadcasted, ok := events[0].(domain.OnchainTxBroadcasted)
			require.True(t, ok)
			require.Equal(t, map[string]struct{}{f.utxo.String(): {}}, broadcasted.SignedInputs)
		})

		t.Run("foreign input signatures are ignored", func(t *testing.T) {
			f := newCosignFixture(t)
			// A key-path input and a script-path input of somebody else, next to the one to
			// cosign. Their signatures are theirs to get right, they are not checked.
			tx := f.cosignTx(t, withForeignInput(t), withForeignScriptPathInput(t))

			txid, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.NoError(t, err)
			require.Equal(t, tx.txid, txid)
			require.Equal(t, []int{0}, f.signer.lastIndexes)
		})

		t.Run("64 inputs", func(t *testing.T) {
			f := newCosignFixture(t)
			tx := f.cosignTx(t, withForeignInputs(63))

			txid, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.NoError(t, err)
			require.Equal(t, tx.txid, txid)
			require.Equal(t, []int{0}, f.signer.lastIndexes)
			f.wallet.AssertNumberOfCalls(t, "GetTransaction", 64)
		})

		t.Run("uses finalized txid for response and event", func(t *testing.T) {
			f := newCosignFixture(t)
			tx := f.cosignTx(t, withForeignInput(t))
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx.b64), true)
			require.NoError(t, err)

			// model the nested-SegWit scriptSig insertion at the builder boundary.
			ptx.UnsignedTx.TxIn[1].SignatureScript = append(
				[]byte{txscript.OP_DATA_22, txscript.OP_0, txscript.OP_DATA_20},
				make([]byte, 20)...,
			)
			finalTxid := ptx.UnsignedTx.TxID()
			require.NotEqual(t, tx.txid, finalTxid)
			var rawTx bytes.Buffer
			require.NoError(t, ptx.UnsignedTx.Serialize(&rawTx))
			f.svc.builder = cosignTestBuilder{rawTx: hex.EncodeToString(rawTx.Bytes())}

			txid, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.NoError(t, err)
			assert.Equal(t, finalTxid, txid)
			events := f.events.events(finalTxid)
			require.NotEmpty(t, events)
			broadcasted, ok := events[0].(domain.OnchainTxBroadcasted)
			require.True(t, ok)
			require.Equal(t, finalTxid, broadcasted.Id)
		})

		t.Run("inputs with deprecated signer past the cutoff", func(t *testing.T) {
			f := newCosignFixture(t)
			// The utxo script was built for the current signer: make it deprecated and past
			// cutoff, with a fresh current one.
			settings := f.settings(t.Context())
			settings.DeprecatedSignerPubkeys = []ports.DeprecatedSignerPubkey{{
				PubKey: settings.SignerPubkey, CutoffDate: time.Now().Add(-time.Hour),
			}}
			settings.SignerPubkey = testPubkey(t)
			f.setSettings(t, settings)
			tx := f.cosignTx(t)

			txid, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.NoError(t, err)
			require.Equal(t, tx.txid, txid)
		})

		// Two requests spend the same utxo with different txs: the second is refused by the
		// cache while the first is still being served, and by the db once the first is recorded.
		t.Run("only one of two concurrent requests is handled", func(t *testing.T) {
			f := newCosignFixture(t)
			// Hold the signer so the first request stays in flight.
			f.signer.hold = make(chan struct{})
			first := f.cosignTx(t)
			second := f.cosignTx(t, withOutputAmount(f.amount-2000))

			cosigned := make(chan error, 1)
			go func() {
				txid, vErr := f.svc.CosignOnchainTx(t.Context(), first.b64)
				switch {
				case vErr != nil:
					cosigned <- vErr
				case txid != first.txid:
					cosigned <- fmt.Errorf("unexpected txid %s", txid)
				default:
					cosigned <- nil
				}
			}()
			require.Eventually(t, func() bool {
				return f.signer.waiting() == 1
			}, time.Second, 10*time.Millisecond)

			// The utxo is locked for the first request, so the second is refused before
			// reaching the signer.
			_, err := f.svc.CosignOnchainTx(t.Context(), second.b64)
			require.Error(t, err)
			require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.Code())
			require.Contains(t, err.Error(), "already co-signed")
			require.Equal(t, 1, f.signer.calls)

			close(f.signer.hold)
			require.NoError(t, <-cosigned)
			f.wallet.AssertNumberOfCalls(t, "BroadcastTransaction", 1)

			// Retrying after the fact is refused by the db record.
			_, err = f.svc.CosignOnchainTx(t.Context(), second.b64)
			require.Error(t, err)
			require.Contains(t, err.Error(), "already signed")
		})

		// A boarding utxo can either be cosigned or registered in a batch, never both.
		// Whoever takes cosignMu first wins, the other is rejected by the loser's check
		// against the winner's store.
		t.Run("only one of a concurrent cosign and intent registration is handled", func(t *testing.T) {
			t.Run("cosign first", func(t *testing.T) {
				f := newCosignFixture(t)
				reg := f.registration(t)
				f.signer.hold = make(chan struct{})
				tx := f.cosignTx(t)

				cosigned := make(chan error, 1)
				go func() {
					_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
					cosigned <- err
				}()
				// The utxo is reserved while the cosign request is still signing.
				require.Eventually(t, func() bool {
					return f.signer.waiting() == 1
				}, time.Second, 10*time.Millisecond)

				_, appErr := f.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
				require.Error(t, appErr)
				require.Equal(t, errors.INVALID_PSBT_INPUT.Code, appErr.Code())
				require.Contains(t, appErr.Error(), "being cosigned")

				close(f.signer.hold)
				require.NoError(t, <-cosigned)

				// Once cosigned, the utxo is rejected by the db record too.
				_, appErr = f.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
				require.Error(t, appErr)
				require.Equal(t, errors.INVALID_PSBT_INPUT.Code, appErr.Code())
				require.Contains(t, appErr.Error(), "already cosigned")
			})

			t.Run("registration first", func(t *testing.T) {
				f := newCosignFixture(t)
				reg := f.registration(t)
				tx := f.cosignTx(t)

				_, appErr := f.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
				require.NoError(t, appErr)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "registered in intents queue")
				require.Equal(t, 0, f.signer.calls)
			})

			t.Run("pending registration wins against cosign via the intent cache", func(t *testing.T) {
				f := newCosignFixture(t)
				reg := f.registration(t)

				// This intent has a boarding input, so RegisterIntent holds cosignMu at this check.
				// Pause here: lockUtxos must wait, then reject the input once the intent is queued.
				read, proceed := make(chan struct{}), make(chan struct{})
				resume := sync.OnceFunc(func() { close(proceed) })
				f.svc.repoManager.(*mockedRepoManager).utxos = &pausingCosignedUtxoRepo{
					UtxoRepository: f.utxos, read: read, proceed: proceed,
				}
				var requests sync.WaitGroup
				t.Cleanup(func() { resume(); requests.Wait() })
				registered, cosigned := make(chan errors.Error, 1), make(chan errors.Error, 1)
				requests.Go(func() {
					_, err := f.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
					registered <- err
				})
				<-read

				requests.Go(func() {
					cosigned <- f.svc.lockUtxos(t.Context(), "", []domain.Outpoint{f.utxo})
				})
				// lockUtxos must wait for registration to release cosignMu.
				select {
				case err := <-cosigned:
					t.Fatalf("cosign completed before registration could push: %v", err)
				case <-time.After(100 * time.Millisecond):
				}

				resume()
				require.NoError(t, <-registered)
				appErr := <-cosigned
				require.Error(t, appErr)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, appErr.Code())
				require.Contains(t, appErr.Error(), "registered in intents queue")
				f.requireReleasedAndUnrecorded(t)
			})
		})

		// If the request is canceled while signing, the utxos reserved for it are removed
		// from the cache.
		t.Run("utxos released if request is canceled", func(t *testing.T) {
			f := newCosignFixture(t)
			ctx, cancel := context.WithCancel(f.svc.ctx)
			t.Cleanup(cancel)
			f.svc.cache = cosignCancellationTestStore{
				LiveStore: f.svc.cache,
				utxos:     contextAwareCosignTestUtxos{f.svc.cache.CosignedUtxos()},
				intents:   f.svc.cache.Intents(),
			}
			// Hold the signer so the request is canceled while signing.
			f.signer.hold = make(chan struct{})
			tx := f.cosignTx(t)

			cosigned := make(chan error, 1)
			go func() {
				_, err := f.svc.CosignOnchainTx(ctx, tx.b64)
				cosigned <- err
			}()

			// The utxo is reserved while the request is still signing...
			require.Eventually(t, func() bool {
				return f.signer.waiting() == 1
			}, time.Second, 10*time.Millisecond)
			reserved, err := f.svc.cache.CosignedUtxos().IncludesAny(
				t.Context(), []domain.Outpoint{f.utxo},
			)
			require.NoError(t, err)
			require.Equal(t, []domain.Outpoint{f.utxo}, reserved)

			// ...and released once the request is canceled.
			cancel()
			close(f.signer.hold)
			vErr := <-cosigned
			require.Error(t, vErr)
			require.Equal(t, errors.INTERNAL_ERROR.Code, vErr.(errors.Error).Code())
			require.NoError(t, f.svc.ctx.Err())
			f.wallet.AssertNotCalled(t, "BroadcastTransaction", mock.Anything, mock.Anything)
			f.requireReleasedAndUnrecorded(t)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		// Every case must fail before anything is signed or broadcast, and must leave no
		// reservation in the cache and no record in the db.
		requireNothingDone := func(t *testing.T, f *cosignFixture) {
			t.Helper()
			require.Equal(t, 0, f.signer.calls)
			f.wallet.AssertNotCalled(t, "BroadcastTransaction", mock.Anything, mock.Anything)
			reserved, err := f.svc.cache.CosignedUtxos().IncludesAny(
				t.Context(), []domain.Outpoint{f.utxo},
			)
			require.NoError(t, err)
			require.Empty(t, reserved)
			utxos, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
			require.NoError(t, err)
			require.Empty(t, utxos)
		}

		t.Run("settlement hands the intent claim to the spent record", func(t *testing.T) {
			f := newCosignFixture(t)
			vtxo := f.vtxo()
			vtxo.Unrolled = true
			intents := f.svc.cache.Intents().(*cosignTestIntentStore)
			require.NoError(t, intents.Push(
				t.Context(), domain.Intent{Inputs: []domain.Vtxo{vtxo}}, nil, nil,
			))
			settlementTxid := randomTxid(t)
			settle := func() {
				// Projection is visible before the batch releases its claim.
				vtxo.Spent = true
				vtxo.SettledBy = settlementTxid
				intents.mu.Lock()
				delete(intents.claimed, f.utxo)
				intents.mu.Unlock()
			}
			f.vtxos.ExpectedCalls = nil
			read := f.vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{f.utxo})
			read.Run(func(mock.Arguments) {
				snapshot := vtxo
				reserved, err := f.svc.cache.CosignedUtxos().IncludesAny(
					t.Context(), []domain.Outpoint{f.utxo},
				)
				require.NoError(t, err)
				// Intercept the read under the reservation, after request
				// validation. Later reads see the spent state, not this snapshot.
				if len(reserved) > 0 && !vtxo.Spent {
					settle()
				}
				read.Return([]domain.Vtxo{snapshot}, nil)
			})
			tx := f.cosignTx(t)

			txid, appErr := f.svc.CosignOnchainTx(t.Context(), tx.b64)
			require.Error(t, appErr)
			require.Empty(t, txid)
			require.Equal(t, errors.INVALID_ARK_PSBT.Code, appErr.Code())
			require.Contains(t, appErr.Error(), "already registered in intents queue")
			require.Contains(t, appErr.Error(), f.utxo.String())
			requireNothingDone(t, f)
			require.Empty(t, f.events.events(tx.txid))
			// Checking the claim first rejects before the settlement hook runs.
			f.vtxos.AssertExpectations(t)
		})

		t.Run("malformed tx", func(t *testing.T) {
			tests := []struct {
				name           string
				opts           []cosignTxOption
				errCode        uint16
				errContains    string
				fundingLookups int
			}{
				{
					// Foreign inputs count toward the limit too, even with only one input to cosign.
					name:        "too many inputs",
					opts:        []cosignTxOption{withForeignInputs(64)},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "too many inputs: got 65, max 64",
				},
				{
					name:        "missing prevout",
					opts:        []cosignTxOption{withoutPrevout()},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "missing prevout",
				},
				{
					name: "missing prevout on later input",
					opts: []cosignTxOption{
						withForeignInput(t),
						func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
							ptx.Inputs[1].WitnessUtxo = nil
						},
					},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "missing prevout for input 1",
				},
				{
					name: "negative input amount",
					opts: []cosignTxOption{func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
						ptx.Inputs[0].WitnessUtxo.Value = -1
					}},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "input amounts out of range",
				},
				{
					name: "total input amount exceeds max money",
					opts: []cosignTxOption{
						withForeignInput(t),
						func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
							ptx.Inputs[1].WitnessUtxo.Value = btcutil.MaxSatoshi
						},
					},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "input amounts out of range",
				},
				{
					name:        "unsigned input",
					opts:        []cosignTxOption{withoutSignatures()},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "missing signatures",
				},
				{
					name:        "more than one tapleaf script",
					opts:        []cosignTxOption{withDuplicatedLeaf()},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "expected exactly 1 tapleaf script",
				},
				{
					name:        "prevout script mismatch",
					opts:        []cosignTxOption{withPrevoutScript(testP2TRScript(t))},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "taptree of input 0 doesn't match prevout script",
				},
				{
					name: "foreign prevout mismatch",
					opts: []cosignTxOption{withForeignInput(t), func(t *testing.T, f *cosignFixture, ptx *psbt.Packet) {
						ptx.Inputs[1].WitnessUtxo.Value++
						f.resign(t, ptx)
					}},
					errCode:        errors.INVALID_ARK_PSBT.Code,
					errContains:    "prevout mismatch for input 1",
					fundingLookups: 2,
				},
				{
					name:        "sum of outputs greater than sum of inputs",
					opts:        []cosignTxOption{withOutputAmount(200_000)},
					errCode:     errors.INVALID_ARK_PSBT.Code,
					errContains: "sum of outputs greater than sum of inputs",
				},
				{
					name:        "too heavy",
					opts:        []cosignTxOption{withOutputs(3000)},
					errCode:     errors.TX_TOO_LARGE.Code,
					errContains: "too heavy",
				},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					f := newCosignFixture(t)
					tx := f.cosignTx(t, tt.opts...)

					_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
					require.Error(t, err)
					require.Equal(t, tt.errCode, err.(errors.Error).Code())
					require.Contains(t, err.Error(), tt.errContains)
					f.wallet.AssertNumberOfCalls(t, "GetTransaction", tt.fundingLookups)
					requireNothingDone(t, f)
				})
			}

			t.Run("not a psbt", func(t *testing.T) {
				f := newCosignFixture(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), "not a psbt")
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "failed to parse tx")
				requireNothingDone(t, f)
			})

			t.Run("nothing to cosign", func(t *testing.T) {
				f := newCosignFixture(t)
				// A tx spending only a foreign input is not our business.
				tx := f.cosignTx(t, withoutCosignableInput(), withForeignInput(t))

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "no inputs to cosign")
				f.wallet.AssertNumberOfCalls(t, "GetTransaction", 0)
				requireNothingDone(t, f)
			})
		})

		t.Run("forged psbt prevout", func(t *testing.T) {
			for _, field := range []string{"value", "script"} {
				t.Run(field, func(t *testing.T) {
					f := newCosignFixture(t)
					funding := f.fundingTx.Copy()
					switch field {
					case "value":
						funding.TxOut[0].Value--
					case "script":
						victimScript := script.NewDefaultVtxoScript(
							testPubkey(t), f.signerKey.PubKey(), f.exitDelay,
						)
						tapKey, _, err := victimScript.TapTree()
						require.NoError(t, err)
						funding.TxOut[0].PkScript, err = script.P2TRScript(tapKey)
						require.NoError(t, err)
					}

					// Reference the actual funding tx, but submit the fixture's original
					// amount, owner tree and matching signature as the claimed prevout.
					f.utxo.Txid = funding.TxID()
					f.svc.wallet = newCosignTestWallet(funding, f.spendConfirmedAt)
					f.scanner.confirmed[f.utxo.Txid] = f.scanner.confirmed[f.fundingTxid]
					tx := f.cosignTx(t)
					ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx.b64), true)
					require.NoError(t, err)

					// Validation must reject this before CosignOnchainTx reserves or signs.
					_, _, vErr := f.svc.validateOnchainTx(t.Context(), tx.b64, ptx)
					require.Error(t, vErr)
					require.Equal(t, errors.INVALID_ARK_PSBT.Code, vErr.Code())
					require.Contains(t, vErr.Error(), "prevout mismatch for input 0")
				})
			}
		})

		t.Run("signatures", func(t *testing.T) {
			tests := []struct {
				name string
				// cosigners other than the signer locking the utxo, 1 if unset.
				cosigners   int
				opts        []cosignTxOption
				errContains string
			}{
				{
					// The utxo is locked by us and 2 owners, one of them didn't sign.
					name:        "missing one of the other cosigners signatures",
					cosigners:   2,
					opts:        []cosignTxOption{withSignaturesDropped(1)},
					errContains: "missing signatures for input 0: expected 2, got 1",
				},
				{
					name:        "more signatures than cosigners",
					cosigners:   2,
					opts:        []cosignTxOption{withExtraSignature(t)},
					errContains: "missing signatures for input 0: expected 2, got 3",
				},
				{
					name:        "signature for a leaf other than the spending one",
					opts:        []cosignTxOption{withSignatureLeafHash(bytes.Repeat([]byte{1}, 32))},
					errContains: "signature for a leaf other than the spending one",
				},
				{
					name:        "signature commits to signer pubkey",
					opts:        []cosignTxOption{withSignatureBy(signerKeyOf)},
					errContains: "includes a signature that commits to signer pubkey",
				},
				{
					name:        "signature by a pubkey not in the spending leaf",
					opts:        []cosignTxOption{withSignatureBy(func(*cosignFixture) *btcec.PublicKey { return testPubkey(t) })},
					errContains: "not included in the spending leaf",
				},
				{
					name:        "sighash type of the input is not ALL or DEFAULT",
					opts:        []cosignTxOption{withSighash(txscript.SigHashSingle)},
					errContains: "invalid sighash type",
				},
				{
					name:        "signature with a sighash type other than the input one",
					opts:        []cosignTxOption{withSignatureSighash(txscript.SigHashAll)},
					errContains: "unexpected sighash type",
				},
				{
					// Well-formed but not valid: the fixture signer never runs.
					name:        "forged signature",
					opts:        []cosignTxOption{withForgedSignature()},
					errContains: "invalid signatures",
				},
				{
					// Valid for another tx: the output was changed after signing.
					name:        "signature for a different tx",
					opts:        []cosignTxOption{withStaleSignature()},
					errContains: "invalid signatures",
				},
				{
					// The control block doesn't commit the leaf to the prevout.
					name:        "wrong control block",
					opts:        []cosignTxOption{withWrongControlBlock()},
					errContains: "invalid signatures",
				},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					f := newCosignFixture(t, withCosigners(max(tt.cosigners, 1)))
					tx := f.cosignTx(t, tt.opts...)

					_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
					require.Error(t, err)
					require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
					require.Contains(t, err.Error(), tt.errContains)
					f.wallet.AssertNumberOfCalls(t, "GetTransaction", 0)
					requireNothingDone(t, f)
				})
			}
		})

		t.Run("script", func(t *testing.T) {
			t.Run("spending leaf is the exit path", func(t *testing.T) {
				// An exit path spend doesn't involve us: the input is skipped, not rejected,
				// and there's nothing left to cosign.
				f := newCosignFixture(t)
				tx := f.cosignTx(t, withExitLeaf())

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Contains(t, err.Error(), "no inputs to cosign")
				requireNothingDone(t, f)
			})

			t.Run("leaf without our signer key", func(t *testing.T) {
				f := newCosignFixture(t)
				// The script is valid for a signer we don't know: skipped, not rejected.
				f.setSettings(t, func() ports.Settings {
					s := f.settings(t.Context())
					s.SignerPubkey = testPubkey(t)
					return s
				}())
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Contains(t, err.Error(), "no inputs to cosign")
				requireNothingDone(t, f)
			})

			t.Run("exit delay shorter than the boarding one", func(t *testing.T) {
				f := newCosignFixture(t)
				settings := f.settings(t.Context())
				settings.BoardingExitDelay = arklib.RelativeLocktime{
					Type: arklib.LocktimeTypeSecond, Value: f.exitDelay.Value * 2,
				}
				f.setSettings(t, settings)
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "invalid vtxo script")
				requireNothingDone(t, f)
			})

			// An unrolled vtxo is locked by a vtxo script, checked against the unilateral exit
			// delay rather than the boarding one.
			t.Run("exit delay of unrolled vtxo shorter than the unilateral one", func(t *testing.T) {
				f := newCosignFixture(t)
				settings := f.settings(t.Context())
				settings.UnilateralExitDelay = arklib.RelativeLocktime{
					Type: arklib.LocktimeTypeSecond, Value: f.exitDelay.Value * 2,
				}
				f.setSettings(t, settings)
				f.vtxos.ExpectedCalls = nil
				f.vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return([]domain.Vtxo{{
					Outpoint: f.utxo, Unrolled: true,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
				}}, nil)
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "invalid vtxo script")
				requireNothingDone(t, f)
			})
		})

		t.Run("chain state", func(t *testing.T) {
			t.Run("utxo already spent", func(t *testing.T) {
				f := newCosignFixture(t)
				f.wallet.spent[f.utxo] = true
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "already spent")
				requireNothingDone(t, f)
			})

			t.Run("exit path already available", func(t *testing.T) {
				f := newCosignFixture(t)
				f.scanner.confirmed[f.fundingTxid] = &ports.BlockTimestamp{
					Height: 100, Time: time.Now().Add(-time.Duration(f.exitDelay.Value) * time.Second).Unix(),
				}
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "available exit closure")
				requireNothingDone(t, f)
			})

			t.Run("exit path available within the margin", func(t *testing.T) {
				f := newCosignFixture(t)
				settings := f.settings(t.Context())
				settings.UnrolledVtxoMinExpiryMargin = 10 * time.Minute
				f.setSettings(t, settings)
				// Matures in 5 minutes, within the margin.
				f.scanner.confirmed[f.fundingTxid] = &ports.BlockTimestamp{
					Height: 100,
					Time: time.Now().Add(
						-time.Duration(f.exitDelay.Value)*time.Second + 5*time.Minute,
					).Unix(),
				}
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Contains(t, err.Error(), "available exit closure")
				requireNothingDone(t, f)
			})
		})

		t.Run("already known outpoints", func(t *testing.T) {
			t.Run("already cosigned", func(t *testing.T) {
				f := newCosignFixture(t)
				require.NoError(t, f.utxos.AddUtxos(t.Context(), []domain.Utxo{{
					Outpoint: f.utxo, Amount: f.amount, PubKey: hex.EncodeToString(f.pkScript[2:]),
					Spend: domain.UtxoSpend{Txid: randomTxid(t)}, CreatedAt: time.Now().Unix(),
				}}, ""))
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "already signed")
				require.Equal(t, 0, f.signer.calls)
			})

			t.Run("tracked as vtxo", func(t *testing.T) {
				f := newCosignFixture(t)
				f.vtxos.ExpectedCalls = nil
				f.vtxos.On("GetVtxos", mock.Anything, mock.Anything).
					Return([]domain.Vtxo{{Outpoint: f.utxo}}, nil)
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "tracked offchain")
				requireNothingDone(t, f)
			})

			// An unrolled vtxo spent offchain is claimed by its checkpoint or forfeit tx, an
			// expired one is swept by us.
			// An offchain tx spending the vtxo is cached but not projected yet, so the vtxo
			// still reads unspent in the db while it got unrolled meanwhile.
			t.Run("unrolled vtxo spent by a cached offchain tx", func(t *testing.T) {
				f := newCosignFixture(t)
				f.vtxos.ExpectedCalls = nil
				f.vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return([]domain.Vtxo{{
					Outpoint: f.utxo, Unrolled: true,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
				}}, nil)
				f.svc.cache.(*cosignTestLiveStore).spentOffchain = []domain.Outpoint{f.utxo}
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "already spent offchain")
				requireNothingDone(t, f)
			})

			t.Run("unrolled vtxo spent offchain", func(t *testing.T) {
				f := newCosignFixture(t)
				f.vtxos.ExpectedCalls = nil
				f.vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return([]domain.Vtxo{{
					Outpoint: f.utxo, Unrolled: true, Spent: true,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
				}}, nil)
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "already spent offchain")
				requireNothingDone(t, f)
			})

			t.Run("unrolled vtxo expired", func(t *testing.T) {
				f := newCosignFixture(t)
				f.vtxos.ExpectedCalls = nil
				f.vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return([]domain.Vtxo{{
					Outpoint: f.utxo, Unrolled: true,
					ExpiresAt: time.Now().Add(-time.Hour).Unix(),
				}}, nil)
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "already expired")
				requireNothingDone(t, f)
			})

			t.Run("checkpoint output", func(t *testing.T) {
				f := newCosignFixture(t)
				f.offchainTxs.checkpoints[f.fundingTxid] = struct{}{}
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INVALID_ARK_PSBT.Code, err.(errors.Error).Code())
				require.Contains(t, err.Error(), "checkpoint outputs")
				requireNothingDone(t, f)
			})

			t.Run("registered in the intents queue", func(t *testing.T) {
				f := newCosignFixture(t)
				reg := f.registration(t)
				_, appErr := f.svc.RegisterIntent(t.Context(), *reg.proof, reg.message)
				require.NoError(t, appErr)
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Contains(t, err.Error(), "registered in intents queue")
				requireNothingDone(t, f)
			})
		})

		// Failures after the reservation must release it and record nothing, so the utxo
		// can be retried.
		t.Run("failures after reservation", func(t *testing.T) {
			t.Run("signer fails", func(t *testing.T) {
				f := newCosignFixture(t)
				f.signer.err = fmt.Errorf("signer unavailable")
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INTERNAL_ERROR.Code, err.(errors.Error).Code())
				f.wallet.AssertNotCalled(t, "BroadcastTransaction", mock.Anything, mock.Anything)
				f.requireReleasedAndUnrecorded(t)

				// Retry succeeds once the signer is back.
				f.signer.err = nil
				_, err = f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.NoError(t, err)
			})

			t.Run("broadcast fails", func(t *testing.T) {
				f := newCosignFixture(t)
				f.wallet.broadcastErr = fmt.Errorf("node unavailable")
				tx := f.cosignTx(t)

				_, err := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.Error(t, err)
				require.Equal(t, errors.INTERNAL_ERROR.Code, err.(errors.Error).Code())
				f.requireReleasedAndUnrecorded(t)
			})

			// Once broadcast, the tx is out and the request succeeds whatever the projection
			// does. If the projection fails (we assume it's rare if even impossible), the utxo has
			// no record, so it must stay reserved: the reservation is the only thing left
			// preventing a second signature.
			t.Run("projection fails and keeps the utxo in cache", func(t *testing.T) {
				f := newCosignFixture(t)
				f.events.projectionErr = fmt.Errorf("db unavailable")
				tx := f.cosignTx(t)

				txid, vErr := f.svc.CosignOnchainTx(t.Context(), tx.b64)
				require.NoError(t, vErr)
				require.Equal(t, tx.txid, txid)
				f.wallet.AssertNumberOfCalls(t, "BroadcastTransaction", 1)

				utxos, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
				require.NoError(t, err)
				require.Empty(t, utxos)
				reserved, err := f.svc.cache.CosignedUtxos().IncludesAny(
					t.Context(), []domain.Outpoint{f.utxo},
				)
				require.NoError(t, err)
				require.Equal(t, []domain.Outpoint{f.utxo}, reserved)

				// Any further request on the utxo is rejected by the reservation.
				_, vErr = f.svc.CosignOnchainTx(
					t.Context(), f.cosignTx(t, withOutputAmount(f.amount-2000)).b64,
				)
				require.Error(t, vErr)
				require.Contains(t, vErr.Error(), "already co-signed")
				require.Equal(t, 1, f.signer.calls)
			})
		})
	})
}

// At startup, the cosigned utxos whose spending tx is still unconfirmed are watched again,
// so a restart between broadcast and confirmation doesn't leave them unconfirmed forever.
func TestRestoreWatchingCosignedUtxos(t *testing.T) {
	// noUnconfirmedUtxos reports whether every utxo of the fixture is confirmed.
	noUnconfirmedUtxos := func(f *cosignFixture) func() bool {
		return func() bool {
			cosigned, boarding, unrolled, err := f.utxos.GetUnconfirmedUtxos(t.Context())
			return err == nil && len(cosigned)+len(boarding)+len(unrolled) == 0
		}
	}

	t.Run("valid", func(t *testing.T) {
		t.Run("unconfirmed utxos are confirmed once their tx is", func(t *testing.T) {
			f := newCosignFixture(t)
			// Two utxos spent by one tx, one by another, one already confirmed by a third.
			txA, txB, txC := randomTxid(t), randomTxid(t), randomTxid(t)
			confirmedAt := &ports.BlockTimestamp{Height: 50, Time: time.Now().Add(-time.Hour).Unix()}
			pending := []domain.Utxo{
				f.seedCosignedUtxo(t, txA, nil), f.seedCosignedUtxo(t, txA, nil),
				f.seedCosignedUtxo(t, txB, nil),
			}
			done := f.seedCosignedUtxo(t, txC, confirmedAt)

			require.NoError(t, f.svc.restoreWatchingCosignedUtxos())

			require.Eventually(t, noUnconfirmedUtxos(f), 5*time.Second, 50*time.Millisecond)

			for _, utxo := range pending {
				got, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{utxo.Outpoint})
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, utxo.Spend.Txid, got[0].Spend.Txid)
				require.Equal(t, f.spendConfirmedAt.Time, got[0].Spend.ConfirmedAtTime)
				require.Equal(t, uint64(f.spendConfirmedAt.Height), got[0].Spend.ConfirmedAtHeight)
			}

			// The already confirmed one is left alone.
			got, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{done.Outpoint})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, confirmedAt.Time, got[0].Spend.ConfirmedAtTime)
			require.Equal(t, uint64(confirmedAt.Height), got[0].Spend.ConfirmedAtHeight)

			// Utxos are watched by spending tx, not one by one.
			require.Equal(t, 1, f.wallet.confirmationChecks(txA))
			require.Equal(t, 1, f.wallet.confirmationChecks(txB))
			require.Equal(t, 0, f.wallet.confirmationChecks(txC))
		})

		// The real projection ignores a confirmed event with no broadcasted one before it, which
		// is the case of a commitment tx spending boarding utxos and of a checkpoint, forfeit or
		// exit path tx spending unrolled vtxos, so these must be confirmed without any event.
		t.Run("utxos spent by a tx not cosigned are confirmed without events", func(t *testing.T) {
			f := newCosignFixture(t)
			commitmentTxid, exitTxid, cosignTxid := randomTxid(t), randomTxid(t), randomTxid(t)
			boarding := f.seedUtxo(t, commitmentTxid, nil)
			unrolled := f.seedUnrolledVtxo(t, exitTxid)
			f.seedCosignedUtxo(t, cosignTxid, nil)

			require.NoError(t, f.svc.restoreWatchingCosignedUtxos())

			require.Eventually(t, noUnconfirmedUtxos(f), 5*time.Second, 50*time.Millisecond)
			for _, utxo := range []domain.Utxo{boarding, unrolled} {
				got, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{utxo.Outpoint})
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, f.spendConfirmedAt.Time, got[0].Spend.ConfirmedAtTime)
				require.Equal(t, uint64(f.spendConfirmedAt.Height), got[0].Spend.ConfirmedAtHeight)
			}
			require.Empty(t, f.events.events(commitmentTxid))
			require.Empty(t, f.events.events(exitTxid))
			require.NotEmpty(t, f.events.events(cosignTxid))
		})

		t.Run("nothing to restore", func(t *testing.T) {
			f := newCosignFixture(t)
			done := f.seedUtxo(t, randomTxid(t), f.spendConfirmedAt)

			require.NoError(t, f.svc.restoreWatchingCosignedUtxos())

			require.Never(t, func() bool {
				return f.wallet.confirmationChecks(done.Spend.Txid) > 0
			}, 300*time.Millisecond, 20*time.Millisecond)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("fail to read utxos from db", func(t *testing.T) {
			f := newCosignFixture(t)
			f.utxos.unconfirmedErr = fmt.Errorf("db unavailable")

			err := f.svc.restoreWatchingCosignedUtxos()
			require.Error(t, err)
			require.ErrorContains(t, err, "db unavailable")
		})

		// A failed confirmation lookup gives up on that tx, the utxo stays unconfirmed for the
		// next restart to pick up, and the other txs are unaffected.
		t.Run("fail to wait for confirmation", func(t *testing.T) {
			f := newCosignFixture(t)
			txA, txB := randomTxid(t), randomTxid(t)
			broken := f.seedCosignedUtxo(t, txA, nil)
			fine := f.seedCosignedUtxo(t, txB, nil)
			f.wallet.confirmErr[txA] = fmt.Errorf("node unavailable")

			require.NoError(t, f.svc.restoreWatchingCosignedUtxos())

			require.Eventually(t, func() bool {
				got, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{fine.Outpoint})
				return err == nil && len(got) == 1 && got[0].Spend.IsConfirmed()
			}, 8*time.Second, 50*time.Millisecond)

			got, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{broken.Outpoint})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.False(t, got[0].Spend.IsConfirmed())
			require.Equal(t, 1, f.wallet.confirmationChecks(txA))
		})
	})
}

func TestWatchSpentCosignedUtxos(t *testing.T) {
	t.Run("tracks confirmation of a tx spending boarding utxos and unrolled vtxos", func(t *testing.T) {
		f := newCosignFixture(t)
		txid, otherTxid := randomTxid(t), randomTxid(t)
		spent := []domain.Utxo{
			f.seedUtxo(t, txid, nil), f.seedUtxo(t, txid, nil), f.seedUnrolledVtxo(t, txid),
		}
		other := f.seedUtxo(t, otherTxid, nil)

		f.svc.watchSpentCosignedUtxos(txid)

		for _, utxo := range spent {
			got, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{utxo.Outpoint})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, f.spendConfirmedAt.Time, got[0].Spend.ConfirmedAtTime)
			require.Equal(t, uint64(f.spendConfirmedAt.Height), got[0].Spend.ConfirmedAtHeight)
		}
		require.Empty(t, f.events.events(txid))

		// Utxos spent by another tx are left alone.
		got, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{other.Outpoint})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.False(t, got[0].Spend.IsConfirmed())
		require.Equal(t, 0, f.wallet.confirmationChecks(otherTxid))
	})

	t.Run("skip track confirmation of a tx spending no utxo", func(t *testing.T) {
		f := newCosignFixture(t)
		txid := randomTxid(t)

		f.svc.watchSpentCosignedUtxos(txid)

		require.Equal(t, 0, f.wallet.confirmationChecks(txid))
	})
}

// cosignFixture is a service wired for CosignOnchainTx and RegisterIntent with a real
// in-memory live store, a fake utxo repo and fakes for signer, wallet, scanner and builder.
// It owns a confirmed boarding utxo locked by a script of owner + signer with a CSV exit.
type cosignFixture struct {
	svc         *service
	signer      *cosignTestSigner
	wallet      *cosignTestWallet
	scanner     *cosignTestScanner
	utxos       *fakeUtxoRepo
	events      *fakeEventRepo
	vtxos       *mockedVtxoRepo
	rounds      *mockedRoundRepo
	offchainTxs *cosignTestOffchainTxRepo

	// owners are the cosigners of the forfeit leaf other than the signer, one by default.
	owners    []*btcec.PrivateKey
	signerKey *btcec.PrivateKey
	exitDelay arklib.RelativeLocktime

	vtxoScript  script.VtxoScript
	tapscripts  []string
	pkScript    []byte
	forfeitLeaf *psbt.TaprootTapLeafScript
	exitLeaf    *psbt.TaprootTapLeafScript

	fundingTx        *wire.MsgTx
	fundingTxid      string
	utxo             domain.Outpoint
	amount           uint64
	spendConfirmedAt *ports.BlockTimestamp
}

type cosignFixtureOption func(*cosignFixture)

// withCosigners sets how many cosigners other than the signer lock the utxo.
func withCosigners(n int) cosignFixtureOption {
	return func(f *cosignFixture) {
		f.owners = make([]*btcec.PrivateKey, 0, n)
		for range n {
			key, _ := btcec.NewPrivateKey()
			f.owners = append(f.owners, key)
		}
	}
}

func newCosignFixture(t *testing.T, opts ...cosignFixtureOption) *cosignFixture {
	t.Helper()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	f := &cosignFixture{signerKey: signerKey}
	withCosigners(1)(f)
	for _, opt := range opts {
		opt(f)
	}

	// The default script, owners + signer with a CSV exit for the first owner. A 2 hours
	// CSV exit, confirmed an hour ago: far from maturing.
	exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 7168}
	forfeitKeys := make([]*btcec.PublicKey, 0, len(f.owners)+1)
	for _, owner := range f.owners {
		forfeitKeys = append(forfeitKeys, owner.PubKey())
	}
	forfeitKeys = append(forfeitKeys, signerKey.PubKey())
	vtxoScript := &script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: forfeitKeys[:1]},
			Locktime:        exitDelay,
		},
		&script.MultisigClosure{PubKeys: forfeitKeys},
	}}
	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	leafOf := func(closure script.Closure) *psbt.TaprootTapLeafScript {
		leafScript, err := closure.Script()
		require.NoError(t, err)
		proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(leafScript).TapHash())
		require.NoError(t, err)
		return &psbt.TaprootTapLeafScript{
			ControlBlock: proof.ControlBlock, Script: proof.Script,
			LeafVersion: txscript.BaseLeafVersion,
		}
	}
	forfeitLeaf := leafOf(vtxoScript.ForfeitClosures()[0])
	exitLeaf := leafOf(vtxoScript.ExitClosures()[0])

	amount := uint64(100_000)
	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	fundingTx.AddTxOut(&wire.TxOut{Value: int64(amount), PkScript: pkScript})
	fundingTxid := fundingTx.TxID()
	utxo := domain.Outpoint{Txid: fundingTxid, VOut: 0}

	spendConfirmedAt := &ports.BlockTimestamp{Height: 101, Time: time.Now().Unix()}
	signer := &cosignTestSigner{}
	wallet := newCosignTestWallet(fundingTx, spendConfirmedAt)
	scanner := &cosignTestScanner{confirmed: map[string]*ports.BlockTimestamp{
		fundingTxid: {Height: 100, Time: time.Now().Add(-time.Hour).Unix()},
	}}
	utxos := newFakeUtxoRepo()
	vtxos := &mockedVtxoRepo{}
	vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(nil, nil)
	offchainTxs := &cosignTestOffchainTxRepo{checkpoints: make(map[string]struct{})}
	rounds := &mockedRoundRepo{}

	events := newFakeEventRepo(t, utxos)

	repos := &mockedRepoManager{RepoManager: &mockRepoManagerForIndexer{}}
	repos.On("Vtxos").Return(vtxos)
	repos.On("OffchainTxs").Return(offchainTxs)
	repos.On("Rounds").Return(rounds)
	repos.On("Convictions").Return(convictionRepoStub{})
	repos.utxos = utxos
	repos.events = events

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	f = &cosignFixture{
		signer:      signer,
		wallet:      wallet,
		scanner:     scanner,
		utxos:       utxos,
		events:      events,
		vtxos:       vtxos,
		rounds:      rounds,
		offchainTxs: offchainTxs,
		owners:      f.owners,
		signerKey:   signerKey,
		exitDelay:   exitDelay,
		vtxoScript:  vtxoScript,
		tapscripts:  tapscripts,
		pkScript:    pkScript,
		forfeitLeaf: forfeitLeaf, exitLeaf: exitLeaf,
		fundingTx: fundingTx, fundingTxid: fundingTxid, utxo: utxo, amount: amount,
		spendConfirmedAt: spendConfirmedAt,
	}
	f.svc = &service{
		ctx:            ctx,
		repoManager:    repos,
		cache:          newCosignTestLiveStore(),
		signer:         signer,
		wallet:         wallet,
		scanner:        scanner,
		builder:        cosignTestBuilder{},
		feeManager:     registrationTestFees{},
		operatorPubkey: signerKey.PubKey(),
		batchSessions:  newBatchSessionManager(),
		cosignMu:       &sync.Mutex{},
		offchainTxMu:   &sync.Mutex{},
	}
	// The reservation is released by the projection, as NewService wires it.
	repos.RegisterOnchainTxUpdateHandler(f.svc.unlockUtxos)
	events.dispatch = repos.onchainTxHandler

	f.setSettings(t, ports.Settings{
		Settings: domain.Settings{
			VtxoMaxAmount:               -1,
			UtxoMaxAmount:               -1,
			UtxoMinAmount:               1000,
			MaxTxWeight:                 400_000,
			BoardingExitDelay:           exitDelay,
			UnilateralExitDelay:         exitDelay,
			UnrolledVtxoMinExpiryMargin: time.Minute,
		},
		DustAmount:   testDust,
		SignerPubkey: signerKey.PubKey(),
	})
	return f
}

// vtxo gives the fixture's funded output the metadata of a live offchain VTXO.
// Its script and registration proof remain valid after it unrolls.
func (f *cosignFixture) vtxo() domain.Vtxo {
	return domain.Vtxo{
		Outpoint:           f.utxo,
		Amount:             f.amount,
		PubKey:             hex.EncodeToString(f.pkScript[2:]),
		CommitmentTxids:    []string{f.fundingTxid},
		RootCommitmentTxid: f.fundingTxid,
		ExpiresAt:          time.Now().Add(time.Hour).Unix(),
		CreatedAt:          time.Now().Add(-time.Hour).Unix(),
	}
}

// cosignTestLiveStore is the live store the cosign flow and RegisterIntent touch: the
// in-memory utxo reservations, stateful settings, an intent queue that claims the inputs
// pushed to it, and an offchain tx cache spending nothing.
type cosignTestLiveStore struct {
	ports.LiveStore
	utxos    ports.CosignedUtxosStore
	settings *cosignTestSettingsStore
	intents  *cosignTestIntentStore
	// spentOffchain are the outpoints spent by the cached offchain txs.
	spentOffchain []domain.Outpoint
}

func newCosignTestLiveStore() *cosignTestLiveStore {
	return &cosignTestLiveStore{
		utxos:    newTestCosignedUtxosStore(),
		settings: &cosignTestSettingsStore{},
		intents:  &cosignTestIntentStore{claimed: make(map[domain.Outpoint]struct{})},
	}
}

func (s *cosignTestLiveStore) CosignedUtxos() ports.CosignedUtxosStore { return s.utxos }

// testCosignedUtxosStore reserves outpoints in memory the way the redis store does: a batch is
// reserved as a whole, or not at all if any of its outpoints is reserved already.
type testCosignedUtxosStore struct {
	mu        sync.Mutex
	outpoints map[domain.Outpoint]struct{}
}

func newTestCosignedUtxosStore() *testCosignedUtxosStore {
	return &testCosignedUtxosStore{outpoints: make(map[domain.Outpoint]struct{})}
}

func (s *testCosignedUtxosStore) AddUtxos(_ context.Context, outpoints []domain.Outpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, outpoint := range outpoints {
		if _, ok := s.outpoints[outpoint]; ok {
			return ports.ErrUtxosAlreadyExist
		}
	}
	for _, outpoint := range outpoints {
		s.outpoints[outpoint] = struct{}{}
	}
	return nil
}

func (s *testCosignedUtxosStore) RemoveUtxos(_ context.Context, outpoints []domain.Outpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, outpoint := range outpoints {
		delete(s.outpoints, outpoint)
	}
	return nil
}

func (s *testCosignedUtxosStore) IncludesAny(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var included []domain.Outpoint
	for _, outpoint := range outpoints {
		if _, ok := s.outpoints[outpoint]; ok {
			included = append(included, outpoint)
		}
	}
	return included, nil
}

func (s *cosignTestLiveStore) Settings() ports.SettingsStore { return s.settings }

func (s *cosignTestLiveStore) Intents() ports.IntentStore { return s.intents }

func (s *cosignTestLiveStore) OffchainTxs() ports.OffChainTxStore {
	return cosignTestOffchainTxStore{spent: s.spentOffchain}
}

type cosignTestOffchainTxStore struct {
	ports.OffChainTxStore
	spent []domain.Outpoint
}

func (s cosignTestOffchainTxStore) IncludesAny(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	included := make([]domain.Outpoint, 0)
	for _, outpoint := range outpoints {
		if slices.Contains(s.spent, outpoint) {
			included = append(included, outpoint)
		}
	}
	return included, nil
}

type cosignTestSettingsStore struct {
	ports.SettingsStore
	mu       sync.Mutex
	settings *ports.Settings
}

func (s *cosignTestSettingsStore) Get(context.Context) (*ports.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	settings := *s.settings
	return &settings, nil
}

func (s *cosignTestSettingsStore) Upsert(_ context.Context, settings ports.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = &settings
	return nil
}

// cosignTestIntentStore claims the vtxo and boarding inputs of the intents pushed to it,
// so a later cosign request on one of them is refused like the redis store would.
type cosignTestIntentStore struct {
	ports.IntentStore
	mu      sync.Mutex
	claimed map[domain.Outpoint]struct{}
}

func (s *cosignTestIntentStore) Push(
	_ context.Context, intent domain.Intent, boardingInputs []ports.BoardingInput, _ []string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, in := range intent.Inputs {
		s.claimed[in.Outpoint] = struct{}{}
	}
	for _, in := range boardingInputs {
		s.claimed[in.Outpoint] = struct{}{}
	}
	return nil
}

func (s *cosignTestIntentStore) IncludesAny(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var included []domain.Outpoint
	for _, outpoint := range outpoints {
		if _, ok := s.claimed[outpoint]; ok {
			included = append(included, outpoint)
		}
	}
	return included, nil
}

func (f *cosignFixture) settings(ctx context.Context) ports.Settings {
	s, _ := f.svc.cache.Settings().Get(ctx)
	return *s
}

func (f *cosignFixture) setSettings(t *testing.T, settings ports.Settings) {
	t.Helper()
	require.NoError(t, f.svc.cache.Settings().Upsert(t.Context(), settings))
}

// seedUtxo records a cosigned utxo spent by spendTxid straight into the repo, confirmed at
// confirmedAt if not nil.
// seedUtxo records a boarding utxo spent by the given tx: no tx stored along with it, as the
// round projection does for the commitment tx.
func (f *cosignFixture) seedUtxo(
	t *testing.T, spendTxid string, confirmedAt *ports.BlockTimestamp,
) domain.Utxo {
	t.Helper()

	utxo := domain.Utxo{
		Outpoint:  domain.Outpoint{Txid: randomTxid(t), VOut: 0},
		Amount:    f.amount,
		PubKey:    hex.EncodeToString(f.pkScript[2:]),
		Spend:     domain.UtxoSpend{Txid: spendTxid},
		CreatedAt: time.Now().Unix(),
	}
	if confirmedAt != nil {
		utxo.Spend.ConfirmedAtTime = confirmedAt.Time
		utxo.Spend.ConfirmedAtHeight = uint64(confirmedAt.Height)
	}
	require.NoError(t, f.utxos.AddUtxos(t.Context(), []domain.Utxo{utxo}, ""))
	return utxo
}

// seedCosignedUtxo records a utxo spent by a tx cosigned with us, stored along with it, as
// the projection of the onchain tx broadcasted event does.
func (f *cosignFixture) seedCosignedUtxo(
	t *testing.T, spendTxid string, confirmedAt *ports.BlockTimestamp,
) domain.Utxo {
	t.Helper()

	utxo := domain.Utxo{
		Outpoint:  domain.Outpoint{Txid: randomTxid(t), VOut: 0},
		Amount:    f.amount,
		PubKey:    hex.EncodeToString(f.pkScript[2:]),
		Spend:     domain.UtxoSpend{Txid: spendTxid},
		CreatedAt: time.Now().Unix(),
	}
	if confirmedAt != nil {
		utxo.Spend.ConfirmedAtTime = confirmedAt.Time
		utxo.Spend.ConfirmedAtHeight = uint64(confirmedAt.Height)
	}
	// The tx is stored once, with the first utxo it spends.
	tx := ""
	if txs, _ := f.utxos.GetOnchainTxs(t.Context(), []string{spendTxid}); len(txs) == 0 {
		tx = "tx-" + spendTxid
	}
	require.NoError(t, f.utxos.AddUtxos(t.Context(), []domain.Utxo{utxo}, tx))
	return utxo
}

// seedUnrolledVtxo records the spend of an unrolled vtxo by a tx not cosigned with us: a
// pointer to the vtxo, with no pubkey and amount, as the unroll of a spent vtxo and the
// scanner notification of an exit path spend do.
func (f *cosignFixture) seedUnrolledVtxo(t *testing.T, spendTxid string) domain.Utxo {
	t.Helper()

	utxo := domain.Utxo{
		Outpoint:  domain.Outpoint{Txid: randomTxid(t), VOut: 0},
		Spend:     domain.UtxoSpend{Txid: spendTxid},
		CreatedAt: time.Now().Unix(),
	}
	require.NoError(t, f.utxos.AddUtxos(t.Context(), []domain.Utxo{utxo}, ""))
	return utxo
}

func (f *cosignFixture) requireReleasedAndUnrecorded(t *testing.T) {
	t.Helper()
	reserved, err := f.svc.cache.CosignedUtxos().IncludesAny(
		t.Context(), []domain.Outpoint{f.utxo},
	)
	require.NoError(t, err)
	require.Empty(t, reserved)
	utxos, err := f.utxos.GetUtxos(t.Context(), []domain.Outpoint{f.utxo})
	require.NoError(t, err)
	require.Empty(t, utxos)
}

// cosignTestTx is a tx to be cosigned along with its txid.
type cosignTestTx struct {
	b64  string
	txid string
}

type cosignTxOption func(t *testing.T, f *cosignFixture, ptx *psbt.Packet)

// cosignTx builds a tx spending the fixture utxo through the forfeit leaf, signed by the owner
// only, with the taptree revealed: what a client sends to have it cosigned. Options tamper
// with it.
func (f *cosignFixture) cosignTx(t *testing.T, opts ...cosignTxOption) cosignTestTx {
	t.Helper()

	hash, err := chainhash.NewHashFromStr(f.utxo.Txid)
	require.NoError(t, err)
	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *hash, Index: f.utxo.VOut}},
		[]*wire.TxOut{{Value: int64(f.amount) - 1000, PkScript: testP2TRScript(t)}},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: int64(f.amount), PkScript: f.pkScript}
	ptx.Inputs[0].SighashType = txscript.SigHashDefault
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.forfeitLeaf}
	require.NoError(t, txutils.SetArkPsbtField(ptx, 0, txutils.VtxoTaprootTreeField, f.tapscripts))
	ptx.Inputs[0].TaprootScriptSpendSig = f.ownerSigs(t, ptx, 0, f.forfeitLeaf)

	for _, opt := range opts {
		opt(t, f, ptx)
	}

	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return cosignTestTx{b64: b64, txid: ptx.UnsignedTx.TxID()}
}

// ownerSigs signs input inIndex of ptx for the given leaf with every owner key. They are
// what the server expects from the other cosigners, their validity is not checked by the
// endpoint but it is by the intent proof verification.
func (f *cosignFixture) ownerSigs(
	t *testing.T, ptx *psbt.Packet, inIndex int, leaf *psbt.TaprootTapLeafScript,
) []*psbt.TaprootScriptSpendSig {
	t.Helper()

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for i, in := range ptx.UnsignedTx.TxIn {
		prevouts[in.PreviousOutPoint] = ptx.Inputs[i].WitnessUtxo
	}
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, txscript.NewMultiPrevOutFetcher(prevouts))
	tapLeaf := txscript.NewBaseTapLeaf(leaf.Script)
	leafHash := tapLeaf.TapHash()

	sigs := make([]*psbt.TaprootScriptSpendSig, 0, len(f.owners))
	for _, owner := range f.owners {
		sig, err := txscript.RawTxInTapscriptSignature(
			ptx.UnsignedTx, sigHashes, inIndex, ptx.Inputs[inIndex].WitnessUtxo.Value,
			ptx.Inputs[inIndex].WitnessUtxo.PkScript, tapLeaf, txscript.SigHashDefault, owner,
		)
		require.NoError(t, err)
		sigs = append(sigs, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: schnorr.SerializePubKey(owner.PubKey()),
			LeafHash:    leafHash[:],
			Signature:   sig[:64],
			SigHash:     txscript.SigHashDefault,
		})
	}
	return sigs
}

func withoutPrevout() cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].WitnessUtxo = nil
	}
}

func withoutSignatures() cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].TaprootScriptSpendSig = nil
	}
}

// withSignaturesDropped removes the last n owner signatures.
func withSignaturesDropped(n int) cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		sigs := ptx.Inputs[0].TaprootScriptSpendSig
		ptx.Inputs[0].TaprootScriptSpendSig = sigs[:len(sigs)-n]
	}
}

// withExtraSignature adds a signature by a third party next to the owners ones.
func withExtraSignature(t *testing.T) cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		extra := *ptx.Inputs[0].TaprootScriptSpendSig[0]
		extra.XOnlyPubKey = schnorr.SerializePubKey(testPubkey(t))
		ptx.Inputs[0].TaprootScriptSpendSig = append(ptx.Inputs[0].TaprootScriptSpendSig, &extra)
	}
}

// withForgedSignature replaces the first owner signature with random bytes.
func withForgedSignature() cosignTxOption {
	return func(t *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		forged := make([]byte, 64)
		_, err := rand.Read(forged)
		require.NoError(t, err)
		ptx.Inputs[0].TaprootScriptSpendSig[0].Signature = forged
	}
}

// withStaleSignature changes the tx after it was signed, so the signatures don't commit to
// it anymore.
func withStaleSignature() cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.UnsignedTx.TxOut[0].Value--
	}
}

// withWrongControlBlock corrupts the merkle path of the spending leaf, so it no longer
// commits to the prevout script.
func withWrongControlBlock() cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		leaf := *ptx.Inputs[0].TaprootLeafScript[0]
		leaf.ControlBlock = append([]byte(nil), leaf.ControlBlock...)
		leaf.ControlBlock[len(leaf.ControlBlock)-1] ^= 0xff
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&leaf}
	}
}

func withSignatureLeafHash(leafHash []byte) cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].TaprootScriptSpendSig[0].LeafHash = leafHash
	}
}

func signerKeyOf(f *cosignFixture) *btcec.PublicKey { return f.signerKey.PubKey() }

func withSignatureBy(pubkey func(*cosignFixture) *btcec.PublicKey) cosignTxOption {
	return func(_ *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey = schnorr.SerializePubKey(pubkey(f))
	}
}

func withSighash(sighash txscript.SigHashType) cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].SighashType = sighash
		ptx.Inputs[0].TaprootScriptSpendSig[0].SigHash = sighash
	}
}

func withSignatureSighash(sighash txscript.SigHashType) cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].TaprootScriptSpendSig[0].SigHash = sighash
	}
}

func withDuplicatedLeaf() cosignTxOption {
	return func(_ *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].TaprootLeafScript = append(ptx.Inputs[0].TaprootLeafScript, f.exitLeaf)
	}
}

func withExitLeaf() cosignTxOption {
	return func(t *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.exitLeaf}
		// The exit leaf is the first owner's only.
		ptx.Inputs[0].TaprootScriptSpendSig = f.ownerSigs(t, ptx, 0, f.exitLeaf)[:1]
	}
}

func withPrevoutScript(pkScript []byte) cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.Inputs[0].WitnessUtxo.PkScript = pkScript
	}
}

// resign refreshes the owners signatures of the fixture input after the tx changed shape,
// like a client signing last would.
func (f *cosignFixture) resign(t *testing.T, ptx *psbt.Packet) {
	t.Helper()
	if len(ptx.Inputs) == 0 || len(ptx.Inputs[0].TaprootLeafScript) == 0 ||
		!bytes.Equal(ptx.Inputs[0].TaprootLeafScript[0].Script, f.forfeitLeaf.Script) {
		return
	}
	ptx.Inputs[0].TaprootScriptSpendSig = f.ownerSigs(t, ptx, 0, f.forfeitLeaf)
}

func withOutputAmount(amount uint64) cosignTxOption {
	return func(t *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		ptx.UnsignedTx.TxOut[0].Value = int64(amount)
		f.resign(t, ptx)
	}
}

// withOutputs pads the tx with n zero-valued outputs, to make it heavy without touching the
// amounts.
func withOutputs(n int) cosignTxOption {
	return func(t *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		pkScript := testP2TRScript(t)
		for range n {
			ptx.UnsignedTx.AddTxOut(&wire.TxOut{Value: 0, PkScript: pkScript})
			ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
		}
		f.resign(t, ptx)
	}
}

// withoutCosignableInput drops the fixture utxo from the tx, and the output funded by it.
func withoutCosignableInput() cosignTxOption {
	return func(_ *testing.T, _ *cosignFixture, ptx *psbt.Packet) {
		ptx.UnsignedTx.TxIn = ptx.UnsignedTx.TxIn[1:]
		ptx.Inputs = ptx.Inputs[1:]
		ptx.UnsignedTx.TxOut[0].Value = 1000
	}
}

func withForeignInputs(n int) cosignTxOption {
	return func(t *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		for range n {
			withForeignInput(t)(t, f, ptx)
		}
	}
}

// withForeignInput appends a key-path taproot input of somebody else, already signed.
func withForeignInput(t *testing.T) cosignTxOption {
	return func(t *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		funding := wire.NewMsgTx(2)
		funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
		funding.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: testP2TRScript(t)})
		var buf bytes.Buffer
		require.NoError(t, funding.Serialize(&buf))
		f.wallet.On("GetTransaction", mock.Anything, funding.TxID()).
			Return(hex.EncodeToString(buf.Bytes()), nil).Maybe()
		ptx.UnsignedTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: funding.TxHash(), Index: 0}, nil, nil))
		ptx.Inputs = append(ptx.Inputs, psbt.PInput{
			WitnessUtxo:        funding.TxOut[0],
			TaprootKeySpendSig: bytes.Repeat([]byte{1}, 64),
		})
		f.resign(t, ptx)
	}
}

// withForeignScriptPathInput appends a script-path input of somebody else, spending a leaf we
// know nothing about, with a signature we can't check.
func withForeignScriptPathInput(t *testing.T) cosignTxOption {
	return func(t *testing.T, f *cosignFixture, ptx *psbt.Packet) {
		withForeignInput(t)(t, f, ptx)
		leafScript := []byte{txscript.OP_TRUE}
		leafHash := txscript.NewBaseTapLeaf(leafScript).TapHash()
		input := &ptx.Inputs[len(ptx.Inputs)-1]
		input.TaprootKeySpendSig = nil
		input.TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: bytes.Repeat([]byte{2}, 33), Script: leafScript,
			LeafVersion: txscript.BaseLeafVersion,
		}}
		input.TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
			XOnlyPubKey: schnorr.SerializePubKey(testPubkey(t)),
			LeafHash:    leafHash[:],
			Signature:   bytes.Repeat([]byte{3}, 64),
		}}
	}
}

// registration is an intent registering the fixture utxo as boarding input, accepted by
// RegisterIntent all the way to the push.
type cosignTestRegistration struct {
	proof   *intent.Proof
	message intent.RegisterMessage
}

func (f *cosignFixture) registration(t *testing.T) cosignTestRegistration {
	t.Helper()

	message := intent.RegisterMessage{
		BaseMessage:         intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		CosignersPublicKeys: []string{hex.EncodeToString(testPubkey(t).SerializeCompressed())},
	}
	encoded, err := message.Encode()
	require.NoError(t, err)

	hash, err := chainhash.NewHashFromStr(f.utxo.Txid)
	require.NoError(t, err)
	proof, err := intent.New(encoded, []intent.Input{{
		OutPoint:    &wire.OutPoint{Hash: *hash, Index: f.utxo.VOut},
		Sequence:    wire.MaxTxInSequenceNum,
		WitnessUtxo: &wire.TxOut{Value: int64(f.amount), PkScript: f.pkScript},
	}}, []*wire.TxOut{{Value: int64(f.amount), PkScript: testP2TRScript(t)}})
	require.NoError(t, err)

	// Input 0 is the BIP322 message input locked by the same script, both are spent through
	// the forfeit leaf and signed by the owner, the server signature is skipped at verification.
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.forfeitLeaf}
		proof.Inputs[i].TaprootScriptSpendSig = f.ownerSigs(t, &proof.Packet, i, f.forfeitLeaf)
	}
	require.NoError(t, txutils.SetArkPsbtField(
		&proof.Packet, 1, txutils.VtxoTaprootTreeField, f.tapscripts,
	))

	return cosignTestRegistration{proof: proof, message: message}
}

// cosignTestSigner records SignTransaction calls and can hold them until released.
// Like the real signer client, it fails a call whose ctx is canceled by the time it returns.
type cosignTestSigner struct {
	ports.SignerService
	mu          sync.Mutex
	calls       int
	lastIndexes []int
	err         error
	hold        chan struct{}
	inflight    int
}

func (s *cosignTestSigner) SignTransaction(
	ctx context.Context, partialTx string, inputIndexes []int,
) (string, error) {
	s.mu.Lock()
	s.calls++
	s.lastIndexes = inputIndexes
	s.inflight++
	hold, err := s.hold, s.err
	s.mu.Unlock()
	if hold != nil {
		<-hold
	}
	s.mu.Lock()
	s.inflight--
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return partialTx, nil
}

func (s *cosignTestSigner) waiting() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight
}

// cosignTestWallet serves the fixture funding tx and answers spent status, broadcast and
// confirmation of the broadcast tx.
type cosignTestWallet struct {
	*mockedWallet
	mu           sync.Mutex
	spent        map[domain.Outpoint]bool
	broadcastErr error
	broadcast    map[string]struct{}
	// confirmedAt is the confirmation of any tx asked about, unless confirmErr has an error
	// for it. checks counts the confirmation lookups per txid.
	confirmedAt *ports.BlockTimestamp
	confirmErr  map[string]error
	checks      map[string]int
}

func (w *cosignTestWallet) confirmationChecks(txid string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.checks[txid]
}

func newCosignTestWallet(
	fundingTx *wire.MsgTx, confirmedAt *ports.BlockTimestamp,
) *cosignTestWallet {
	var buf bytes.Buffer
	_ = fundingTx.Serialize(&buf)
	w := &cosignTestWallet{
		mockedWallet: &mockedWallet{},
		spent:        make(map[domain.Outpoint]bool),
		broadcast:    make(map[string]struct{}),
		confirmedAt:  confirmedAt,
		confirmErr:   make(map[string]error),
		checks:       make(map[string]int),
	}
	w.On("GetTransaction", mock.Anything, fundingTx.TxID()).
		Return(hex.EncodeToString(buf.Bytes()), nil).Maybe()
	w.On("BroadcastTransaction", mock.Anything, mock.Anything).Return("", nil).Maybe()
	return w
}

func (w *cosignTestWallet) GetOutpointStatus(
	_ context.Context, outpoint domain.Outpoint,
) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.spent[outpoint], nil
}

func (w *cosignTestWallet) BroadcastTransaction(
	ctx context.Context, txs ...string,
) (string, error) {
	// Recorded through the mock for the assertions, answered here.
	w.mockedWallet.Called(ctx, txs)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broadcastErr != nil {
		return "", w.broadcastErr
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txs[0]))); err != nil {
		return "", err
	}
	w.broadcast[tx.TxID()] = struct{}{}
	return tx.TxID(), nil
}

func (w *cosignTestWallet) GetNetwork(context.Context) (*arklib.Network, error) {
	return &arklib.BitcoinRegTest, nil
}

// IsTransactionConfirmed serves the boarding validation at registration and the wait for
// the broadcast tx: everything is confirmed right away with the fixture confirmation.
func (w *cosignTestWallet) IsTransactionConfirmed(
	_ context.Context, txid string,
) (bool, *ports.BlockTimestamp, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checks[txid]++
	if err := w.confirmErr[txid]; err != nil {
		return false, nil, err
	}
	return true, w.confirmedAt, nil
}

// cosignTestScanner answers confirmations from a map and accepts any watch request.
type cosignTestScanner struct {
	ports.BlockchainScanner
	confirmed map[string]*ports.BlockTimestamp
}

func (s *cosignTestScanner) IsTransactionConfirmed(
	_ context.Context, txid string,
) (bool, *ports.BlockTimestamp, error) {
	conf, ok := s.confirmed[txid]
	return ok, conf, nil
}

func (s *cosignTestScanner) WatchScripts(context.Context, []string) error   { return nil }
func (s *cosignTestScanner) UnwatchScripts(context.Context, []string) error { return nil }
func (s *cosignTestScanner) RescanUtxos(context.Context, []wire.OutPoint) error {
	return nil
}

// cosignTestBuilder returns rawTx when set, otherwise extracts the unsigned tx as is.
type cosignTestBuilder struct {
	ports.TxBuilder
	rawTx string
}

func (b cosignTestBuilder) FinalizeAndExtract(tx string) (string, error) {
	if b.rawTx != "" {
		return b.rawTx, nil
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := ptx.UnsignedTx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

type cosignTestOffchainTxRepo struct {
	domain.OffchainTxRepository
	checkpoints map[string]struct{}
}

func (r *cosignTestOffchainTxRepo) GetCheckpointTxs(
	_ context.Context, txids []string,
) ([]string, error) {
	found := make([]string, 0)
	for _, txid := range txids {
		if _, ok := r.checkpoints[txid]; ok {
			found = append(found, txid)
		}
	}
	return found, nil
}

// fakeEventRepo records the events saved per topic and id, and projects the onchain tx ones
// into the utxo repo the way the real projection is expected to: the broadcast records the
// signed inputs as utxos spent by the tx, taking their amount and pubkey from the tx prevouts,
// the confirmation confirms them.
type fakeEventRepo struct {
	domain.EventRepository
	t     *testing.T
	mu    sync.Mutex
	saved map[string][]domain.Event // topic:id -> events
	utxos *fakeUtxoRepo
	// dispatch is the registered onchain tx update handler, called once the projection
	// succeeded like the repo manager does. projectionErr makes the projection fail instead,
	// so nothing is recorded nor dispatched.
	dispatch      func(domain.OnchainTx)
	projectionErr error
}

func newFakeEventRepo(t *testing.T, utxos *fakeUtxoRepo) *fakeEventRepo {
	return &fakeEventRepo{t: t, saved: make(map[string][]domain.Event), utxos: utxos}
}

func (r *fakeEventRepo) Save(
	ctx context.Context, topic, id string, events []domain.Event,
) error {
	r.mu.Lock()
	r.saved[topic+":"+id] = append(r.saved[topic+":"+id], events...)
	history := append([]domain.Event(nil), r.saved[topic+":"+id]...)
	r.mu.Unlock()

	if topic != domain.OnchainTxTopic {
		return nil
	}
	// The event is saved regardless, only the projection fails.
	if r.projectionErr != nil {
		return nil
	}
	for _, event := range events {
		switch e := event.(type) {
		case domain.OnchainTxBroadcasted:
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(e.Tx), true)
			if err != nil {
				return err
			}
			utxos := make([]domain.Utxo, 0, len(e.SignedInputs))
			for i, in := range ptx.UnsignedTx.TxIn {
				outpoint := domain.Outpoint{
					Txid: in.PreviousOutPoint.Hash.String(), VOut: in.PreviousOutPoint.Index,
				}
				if _, ok := e.SignedInputs[outpoint.String()]; !ok {
					continue
				}
				prevout := ptx.Inputs[i].WitnessUtxo
				utxos = append(utxos, domain.Utxo{
					Outpoint:  outpoint,
					Amount:    uint64(prevout.Value),
					PubKey:    hex.EncodeToString(prevout.PkScript[2:]),
					Spend:     domain.UtxoSpend{Txid: e.Id},
					CreatedAt: e.Timestamp,
				})
			}
			if err := r.utxos.AddUtxos(ctx, utxos, e.Tx); err != nil {
				return err
			}
		case domain.OnchainTxConfirmed:
			utxos, _, _, err := r.utxos.GetUnconfirmedUtxos(ctx)
			if err != nil {
				return err
			}
			confirmed := make([]domain.Utxo, 0)
			for _, utxo := range utxos {
				if utxo.Spend.Txid != e.Id {
					continue
				}
				utxo.Spend.ConfirmedAtTime = e.ConfirmedAtTime
				utxo.Spend.ConfirmedAtHeight = e.ConfirmedAtHeight
				confirmed = append(confirmed, utxo)
			}
			if err := r.utxos.UpdateUtxos(ctx, confirmed); err != nil {
				return err
			}
		}
	}

	// Projected: notify the app the way the repo manager does, with the whole tx.
	if r.dispatch != nil {
		r.dispatch(*domain.NewOnchainTxFromEvents(history))
	}
	return nil
}

// events returns the events saved for the given onchain tx.
func (r *fakeEventRepo) events(txid string) []domain.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.Event(nil), r.saved[domain.OnchainTxTopic+":"+txid]...)
}

// pausingCosignedUtxoRepo pauses only its first read, after taking the snapshot.
// Later reads remain free to proceed, so the barrier cannot hide a missing app lock.
type pausingCosignedUtxoRepo struct {
	domain.UtxoRepository
	once    sync.Once
	read    chan<- struct{}
	proceed <-chan struct{}
}

func (r *pausingCosignedUtxoRepo) GetUtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Utxo, error) {
	utxos, err := r.UtxoRepository.GetUtxos(ctx, outpoints)
	pause := false
	r.once.Do(func() { pause = true })
	if pause {
		close(r.read)
		select {
		case <-r.proceed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return utxos, err
}

// fakeUtxoRepo is an in-memory domain.UtxoRepository with the same constraints as the sql
// ones: an outpoint is inserted once and confirmed once.
type fakeUtxoRepo struct {
	mu    sync.Mutex
	utxos map[domain.Outpoint]domain.Utxo
	// txs are the spending txs recorded along with the utxos, one per txid.
	txs map[string]string
	// unconfirmedErr fails GetUnconfirmedUtxos if set.
	unconfirmedErr error
}

func newFakeUtxoRepo() *fakeUtxoRepo {
	return &fakeUtxoRepo{
		utxos: make(map[domain.Outpoint]domain.Utxo),
		txs:   make(map[string]string),
	}
}

func (r *fakeUtxoRepo) AddUtxos(_ context.Context, utxos []domain.Utxo, tx string) error {
	if len(utxos) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, utxo := range utxos {
		if _, ok := r.utxos[utxo.Outpoint]; ok {
			return fmt.Errorf("utxo %s already exists", utxo.Outpoint)
		}
	}
	if tx != "" {
		txid := utxos[0].Spend.Txid
		if _, ok := r.txs[txid]; ok {
			return fmt.Errorf("onchain tx %s already exists", txid)
		}
		r.txs[txid] = tx
	}
	for _, utxo := range utxos {
		r.utxos[utxo.Outpoint] = utxo
	}
	return nil
}

func (r *fakeUtxoRepo) GetOnchainTxs(_ context.Context, txids []string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	txs := make([]string, 0, len(txids))
	for _, txid := range txids {
		if tx, ok := r.txs[txid]; ok {
			txs = append(txs, tx)
		}
	}
	return txs, nil
}

func (r *fakeUtxoRepo) UpdateUtxos(_ context.Context, utxos []domain.Utxo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, utxo := range utxos {
		existing, ok := r.utxos[utxo.Outpoint]
		if !ok || existing.Spend.IsConfirmed() {
			return fmt.Errorf("utxo %s not found or already confirmed", utxo.Outpoint)
		}
		existing.Spend = utxo.Spend
		r.utxos[utxo.Outpoint] = existing
	}
	return nil
}

func (r *fakeUtxoRepo) GetUtxos(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Utxo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	utxos := make([]domain.Utxo, 0)
	for _, outpoint := range outpoints {
		if utxo, ok := r.utxos[outpoint]; ok {
			utxos = append(utxos, utxo)
		}
	}
	return utxos, nil
}

// GetUtxosWithPubKeys filters and pages in memory the way the sql stores do: most recent
// first, a non positive limit reads everything from the offset on, a page past the end is
// empty but still reports the total.
func (r *fakeUtxoRepo) GetUtxosWithPubKeys(
	_ context.Context, pubkeys []string, page domain.Page,
) ([]domain.Utxo, int32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	wanted := make(map[string]struct{}, len(pubkeys))
	for _, pubkey := range pubkeys {
		wanted[pubkey] = struct{}{}
	}
	matched := make([]domain.Utxo, 0)
	for _, utxo := range r.utxos {
		if _, ok := wanted[utxo.PubKey]; ok {
			matched = append(matched, utxo)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].CreatedAt != matched[j].CreatedAt {
			return matched[i].CreatedAt > matched[j].CreatedAt
		}
		if matched[i].Txid != matched[j].Txid {
			return matched[i].Txid < matched[j].Txid
		}
		return matched[i].VOut < matched[j].VOut
	})

	total := int32(len(matched))
	offset := max(page.Offset, 0)
	if offset >= total {
		return nil, total, nil
	}
	end := total
	if page.Limit > 0 {
		end = min(offset+page.Limit, total)
	}
	return matched[offset:end], total, nil
}

func (r *fakeUtxoRepo) GetUnconfirmedUtxosWithSpendingTxid(
	_ context.Context, txid string,
) ([]domain.Utxo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unconfirmedErr != nil {
		return nil, r.unconfirmedErr
	}
	utxos := make([]domain.Utxo, 0)
	for _, utxo := range r.utxos {
		if utxo.Spend.Txid == txid && !utxo.Spend.IsConfirmed() {
			utxos = append(utxos, utxo)
		}
	}
	return utxos, nil
}

// GetUnconfirmedUtxos splits the unconfirmed utxos the way the sql store does: cosigned if
// their spending tx was recorded along with them, unrolled vtxos if they carry no pubkey, as
// pointers to a vtxo do, boarding otherwise.
func (r *fakeUtxoRepo) GetUnconfirmedUtxos(
	context.Context,
) (cosignedUtxos, boardingUtxos, unrolledVtxos []domain.Utxo, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unconfirmedErr != nil {
		return nil, nil, nil, r.unconfirmedErr
	}
	for _, utxo := range r.utxos {
		if utxo.Spend.IsConfirmed() {
			continue
		}
		switch {
		case r.txs[utxo.Spend.Txid] != "":
			cosignedUtxos = append(cosignedUtxos, utxo)
		case utxo.PubKey == "":
			unrolledVtxos = append(unrolledVtxos, utxo)
		default:
			boardingUtxos = append(boardingUtxos, utxo)
		}
	}
	return cosignedUtxos, boardingUtxos, unrolledVtxos, nil
}

func randomTxid(t *testing.T) string {
	t.Helper()
	var hash chainhash.Hash
	_, err := rand.Read(hash[:])
	require.NoError(t, err)
	return hash.String()
}

type cosignCancellationTestStore struct {
	ports.LiveStore
	utxos   ports.CosignedUtxosStore
	intents ports.IntentStore
}

func (s cosignCancellationTestStore) CosignedUtxos() ports.CosignedUtxosStore {
	return s.utxos
}

func (s cosignCancellationTestStore) Intents() ports.IntentStore { return s.intents }

type contextAwareCosignTestUtxos struct{ ports.CosignedUtxosStore }

func (s contextAwareCosignTestUtxos) RemoveUtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) error {
	// The in-memory store ignores cancellation; model Redis refusing cancelled cleanup.
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.CosignedUtxosStore.RemoveUtxos(ctx, outpoints)
}
