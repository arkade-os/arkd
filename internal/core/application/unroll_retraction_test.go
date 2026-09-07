package application

import (
	"context"
	"errors"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRetractStaleUnrolls(t *testing.T) {
	ctx := context.Background()
	out := outpoint(unrolledVtxoTxid, 0)
	candidates := []domain.Vtxo{{Outpoint: out, Unrolled: true}}

	t.Run("retracts once the tx has been unknown for enough passes", func(t *testing.T) {
		svc, vtxos := unrollService(t, &mockedScanner{
			unspent: map[domain.Outpoint]struct{}{},
			known:   map[string]bool{},
		})
		vtxos.On("UnmarkVtxosUnrolled", mock.Anything, mock.Anything).Return(nil)

		for range unrollRetractionObservations - 1 {
			svc.retractStaleUnrolls(ctx, candidates)
			vtxos.AssertNotCalled(t, "UnmarkVtxosUnrolled", mock.Anything, mock.Anything)
		}
		svc.retractStaleUnrolls(ctx, candidates)

		vtxos.AssertCalled(t, "UnmarkVtxosUnrolled", mock.Anything, []domain.Outpoint{out})
	})

	// The stronger of the two signals. An outpoint the wallet still lists as
	// unspent exists on chain, so no number of passes may retract past it.
	t.Run("never retracts while the outpoint is still unspent", func(t *testing.T) {
		svc, vtxos := unrollService(t, &mockedScanner{
			unspent: map[domain.Outpoint]struct{}{out: {}},
			known:   map[string]bool{},
		})

		for range unrollRetractionObservations * 2 {
			svc.retractStaleUnrolls(ctx, candidates)
		}

		vtxos.AssertNotCalled(t, "UnmarkVtxosUnrolled", mock.Anything, mock.Anything)
	})

	// A wallet predating the not-found field reports every tx as known, so it
	// degrades to never retracting rather than to retracting blindly.
	t.Run("a tx the backend still knows resets the count", func(t *testing.T) {
		scanner := &mockedScanner{
			unspent: map[domain.Outpoint]struct{}{},
			known:   map[string]bool{},
		}
		svc, vtxos := unrollService(t, scanner)

		for range unrollRetractionObservations - 1 {
			svc.retractStaleUnrolls(ctx, candidates)
		}
		scanner.known[unrolledVtxoTxid] = true
		svc.retractStaleUnrolls(ctx, candidates)
		scanner.known[unrolledVtxoTxid] = false
		svc.retractStaleUnrolls(ctx, candidates)

		vtxos.AssertNotCalled(t, "UnmarkVtxosUnrolled", mock.Anything, mock.Anything)
	})

	// A failing lookup is not evidence, so it must not accumulate towards a
	// retraction the way a real "gone" answer does.
	t.Run("a lookup failure does not advance the count", func(t *testing.T) {
		svc, vtxos := unrollService(t, &mockedScanner{
			unspent:  map[domain.Outpoint]struct{}{},
			knownErr: errors.New("wallet down"),
		})

		for range unrollRetractionObservations * 2 {
			svc.retractStaleUnrolls(ctx, candidates)
		}

		vtxos.AssertNotCalled(t, "UnmarkVtxosUnrolled", mock.Anything, mock.Anything)
	})

	t.Run("an unspent-set failure skips the pass without asking further", func(t *testing.T) {
		scanner := &mockedScanner{unspentErr: errors.New("wallet down")}
		svc, vtxos := unrollService(t, scanner)

		svc.retractStaleUnrolls(ctx, candidates)

		require.Empty(t, scanner.KnownCalls(), "no tx lookup without the stronger signal")
		vtxos.AssertNotCalled(t, "UnmarkVtxosUnrolled", mock.Anything, mock.Anything)
	})

	// A vtxo that leaves the candidate set has been resolved some other way, so
	// its count must not survive to be counted against a later unroll.
	t.Run("counts do not survive leaving the candidate set", func(t *testing.T) {
		svc, vtxos := unrollService(t, &mockedScanner{
			unspent: map[domain.Outpoint]struct{}{},
			known:   map[string]bool{},
		})
		vtxos.On("UnmarkVtxosUnrolled", mock.Anything, mock.Anything).Return(nil)

		for range unrollRetractionObservations - 1 {
			svc.retractStaleUnrolls(ctx, candidates)
		}
		svc.retractStaleUnrolls(ctx, nil)
		svc.retractStaleUnrolls(ctx, candidates)

		vtxos.AssertNotCalled(t, "UnmarkVtxosUnrolled", mock.Anything, mock.Anything)
	})

	t.Run("no candidates is a no-op", func(t *testing.T) {
		scanner := &mockedScanner{}
		svc, vtxos := unrollService(t, scanner)

		svc.retractStaleUnrolls(ctx, nil)

		require.Empty(t, scanner.KnownCalls())
		vtxos.AssertNotCalled(t, "UnmarkVtxosUnrolled", mock.Anything, mock.Anything)
	})
}

// --- fixtures ---

// unrollService builds a service wired to the given scanner, with a vtxo repo
// that records retraction calls.
func unrollService(t *testing.T, scanner *mockedScanner) (*service, *mockedVtxoRepo) {
	t.Helper()
	vtxos := &mockedVtxoRepo{}
	rm := &mockedRepoManager{}
	rm.On("Vtxos").Return(vtxos)
	return &service{repoManager: rm, scanner: scanner}, vtxos
}
