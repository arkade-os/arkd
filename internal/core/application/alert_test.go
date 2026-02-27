package application

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestCalculateCollectedFees(t *testing.T) {
	makeRound := func(intents map[string]domain.Intent) *domain.Round {
		return &domain.Round{Intents: intents}
	}

	makeIntent := func(inputs []uint64, outputs []uint64) domain.Intent {
		vtxos := make([]domain.Vtxo, len(inputs))
		for i, a := range inputs {
			vtxos[i] = domain.Vtxo{Amount: a}
		}
		receivers := make([]domain.Receiver, len(outputs))
		for i, a := range outputs {
			receivers[i] = domain.Receiver{Amount: a}
		}
		return domain.Intent{Inputs: vtxos, Receivers: receivers}
	}

	t.Run("no_intents_no_boarding", func(t *testing.T) {
		round := makeRound(nil)
		require.Equal(t, uint64(0), calculateCollectedFees(round, 0))
	})

	t.Run("no_intents_with_boarding", func(t *testing.T) {
		// boarding input with no intents means all boarding goes to fees
		round := makeRound(nil)
		require.Equal(t, uint64(5000), calculateCollectedFees(round, 5000))
	})

	t.Run("single_intent_no_fee", func(t *testing.T) {
		round := makeRound(map[string]domain.Intent{
			"a": makeIntent([]uint64{10000}, []uint64{10000}),
		})
		require.Equal(t, uint64(0), calculateCollectedFees(round, 0))
	})

	t.Run("single_intent_with_fee", func(t *testing.T) {
		// input 10000, output 9800 → fee = 200
		round := makeRound(map[string]domain.Intent{
			"a": makeIntent([]uint64{10000}, []uint64{9800}),
		})
		require.Equal(t, uint64(200), calculateCollectedFees(round, 0))
	})

	t.Run("boarding_counted_once_not_per_intent", func(t *testing.T) {
		// Two intents, each with input 10000 and output 9900.
		// Boarding input = 5000.
		// Correct: totalIn = 5000 + 10000 + 10000 = 25000
		//          totalOut = 9900 + 9900 = 19800
		//          fee = 5200
		// Bug (boarding * N): totalIn would be 5000*2 + 20000 = 30000 → fee = 10200
		round := makeRound(map[string]domain.Intent{
			"a": makeIntent([]uint64{10000}, []uint64{9900}),
			"b": makeIntent([]uint64{10000}, []uint64{9900}),
		})
		require.Equal(t, uint64(5200), calculateCollectedFees(round, 5000))
	})

	t.Run("multiple_inputs_and_outputs", func(t *testing.T) {
		// Intent with two inputs and two outputs.
		// inputs: 3000 + 7000 = 10000, outputs: 4000 + 5000 = 9000
		// boarding: 1000
		// fee = (1000 + 10000) - 9000 = 2000
		round := makeRound(map[string]domain.Intent{
			"a": makeIntent([]uint64{3000, 7000}, []uint64{4000, 5000}),
		})
		require.Equal(t, uint64(2000), calculateCollectedFees(round, 1000))
	})

	t.Run("output_exceeds_input_returns_zero", func(t *testing.T) {
		// This shouldn't happen in practice, but the function guards against underflow.
		round := makeRound(map[string]domain.Intent{
			"a": makeIntent([]uint64{1000}, []uint64{2000}),
		})
		require.Equal(t, uint64(0), calculateCollectedFees(round, 0))
	})
}
