package batchtrigger

import (
	"github.com/arkade-os/arkd/pkg/ark-lib/batchtrigger/celenv"
)

// Context is the snapshot of state passed to a batch_trigger program when it is
// evaluated. Every field maps 1:1 to a CEL variable declared in
// pkg/ark-lib/batchtrigger/celenv.
type Context struct {
	// IntentsCount is the number of pending intents queued.
	IntentsCount int64
	// CurrentFeerate is the current mempool fee rate in sat/kvbyte
	// (matches ports.WalletService.FeeRate).
	CurrentFeerate uint64
	// TimeSinceLastBatch is the number of seconds elapsed since the last batch
	// was finalized. It is 0 when no batch has been finalized yet since the
	// server started.
	TimeSinceLastBatch int64
	// BoardingInputsCount is the total number of pending boarding UTXOs across
	// all queued intents.
	BoardingInputsCount int64
	// TotalBoardingAmount is the total amount in satoshis across all pending
	// boarding UTXOs.
	TotalBoardingAmount uint64
	// TotalIntentFees is the total implicit fees in satoshis across all pending
	// intents (sum of (input amounts) - (output amounts) per intent).
	TotalIntentFees uint64
}

func (c Context) toArgs() map[string]any {
	return map[string]any{
		celenv.IntentsCountVariableName:        float64(c.IntentsCount),
		celenv.CurrentFeerateVariableName:      float64(c.CurrentFeerate),
		celenv.TimeSinceLastBatchVariableName:  float64(c.TimeSinceLastBatch),
		celenv.BoardingInputsCountVariableName: float64(c.BoardingInputsCount),
		celenv.TotalBoardingAmountVariableName: float64(c.TotalBoardingAmount),
		celenv.TotalIntentFeesVariableName:     float64(c.TotalIntentFees),
	}
}
