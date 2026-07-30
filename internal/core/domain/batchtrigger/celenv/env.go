// Package celenv defines the CEL environment used by batch_trigger programs.
//
// The environment exposes a fixed set of variables describing the state of the
// pending batch (queued intents, fee market, time since last batch, etc.) and a
// `now()` helper that returns the current unix timestamp in seconds.
package celenv

import (
	"github.com/google/cel-go/cel"
)

// BatchTriggerEnv is the CEL environment used to compile batch_trigger programs.
var BatchTriggerEnv *cel.Env

func init() {
	var err error
	BatchTriggerEnv, err = cel.NewEnv(
		// variables
		intentsCount,
		currentFeerate,
		timeSinceLastBatch,
		boardingInputsCount,
		totalBoardingAmount,
		totalIntentFees,
		// functions
		nowFunction,
	)
	if err != nil {
		panic(err)
	}
}
