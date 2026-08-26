package celenv

import (
	"github.com/google/cel-go/cel"
)

const (
	IntentsCountVariableName        = "intents_count"
	CurrentFeerateVariableName      = "current_feerate"
	TimeSinceLastBatchVariableName  = "time_since_last_batch"
	BoardingInputsCountVariableName = "boarding_inputs_count"
	TotalBoardingAmountVariableName = "total_boarding_amount"
	TotalIntentFeesVariableName     = "total_intent_fees"
)

var (
	intentsCount = cel.VariableWithDoc(
		IntentsCountVariableName, cel.DoubleType,
		"Number of pending intents queued",
	)
	currentFeerate = cel.VariableWithDoc(
		CurrentFeerateVariableName, cel.DoubleType,
		"Current mempool fee rate in sat/kvbyte (as reported by the wallet)",
	)
	timeSinceLastBatch = cel.VariableWithDoc(
		TimeSinceLastBatchVariableName, cel.DoubleType,
		"Seconds elapsed since the last batch was finalized "+
			"(0 if no batch has been finalized since the server started)",
	)
	boardingInputsCount = cel.VariableWithDoc(
		BoardingInputsCountVariableName, cel.DoubleType,
		"Total number of pending boarding UTXOs across all queued intents",
	)
	totalBoardingAmount = cel.VariableWithDoc(
		TotalBoardingAmountVariableName, cel.DoubleType,
		"Total amount in satoshis across all pending boarding UTXOs",
	)
	totalIntentFees = cel.VariableWithDoc(
		TotalIntentFeesVariableName, cel.DoubleType,
		"Total implicit fees in satoshis across all pending intents "+
			"(sum of (input amounts) - (output amounts) per intent)",
	)
)
