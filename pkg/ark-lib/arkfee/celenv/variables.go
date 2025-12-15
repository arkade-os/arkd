package celenv

import (
	"github.com/google/cel-go/cel"
)

const (
	AmountVariableName       = "amount"
	ExpiryVariableName       = "expiry"
	BirthVariableName        = "birth"
	WeightVariableName       = "weight"
	InputTypeVariableName    = "inputType"
	OutputScriptVariableName = "script"
)

var (
	amount       = cel.VariableWithDoc(AmountVariableName, cel.DoubleType, "Amount in satoshis")
	expiry       = cel.VariableWithDoc(ExpiryVariableName, cel.DoubleType, "Expiry date in unix timestamp seconds")
	birth        = cel.VariableWithDoc(BirthVariableName, cel.DoubleType, "Birth date in unix timestamp seconds")
	weight       = cel.VariableWithDoc(WeightVariableName, cel.DoubleType, "Weighted liquidity lockup ratio of a vtxo")
	inputType    = cel.VariableWithDoc(InputTypeVariableName, cel.StringType, "Type of the input, either 'vtxo', 'recoverable' or 'note'")
	outputScript = cel.VariableWithDoc(OutputScriptVariableName, cel.StringType, "hex encoded pkscript")
)
