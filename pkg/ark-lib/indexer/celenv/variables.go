package celenv

import (
	"github.com/google/cel-go/cel"
)

const TxVariableName = "tx"

var tx = cel.VariableWithDoc(
	TxVariableName,
	cel.MapType(cel.StringType, cel.DynType),
	"Transaction envelope. tx.extension is a map<int, string> of packet type "+
		"to hex-encoded packet bytes, only set when the tx carries an ARK OP_RETURN extension.",
)
