package celenv

import (
	"github.com/google/cel-go/cel"
)

const TxVariableName = "tx"

// tx is declared as cel.MapType(string, dyn) because CEL needs static-typed
// field access (`tx.extension`) on a string-keyed map. The runtime value of
// tx.extension is a map<int, string> (packet type -> hex-encoded packet
// bytes); CEL accepts integer indexing on it via the dyn-typed value, so
// expressions like `tx.extension[0x05]` work as expected. tx.extension is
// only populated when the tx carries an ARK OP_RETURN extension, so
// `has(tx.extension)` is the correct presence guard.
var tx = cel.VariableWithDoc(
	TxVariableName,
	cel.MapType(cel.StringType, cel.DynType),
	"Transaction envelope. tx.extension is a map<int, string> of packet type "+
		"to hex-encoded packet bytes, only set when the tx carries an ARK OP_RETURN extension.",
)
