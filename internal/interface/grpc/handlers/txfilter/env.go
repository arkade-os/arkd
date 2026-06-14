package txfilter

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
)

var TxFilterEnv *cel.Env

func init() {
	var err error
	TxFilterEnv, err = cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[Tx](), ext.ParseStructTag("json")),
		tx,
		hasPacketFunction,
	)
	if err != nil {
		panic(err)
	}
}

var tx = cel.VariableWithDoc(
	"tx",
	cel.ObjectType("txfilter.Tx"),
	"Transaction envelope. tx.extension is a map<int, string> of packet type "+
		"to hex-encoded packet bytes, only set when the tx carries an ARK OP_RETURN extension.",
)

// hasPacket(extension, packetType) returns true if the extension map contains
// an entry whose key equals packetType.
var hasPacketFunction = cel.Function("hasPacket",
	cel.Overload("hasPacket_map_int_string_int_bool",
		[]*cel.Type{cel.MapType(cel.IntType, cel.StringType), cel.IntType},
		cel.BoolType,
		cel.BinaryBinding(func(ext, packetType ref.Val) ref.Val {
			return ext.(traits.Mapper).Contains(packetType)
		}),
	),
)
