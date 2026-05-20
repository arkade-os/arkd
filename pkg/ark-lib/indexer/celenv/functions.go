package celenv

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// hasPacket(extension, packetType) returns true if the extension map contains
// an entry whose key equals packetType.
var hasPacketFunction = cel.Function("hasPacket",
	cel.Overload("hasPacket_dyn_dyn_bool",
		[]*cel.Type{cel.DynType, cel.DynType},
		cel.BoolType,
		cel.BinaryBinding(func(ext, packetType ref.Val) ref.Val {
			m, ok := ext.(traits.Mapper)
			if !ok {
				return types.False
			}
			return m.Contains(packetType)
		}),
	),
)
