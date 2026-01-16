package celenv

import (
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// now() returns the current Unix timestamp in seconds
var nowFunction = cel.Function("now",
	cel.Overload("now_double",
		[]*cel.Type{},
		cel.DoubleType,
		cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			return types.Double(float64(time.Now().Unix()))
		}),
	),
)
