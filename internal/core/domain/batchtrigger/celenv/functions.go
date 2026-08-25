package celenv

import (
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// now() returns the current Unix timestamp in seconds. The binding is
// evaluated on every call: BatchTriggerEnv does not opt into the constant
// folding optimizer (cel.OptOptimize), so the value is never folded.
var nowFunction = cel.Function("now",
	cel.Overload("now_double",
		[]*cel.Type{},
		cel.DoubleType,
		cel.FunctionBinding(func(_ ...ref.Val) ref.Val {
			return types.Double(time.Now().Unix())
		}),
	),
)
