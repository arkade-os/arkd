package celenv

import (
	"reflect"
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

// clamp(value, min, max) returns the value clamped between min and max
var clampFunction = cel.Function("clamp",
	cel.Overload("clamp_double",
		[]*cel.Type{cel.DoubleType, cel.DoubleType, cel.DoubleType},
		cel.DoubleType,
		cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			if len(args) != 3 {
				return types.NewErr("clamp expects 3 arguments")
			}
			value, err := args[0].ConvertToNative(reflect.TypeOf(float64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}
			min, err := args[1].ConvertToNative(reflect.TypeOf(float64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}
			max, err := args[2].ConvertToNative(reflect.TypeOf(float64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}

			if value.(float64) < min.(float64) {
				return types.Double(min.(float64))
			}
			if value.(float64) > max.(float64) {
				return types.Double(max.(float64))
			}
			return types.Double(value.(float64))
		}),
	),
	cel.Overload("clamp_int",
		[]*cel.Type{cel.IntType, cel.IntType, cel.IntType},
		cel.DoubleType,
		cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			if len(args) != 3 {
				return types.NewErr("clamp expects 3 arguments")
			}
			value, err := args[0].ConvertToNative(reflect.TypeOf(int64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}
			min, err := args[1].ConvertToNative(reflect.TypeOf(int64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}
			max, err := args[2].ConvertToNative(reflect.TypeOf(int64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}

			if value.(int64) < min.(int64) {
				return types.Int(min.(int64))
			}
			if value.(int64) > max.(int64) {
				return types.Int(max.(int64))
			}
			return types.Int(value.(int64))
		}),
	),
	cel.Overload("clamp_double_int_int",
		[]*cel.Type{cel.DoubleType, cel.IntType, cel.IntType},
		cel.DoubleType,
		cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			if len(args) != 3 {
				return types.NewErr("clamp expects 3 arguments")
			}
			value, err := args[0].ConvertToNative(reflect.TypeOf(float64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}
			min, err := args[1].ConvertToNative(reflect.TypeOf(int64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}
			max, err := args[2].ConvertToNative(reflect.TypeOf(int64(0)))
			if err != nil {
				return types.NewErr("%s", err.Error())
			}

			valueFloat := value.(float64)
			minFloat := float64(min.(int64))
			maxFloat := float64(max.(int64))

			if valueFloat < minFloat {
				return types.Double(minFloat)
			}
			if valueFloat > maxFloat {
				return types.Double(maxFloat)
			}
			return types.Double(valueFloat)
		}),
	),
)
