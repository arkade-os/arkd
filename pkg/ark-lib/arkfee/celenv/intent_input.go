package celenv

import (
	"github.com/google/cel-go/cel"
)

var IntentInputEnv *cel.Env

func init() {
	var err error
	IntentInputEnv, err = cel.NewEnv(
		// variables
		amount,
		expiry,
		birth,
		weight,
		inputType,
		// functions
		nowFunction,
	)
	if err != nil {
		panic(err)
	}
}
