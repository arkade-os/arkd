package celenv

import (
	"github.com/google/cel-go/cel"
)

var IntentOffchainInputEnv *cel.Env

func init() {
	var err error
	IntentOffchainInputEnv, err = cel.NewEnv(
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
