package celenv

import (
	"github.com/google/cel-go/cel"
)

var IntentOutputEnv *cel.Env

func init() {
	var err error
	IntentOutputEnv, err = cel.NewEnv(
		// variables
		amount,
		outputScript,
		// functions
		nowFunction,
	)
	if err != nil {
		panic(err)
	}
}
