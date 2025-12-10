package celenv

import (
	"github.com/google/cel-go/cel"
)

var IntentOnchainInputEnv *cel.Env

func init() {
	var err error
	IntentOnchainInputEnv, err = cel.NewEnv(
		// variables
		amount,
		// functions
		nowFunction,
	)
	if err != nil {
		panic(err)
	}
}
