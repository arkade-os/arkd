package arkfee

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
	"github.com/google/cel-go/cel"
)

func parse(txt string, env *cel.Env) (cel.Program, error) {
	ast, issues := env.Compile(txt)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	if ast.OutputType() != cel.DoubleType {
		return nil, fmt.Errorf("expected return type double, got %v", ast.OutputType())
	}

	return env.Program(ast)
}

func ParseIntentInputProgram(txt string) (cel.Program, error) {
	return parse(txt, celenv.IntentInputEnv)
}

func ParseIntentOutputProgram(txt string) (cel.Program, error) {
	return parse(txt, celenv.IntentOutputEnv)
}
