package txfilter

import (
	"fmt"

	"github.com/google/cel-go/cel"
)

type Filter struct {
	cel.Program
}

func (f Filter) Eval(tx Tx) (bool, error) {
	out, _, err := f.Program.Eval(map[string]any{"tx": tx})
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not yield bool")
	}
	return b, nil
}

func Parse(expression string) (*Filter, error) {
	ast, issues := TxFilterEnv.Compile(expression)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("expected return type bool, got %v", ast.OutputType())
	}

	prg, err := TxFilterEnv.Program(ast)
	if err != nil {
		return nil, err
	}
	return &Filter{prg}, nil
}
