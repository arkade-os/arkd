// Package batchtrigger evaluates an operator-supplied CEL formula that decides
// whether the server should start a new batch round.
//
// The package mirrors the pattern used by pkg/ark-lib/arkfee for fee programs:
// programs are compiled once via Parse, then evaluated against a Context
// snapshot. A nil Trigger is always permissive (returns true) so that callers
// can keep batch behaviour unchanged when no formula is configured.
package batchtrigger

import (
	"fmt"
	"reflect"

	"github.com/arkade-os/arkd/pkg/ark-lib/batchtrigger/celenv"
	"github.com/google/cel-go/cel"
)

// Trigger wraps a compiled CEL program and the original source text.
type Trigger struct {
	program cel.Program
	txt     string
}

// New parses the supplied program text against the batch_trigger CEL
// environment. An empty string returns (nil, nil) so callers can treat the
// gate as "always allow" without special-casing.
func New(program string) (*Trigger, error) {
	if program == "" {
		return nil, nil
	}
	return Parse(program)
}

// Parse compiles a batch_trigger CEL program. It enforces that the program's
// output type is bool — anything else is rejected at compile time so operators
// catch mistakes before the server boots.
func Parse(txt string) (*Trigger, error) {
	ast, issues := celenv.BatchTriggerEnv.Compile(txt)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("expected return type bool, got %v", ast.OutputType())
	}

	prg, err := celenv.BatchTriggerEnv.Program(ast)
	if err != nil {
		return nil, err
	}
	return &Trigger{program: prg, txt: txt}, nil
}

// Source returns the original program text.
func (t *Trigger) Source() string {
	if t == nil {
		return ""
	}
	return t.txt
}

// Eval evaluates the program against the supplied context. A nil receiver
// returns true so that an unconfigured trigger never blocks a batch.
func (t *Trigger) Eval(ctx Context) (bool, error) {
	if t == nil {
		return true, nil
	}
	result, _, err := t.program.Eval(ctx.toArgs())
	if err != nil {
		return false, err
	}
	native, err := result.ConvertToNative(reflect.TypeOf(false))
	if err != nil {
		return false, err
	}
	return native.(bool), nil
}
