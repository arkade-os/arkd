package unroll

import "fmt"

// UnrollRes is the result of a single Unroll iteration (one parent + child 1C1P package).
type UnrollRes struct {
	ParentTx   string
	ParentTxid string
	ChildTx    string
	ChildTxid  string
}

var ErrWaitingForConfirmation = fmt.Errorf("waiting for confirmation(s), please retry later")
