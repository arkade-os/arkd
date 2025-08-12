package arkade

import "github.com/btcsuite/btcd/txscript"

// scriptError creates an Error given a set of arguments.
func scriptError(c txscript.ErrorCode, desc string) error {
	return txscript.Error{ErrorCode: c, Description: desc}
}
