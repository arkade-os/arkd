package common

import (
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func P2TRScript(taprootKey *secp256k1.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(taprootKey)).Script()
}

func SubDustScript(taprootKey *secp256k1.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).AddData(schnorr.SerializePubKey(taprootKey)).Script()
}

func IsSubDustScript(script []byte) bool {
	return len(script) == 32+1+1 &&
		script[0] == txscript.OP_RETURN &&
		script[1] == 0x20
}
