package ports

import "github.com/arkade-os/arkd/internal/core/domain"

type TxIn = domain.Outpoint

type TxOut struct {
	Amount   uint64
	PkScript []byte
}

type TxDecoder interface {
	DecodeTx(tx string) (txid string, ins []TxIn, outs []TxOut, err error)
}
