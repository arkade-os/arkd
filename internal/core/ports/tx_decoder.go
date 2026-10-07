package ports

import "github.com/arkade-os/arkd/internal/core/domain"

type TxIn struct {
	domain.Outpoint
	// Prevout is the output spent by the input, nil if the tx doesn't carry it.
	Prevout *TxOut
}

type TxOut struct {
	Amount   uint64
	PkScript []byte
}

type TxDecoder interface {
	DecodeTx(tx string) (txid string, ins []TxIn, outs []TxOut, err error)
}
