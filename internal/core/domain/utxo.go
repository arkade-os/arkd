package domain

type Utxo struct {
	Outpoint
	Amount    uint64
	PubKey    string
	Spend     UtxoSpend
	CreatedAt int64
	Assets    []AssetDenomination
}

type UtxoSpend struct {
	Txid              string
	ConfirmedAtTime   int64
	ConfirmedAtHeight uint64
}

func (u UtxoSpend) IsConfirmed() bool {
	return u.ConfirmedAtTime > 0 || u.ConfirmedAtHeight > 0
}
