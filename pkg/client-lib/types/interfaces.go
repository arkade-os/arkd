package types

import (
	"context"
	"time"
)

type Store interface {
	ConfigStore() ConfigStore
	TransactionStore() TransactionStore
	UtxoStore() UtxoStore
	VtxoStore() VtxoStore
	Clean(ctx context.Context)
	Close()
}

type ConfigStore interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data Config) error
	GetData(ctx context.Context) (*Config, error)
	CleanData(ctx context.Context) error
	Close()
}

type TransactionStore interface {
	AddTransactions(ctx context.Context, txs []Transaction) (int, error)
	SettleTransactions(ctx context.Context, txids []string, settledBy string) (int, error)
	ConfirmTransactions(ctx context.Context, txids []string, timestamp time.Time) (int, error)
	RbfTransactions(ctx context.Context, rbfTxs map[string]string) (int, error)
	GetAllTransactions(ctx context.Context) ([]Transaction, error)
	GetTransactions(ctx context.Context, txids []string) ([]Transaction, error)
	UpdateTransactions(ctx context.Context, txs []Transaction) (int, error)
	Clean(ctx context.Context) error
	GetEventChannel() <-chan TransactionEvent
	Close()
}

type UtxoStore interface {
	AddUtxos(ctx context.Context, utxos []Utxo) (int, error)
	ReplaceUtxo(ctx context.Context, from Outpoint, to Outpoint) error
	ConfirmUtxos(ctx context.Context, confirmedUtxos map[Outpoint]int64) (int, error)
	SpendUtxos(ctx context.Context, spentUtxos map[Outpoint]string) (int, error)
	GetAllUtxos(ctx context.Context) (spendable, spent []Utxo, err error)
	GetUtxos(ctx context.Context, keys []Outpoint) ([]Utxo, error)
	Clean(ctx context.Context) error
	GetEventChannel() <-chan UtxoEvent
	Close()
}

type VtxoStore interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) (int, error)
	SpendVtxos(
		ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string,
	) (int, error)
	SettleVtxos(
		ctx context.Context, spentVtxos map[Outpoint]string, settledBy string,
	) (int, error)
	UpdateVtxos(ctx context.Context, vtxos []Vtxo) (int, error)
	GetAllVtxos(ctx context.Context) (spendable, spent []Vtxo, err error)
	GetSpendableVtxos(ctx context.Context) ([]Vtxo, error)
	GetVtxos(ctx context.Context, keys []Outpoint) ([]Vtxo, error)
	Clean(ctx context.Context) error
	GetEventChannel() <-chan VtxoEvent
	Close()
}
