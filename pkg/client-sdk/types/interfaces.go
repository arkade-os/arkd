package types

import (
	"context"
	"time"
)

type Store interface {
	ConfigStore() ConfigStore
	TransactionStore() TransactionStore
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
	RbfTransactions(ctx context.Context, rbfTxs map[string]Transaction) (int, error)
	GetAllTransactions(ctx context.Context) ([]Transaction, error)
	GetTransactions(ctx context.Context, txids []string) ([]Transaction, error)
	UpdateTransactions(ctx context.Context, txs []Transaction) (int, error)
	Clean(ctx context.Context) error
	GetEventChannel() chan TransactionEvent
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
	GetAllVtxos(ctx context.Context) (spendable []Vtxo, spent []Vtxo, err error)
	GetVtxos(ctx context.Context, keys []Outpoint) ([]Vtxo, error)
	Clean(ctx context.Context) error
	GetEventChannel() chan VtxoEvent
	Close()
}
