// Package explorer provides a simplified blockchain explorer client interface
// with only the methods that are actually used in production code.
//
// This interface removes debugging, monitoring, and example-only methods
// to provide a cleaner, more focused API.
package walletclient

import (
	"github.com/arkade-os/go-sdk/types"
)

// Explorer provides the core methods to interact with blockchain explorers.
// This is a simplified version of the Explorer interface that only includes
// methods that are actually used in production code.
type Explorer interface {
	// GetTxHex retrieves the raw transaction hex for a given transaction ID.
	GetTxHex(txid string) (string, error)

	// Broadcast broadcasts one or more raw transactions to the network.
	// Returns the transaction ID of the first transaction on success.
	Broadcast(txs ...string) (string, error)

	// GetTxs retrieves all transactions associated with a given address.
	GetTransactions(addr string) ([]Tx, error)

	// GetTxOutspends returns the spent status of all outputs for a given transaction.
	GetTxOutspends(tx string) ([]SpentStatus, error)

	// GetUtxos retrieves all unspent transaction outputs (UTXOs) for a given address.
	GetUtxos(addr string) ([]Utxo, error)

	// GetTxBlockTime returns whether a transaction is confirmed and its block time.
	GetTxBlockTime(
		txid string,
	) (confirmed bool, blocktime int64, err error)

	// BaseUrl returns the base URL of the explorer service.
	BaseUrl() string

	// GetFeeRate retrieves the current recommended fee rate in sat/vB.
	GetFeeRate() (float64, error)

	// GetAddressesEvents returns a channel that receives onchain address events
	// (new UTXOs, spent UTXOs, confirmed UTXOs) for all subscribed addresses.
	GetAddressesEvents() <-chan types.OnchainAddressEvent

	// SubscribeForAddresses subscribes to address updates via WebSocket connections.
	// Addresses are automatically distributed across multiple connections using hash-based routing.
	// Subscriptions are batched to prevent overwhelming individual connections.
	// Duplicate subscriptions are automatically prevented via instance-scoped deduplication.
	SubscribeForAddresses(addresses []string) error

	// UnsubscribeForAddresses removes address subscriptions and updates the WebSocket connections.
	UnsubscribeForAddresses(addresses []string) error

	// Stop gracefully shuts down the explorer, closing all WebSocket connections and channels.
	Stop()
}

type SpentStatus struct {
	Spent   bool   `json:"spent"`
	SpentBy string `json:"txid,omitempty"`
}

type Tx struct {
	Txid string `json:"txid"`
	Vin  []struct {
		Txid    string `json:"txid"`
		Vout    uint32 `json:"vout"`
		Prevout struct {
			Address string `json:"scriptpubkey_address"`
			Amount  uint64 `json:"value"`
		} `json:"prevout"`
	} `json:"vin"`
	Vout []struct {
		Script  string `json:"scriptpubkey"`
		Address string `json:"scriptpubkey_address"`
		Amount  uint64 `json:"value"`
	} `json:"vout"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type Utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset,omitempty"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		BlockTime int64 `json:"block_time"`
	} `json:"status"`
	Script string
}

type RbfTxId struct {
	TxId string `json:"txid"`
}

type RBFTxn struct {
	TxId       string
	ReplacedBy string
}
