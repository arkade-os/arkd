package explorer

import (
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

// Explorer provides methods to interact with blockchain explorers (e.g., mempool.space, esplora).
// It supports both HTTP REST API calls and WebSocket connections for real-time address tracking.
// The implementation uses a connection pool architecture with multiple concurrent WebSocket connections
// to handle high-volume address subscriptions without overwhelming individual connections.
type Explorer interface {
	// Start must be used when using the explorer with tracking enabled.
	Start()

	// GetTxHex retrieves the raw transaction hex for a given transaction ID.
	GetTxHex(txid string) (string, error)

	// Broadcast broadcasts one or more raw transactions to the network.
	// Returns the transaction ID of the first transaction on success.
	Broadcast(txs ...string) (string, error)

	// GetTxs retrieves all transactions associated with a given address.
	GetTxs(addr string) ([]Tx, error)

	// GetTxOutspends returns the spent status of all outputs for a given transaction.
	GetTxOutspends(tx string) ([]SpentStatus, error)

	// GetUtxos retrieves all unspent transaction outputs (UTXOs) for a given address.
	GetUtxos(addr string) ([]Utxo, error)

	// GetRedeemedVtxosBalance calculates the redeemed virtual UTXO balance for an address
	// considering the unilateral exit delay.
	GetRedeemedVtxosBalance(
		addr string, unilateralExitDelay arklib.RelativeLocktime,
	) (uint64, map[int64]uint64, error)

	// GetTxBlockTime returns whether a transaction is confirmed and its block time.
	GetTxBlockTime(txid string) (confirmed bool, blocktime int64, err error)

	// BaseUrl returns the base URL of the explorer service.
	BaseUrl() string

	// GetFeeRate retrieves the current recommended fee rate in sat/vB.
	GetFeeRate() (float64, error)

	// GetConnectionCount returns the number of active WebSocket connections.
	GetConnectionCount() int

	// GetSubscribedAddresses returns a list of all currently subscribed addresses.
	GetSubscribedAddresses() []string

	// IsAddressSubscribed checks if a specific address is currently subscribed.
	IsAddressSubscribed(address string) bool

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
	Spent   bool
	SpentBy string
}

type Output struct {
	Script  string
	Address string
	Amount  uint64
}

type Input struct {
	Output
	Txid string
	Vout uint32
}

type Tx struct {
	Txid   string
	Vin    []Input
	Vout   []Output
	Status ConfirmedStatus
}

type ConfirmedStatus struct {
	Confirmed bool
	BlockTime int64
}

// Utxo represents an unspent transaction output from the blockchain explorer.
type Utxo struct {
	Txid   string
	Vout   uint32
	Amount uint64
	Script string
	Status ConfirmedStatus
}

// ToUtxo converts the explorer UTXO to the internal types.Utxo format
// with the specified relative locktime delay and tapscripts.
func (e Utxo) ToUtxo(delay arklib.RelativeLocktime, tapscripts []string) types.Utxo {
	return newUtxo(e, delay, tapscripts)
}

func newUtxo(explorerUtxo Utxo, delay arklib.RelativeLocktime, tapscripts []string) types.Utxo {
	utxoTime := explorerUtxo.Status.BlockTime
	createdAt := time.Unix(utxoTime, 0)
	if utxoTime == 0 {
		createdAt = time.Time{}
		utxoTime = time.Now().Unix()
	}

	return types.Utxo{
		Outpoint: types.Outpoint{
			Txid: explorerUtxo.Txid,
			VOut: explorerUtxo.Vout,
		},
		Amount:      explorerUtxo.Amount,
		Delay:       delay,
		SpendableAt: time.Unix(utxoTime, 0).Add(time.Duration(delay.Seconds()) * time.Second),
		CreatedAt:   createdAt,
		Tapscripts:  tapscripts,
	}
}
