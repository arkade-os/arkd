package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
	KVStore       = "kv"
	SQLStore      = "sql"
)

type Config struct {
	ServerUrl                  string
	ServerPubKey               *secp256k1.PublicKey
	WalletType                 string
	ClientType                 string
	Network                    common.Network
	VtxoTreeExpiry             common.RelativeLocktime
	RoundInterval              int64
	UnilateralExitDelay        common.RelativeLocktime
	Dust                       uint64
	BoardingExitDelay          common.RelativeLocktime
	BoardingDescriptorTemplate string
	ExplorerURL                string
	ExplorerWSURL              string
	ForfeitAddress             string
	WithTransactionFeed        bool
	MarketHourStartTime        int64
	MarketHourEndTime          int64
	MarketHourPeriod           int64
	MarketHourRoundInterval    int64
	UtxoMinAmount              int64
	UtxoMaxAmount              int64
	VtxoMinAmount              int64
	VtxoMaxAmount              int64
}

type VtxoKey struct {
	Txid string
	VOut uint32
}

func (v VtxoKey) String() string {
	return fmt.Sprintf("%s:%s", v.Txid, strconv.Itoa(int(v.VOut)))
}

type Vtxo struct {
	VtxoKey
	PubKey    string
	Amount    uint64
	RoundTxid string
	ExpiresAt time.Time
	CreatedAt time.Time
	RedeemTx  string
	Pending   bool
	SpentBy   string
	Spent     bool
}

type VtxoEventType int

const (
	VtxosAdded VtxoEventType = iota
	VtxosSpent
	VtxosUpdated
)

func (e VtxoEventType) String() string {
	return map[VtxoEventType]string{
		VtxosAdded: "VTXOS_ADDED",
		VtxosSpent: "VTXOS_SPENT",
	}[e]
}

type VtxoEvent struct {
	Type  VtxoEventType
	Vtxos []Vtxo
}

const (
	TxSent     TxType = "SENT"
	TxReceived TxType = "RECEIVED"
)

type TxType string

type TransactionKey struct {
	BoardingTxid string
	RoundTxid    string
	RedeemTxid   string
}

func (t TransactionKey) String() string {
	return fmt.Sprintf("%s%s%s", t.BoardingTxid, t.RoundTxid, t.RedeemTxid)
}

type Transaction struct {
	TransactionKey
	Amount    uint64
	Type      TxType
	Settled   bool
	CreatedAt time.Time
	Hex       string
}

func (t Transaction) IsRound() bool {
	return t.RoundTxid != ""
}

func (t Transaction) IsBoarding() bool {
	return t.BoardingTxid != ""
}

func (t Transaction) IsOOR() bool {
	return t.RedeemTxid != ""
}

func (t Transaction) String() string {
	buf, _ := json.MarshalIndent(t, "", "  ")
	return string(buf)
}

type TxEventType int

const (
	TxsAdded TxEventType = iota
	TxsSettled
	TxsConfirmed
	TxsReplaced
	TxsUpdated
)

func (e TxEventType) String() string {
	return map[TxEventType]string{
		TxsAdded:     "TXS_ADDED",
		TxsSettled:   "TXS_SETTLED",
		TxsConfirmed: "TXS_CONFIRMED",
		TxsReplaced:  "TXS_REPLACED",
	}[e]
}

type TransactionEvent struct {
	Type         TxEventType
	Txs          []Transaction
	Replacements map[string]string
}

type Utxo struct {
	Txid        string
	VOut        uint32
	Amount      uint64
	Delay       common.RelativeLocktime
	SpendableAt time.Time
	CreatedAt   time.Time
	Tapscripts  []string
	Spent       bool
	Tx          string
}

func (u *Utxo) Sequence() (uint32, error) {
	return common.BIP68Sequence(u.Delay)
}
