package walletclient

import (
	"errors"

	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
)

type Outpoint struct {
	Txid string
	VOut uint32
}

type txInput struct {
	txId   string
	index  uint32
	script string
	value  uint64
}

func (t txInput) GetTxid() string {
	return t.txId
}

func (t txInput) GetIndex() uint32 {
	return t.index
}

func (t txInput) GetScript() string {
	return t.script
}

func (t txInput) GetValue() uint64 {
	return t.value
}

type walletStatus struct {
	resp *arkwalletv1.StatusResponse
}

func (ws *walletStatus) IsInitialized() bool { return ws.resp.GetInitialized() }
func (ws *walletStatus) IsUnlocked() bool    { return ws.resp.GetUnlocked() }
func (ws *walletStatus) IsSynced() bool      { return ws.resp.GetSynced() }

// Local error definitions
var (
	// ErrNonFinalBIP68 is returned when a transaction spending a CSV-locked output is not final.
	ErrNonFinalBIP68 = errors.New("non-final BIP68 sequence")
)

// VtxoWithValue represents a VTXO with its value
type VtxoWithValue struct {
	Outpoint Outpoint
	Value    uint64
}

// BlockTimestamp represents a block timestamp
type BlockTimestamp struct {
	Height uint32
	Time   int64
}

// WalletStatus interface defines wallet status methods
type WalletStatus interface {
	IsInitialized() bool
	IsUnlocked() bool
	IsSynced() bool
}

// TxInput interface defines transaction input methods
type TxInput interface {
	GetTxid() string
	GetIndex() uint32
	GetScript() string
	GetValue() uint64
}

func (w *Wallet) Close() {
	_ = w.conn.Close()
}
