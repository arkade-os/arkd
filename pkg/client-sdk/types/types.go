package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
	KVStore       = "kv"
	SQLStore      = "sql"
)

type Config struct {
	ServerUrl               string
	SignerPubKey            *secp256k1.PublicKey
	WalletType              string
	ClientType              string
	Network                 common.Network
	VtxoTreeExpiry          common.RelativeLocktime
	RoundInterval           int64
	UnilateralExitDelay     common.RelativeLocktime
	Dust                    uint64
	BoardingExitDelay       common.RelativeLocktime
	ExplorerURL             string
	ForfeitAddress          string
	WithTransactionFeed     bool
	MarketHourStartTime     int64
	MarketHourEndTime       int64
	MarketHourPeriod        int64
	MarketHourRoundInterval int64
	UtxoMinAmount           int64
	UtxoMaxAmount           int64
	VtxoMinAmount           int64
	VtxoMaxAmount           int64
}

type Outpoint struct {
	Txid string
	VOut uint32
}

func (v Outpoint) String() string {
	return fmt.Sprintf("%s:%d", v.Txid, v.VOut)
}

type Vtxo struct {
	Outpoint
	Script          string
	Amount          uint64
	CommitmentTxids []string
	ExpiresAt       time.Time
	CreatedAt       time.Time
	Preconfirmed    bool
	Swept           bool
	Unrolled        bool
	Spent           bool
	SpentBy         string
	SettledBy       string
	ArkTxid         string
}

func (v Vtxo) String() string {
	// nolint
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (v Vtxo) IsRecoverable() bool {
	return v.Swept && !v.Spent
}

func (v Vtxo) Address(server *secp256k1.PublicKey, net common.Network) (string, error) {
	buf, err := hex.DecodeString(v.Script)
	if err != nil {
		return "", err
	}
	pubkeyBytes := buf[2:]

	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return "", err
	}

	a := &common.Address{
		HRP:        net.Addr,
		Signer:     server,
		VtxoTapKey: pubkey,
	}

	return a.EncodeV0()
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
	BoardingTxid   string
	CommitmentTxid string
	ArkTxid        string
}

func (t TransactionKey) String() string {
	return fmt.Sprintf("%s%s%s", t.BoardingTxid, t.CommitmentTxid, t.ArkTxid)
}

type Transaction struct {
	TransactionKey
	Amount    uint64
	Type      TxType
	Settled   bool
	CreatedAt time.Time
	Hex       string
	SettledBy string
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

type Receiver struct {
	To     string
	Amount uint64
}

func (r Receiver) IsOnchain() bool {
	_, err := btcutil.DecodeAddress(r.To, nil)
	return err == nil
}

func (o Receiver) ToTxOut() (*wire.TxOut, bool, error) {
	var pkScript []byte
	isOnchain := false

	arkAddress, err := common.DecodeAddressV0(o.To)
	if err != nil {
		// decode onchain address
		btcAddress, err := btcutil.DecodeAddress(o.To, nil)
		if err != nil {
			return nil, false, err
		}

		pkScript, err = txscript.PayToAddrScript(btcAddress)
		if err != nil {
			return nil, false, err
		}

		isOnchain = true
	} else {
		pkScript, err = common.P2TRScript(arkAddress.VtxoTapKey)
		if err != nil {
			return nil, false, err
		}
	}

	if len(pkScript) == 0 {
		return nil, false, fmt.Errorf("invalid address")
	}

	return &wire.TxOut{
		Value:    int64(o.Amount),
		PkScript: pkScript,
	}, isOnchain, nil
}
