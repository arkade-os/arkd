package explorer

import (
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type spentStatus struct {
	Spent   bool   `json:"spent"`
	SpentBy string `json:"txid,omitempty"`
}

type tx struct {
	Txid string `json:"txid"`
	Vout []struct {
		Address string `json:"scriptpubkey_address"`
		Amount  uint64 `json:"value"`
	} `json:"vout"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type rbfTx struct {
	Txid    string `json:"txid"`
	RBF     bool   `json:"rbf"`
	FullRBF bool   `json:"fullRbf"`
}

type replacement struct {
	Tx        rbfTx         `json:"tx"`
	Timestamp int64         `json:"time"`
	FullRBF   bool          `json:"fullRbf"`
	Mined     bool          `json:"mined"`
	Replaces  []replacement `json:"replaces"`
}

type utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset,omitempty"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

func (e utxo) ToUtxo(delay common.RelativeLocktime, tapscripts []string) types.Utxo {
	return newUtxo(e, delay, tapscripts)
}

type WSBlockTransactions struct {
	BlockTransactions []RawTx `json:"block-transactions"`
}

type RawTx struct {
	Txid     string      `json:"txid"`
	Version  int         `json:"version"`
	Locktime uint32      `json:"locktime"`
	Vin      []VinEntry  `json:"vin"`
	Vout     []VoutEntry `json:"vout"`
	Size     int         `json:"size"`
	Weight   int         `json:"weight"`
	Fee      uint64      `json:"fee"`
}

type VinEntry struct {
	Txid           string  `json:"txid"`
	VoutIndex      uint32  `json:"vout"`
	Prevout        Prevout `json:"prevout"`
	Scriptsig      string  `json:"scriptsig"`
	ScriptsigAsm   string  `json:"scriptsig_asm"`
	IsCoinbase     bool    `json:"is_coinbase"`
	Sequence       uint32  `json:"sequence"`
	InnerRedeemAsm string  `json:"inner_redeemscript_asm,omitempty"`
}

type Prevout struct {
	ScriptPubKey     string `json:"scriptpubkey"`
	ScriptPubKeyAsm  string `json:"scriptpubkey_asm"`
	ScriptPubKeyType string `json:"scriptpubkey_type"`
	ScriptPubKeyAddr string `json:"scriptpubkey_address"`
	Value            uint64 `json:"value"`
}

type VoutEntry struct {
	ScriptPubKey     string `json:"scriptpubkey"`
	ScriptPubKeyAsm  string `json:"scriptpubkey_asm"`
	ScriptPubKeyType string `json:"scriptpubkey_type"`
	ScriptPubKeyAddr string `json:"scriptpubkey_address"`
	Value            uint64 `json:"value"`
}

type BlockUtxo struct {
	Txid             string
	VoutIndex        int
	ScriptPubAddress string
	Value            uint64
}
