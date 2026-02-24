package mempool_explorer

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
)

type spentStatus struct {
	Spent   bool   `json:"spent"`
	SpentBy string `json:"txid,omitempty"`
}

type tx struct {
	Txid string `json:"txid"`
	Vin  []struct {
		Txid    string `json:"txid"`
		Vout    uint32 `json:"vout"`
		Prevout struct {
			Script  string `json:"scriptpubkey"`
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

type txs []tx

func (t txs) toList() []explorer.Tx {
	txs := make([]explorer.Tx, 0)
	for _, tx := range t {
		ins := make([]explorer.Input, 0, len(tx.Vin))
		for _, in := range tx.Vin {
			ins = append(ins, explorer.Input{
				Txid: in.Txid,
				Vout: in.Vout,
				Output: explorer.Output{
					Script:  in.Prevout.Script,
					Address: in.Prevout.Address,
					Amount:  in.Prevout.Amount,
				},
			})
		}
		outs := make([]explorer.Output, 0, len(tx.Vout))
		for _, out := range tx.Vout {
			outs = append(outs, explorer.Output{
				Script:  out.Script,
				Address: out.Address,
				Amount:  out.Amount,
			})
		}
		txs = append(txs, explorer.Tx{
			Txid: tx.Txid,
			Vin:  ins,
			Vout: outs,
			Status: explorer.ConfirmedStatus{
				Confirmed: tx.Status.Confirmed,
				BlockTime: tx.Status.Blocktime,
			},
		})
	}
	return txs
}

type addressNotification struct {
	MultiAddrTx map[string]txNotificationSet `json:"multi-address-transactions"`
	Error       string                       `json:"track-addresses-error"`
}

type txNotificationSet struct {
	Mempool   []txNotification `json:"mempool"`
	Confirmed []txNotification `json:"confirmed"`
	Removed   []txNotification `json:"removed"`
}

type txNotification struct {
	Txid    string                  `json:"txid"`
	Version uint32                  `json:"version"`
	Inputs  []txNotificationInput   `json:"vin"`
	Outputs []txNotificationPrevout `json:"vout"`
	Status  struct {
		Confirmed bool  `json:"confirmed"`
		BlockTime int64 `json:"block_time"`
	} `json:"status"`
}

type txNotificationInput struct {
	Prevout txNotificationPrevout `json:"prevout"`
	Txid    string                `json:"txid"`
	Vout    int                   `json:"vout"`
}

type txNotificationPrevout struct {
	Script  string `json:"scriptpubkey"`
	Address string `json:"scriptpubkey_address"`
	Amount  uint64 `json:"value"`
}

type RbfTxId struct {
	TxId string `json:"txid"`
}

type RBFTxn struct {
	TxId       string
	ReplacedBy string
}

// addressData stores cached UTXO data for an address to detect changes during polling.
type addressData struct {
	hash  []byte
	utxos []utxo
}

type utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Script string `json:"scriptpubkey"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		BlockTime int64 `json:"block_time"`
	} `json:"status"`
}

func (u utxo) hash() []byte {
	buf := bytes.Buffer{}
	buf.WriteString(u.Txid)
	buf.WriteString(strconv.Itoa(int(u.Vout)))
	buf.WriteString(strconv.FormatUint(u.Amount, 10))
	buf.WriteString(u.Script)
	buf.WriteString(strconv.FormatBool(u.Status.Confirmed))
	buf.WriteString(strconv.FormatInt(u.Status.BlockTime, 10))
	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

type utxos []utxo

func (u utxos) toUtxoList() []explorer.Utxo {
	utxos := make([]explorer.Utxo, 0)
	for _, utxo := range u {
		utxos = append(utxos, explorer.Utxo{
			Txid:   utxo.Txid,
			Vout:   utxo.Vout,
			Amount: utxo.Amount,
			Status: explorer.ConfirmedStatus{
				Confirmed: utxo.Status.Confirmed,
				BlockTime: utxo.Status.BlockTime,
			},
			Script: utxo.Script,
		})
	}
	return utxos
}

func (u utxos) hash() []byte {
	// order the utxos by txid and vout
	sort.SliceStable(u, func(i, j int) bool {
		txidCmp := strings.Compare(u[i].Txid, u[j].Txid)
		if txidCmp == 0 {
			return u[i].Vout < u[j].Vout
		}
		return txidCmp < 0
	})
	buf := bytes.Buffer{}
	for _, utxo := range u {
		buf.Write(utxo.hash())
	}
	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}
