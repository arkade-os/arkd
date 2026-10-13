package nbxplorer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadcastTransactionPackage(t *testing.T) {
	newService := func(t *testing.T, response string, txs []string) *nbxplorer {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/v1/cryptos/BTC/rpc", r.URL.Path)
			var request struct {
				Method string     `json:"method"`
				Params [][]string `json:"params"`
			}
			if assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
				assert.Equal(t, "submitpackage", request.Method)
				assert.Equal(t, [][]string{txs}, request.Params)
			}
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(response))
			assert.NoError(t, err)
		}))
		t.Cleanup(server.Close)

		return &nbxplorer{url: server.URL, httpClient: server.Client()}
	}

	t.Run("success", func(t *testing.T) {
		tests := []struct {
			name     string
			response string
		}{
			{
				name: "accepted package",
				response: `{"error":null,"result":{
				"package_msg":"success",
				"tx-results":{
					"parent-wtxid":{"txid":"parent-txid","vsize":100,"fees":{"base":0.00001}},
					"child-wtxid":{"txid":"child-txid","vsize":100,"fees":{"base":0.00002}}
				},
				"replaced-transactions":["replaced-txid"]
			}}`,
			},
			{
				name: "already in mempool",
				response: `{"error":null,"result":{
				"package_msg":"success",
				"tx-results":{
					"parent-wtxid":{"txid":"parent-txid","other-wtxid":"existing-parent-wtxid"},
					"child-wtxid":{"txid":"child-txid"}
				}
			}}`,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				txs := []string{"00", "01"}
				n := newService(t, tt.response, txs)
				result, err := n.BroadcastTransaction(t.Context(), txs...)
				require.NoError(t, err)
				var response struct {
					Result json.RawMessage `json:"result"`
				}
				require.NoError(t, json.Unmarshal([]byte(tt.response), &response))
				require.JSONEq(t, string(response.Result), result)
			})
		}
	})

	t.Run("error", func(t *testing.T) {
		tests := []struct {
			name     string
			response string
			wantErr  []string
		}{
			{
				name: "partial rejection",
				response: `{"error":null,"result":{
				"package_msg":"transaction failed",
				"tx-results":{
					"parent-wtxid":{"txid":"parent-txid","vsize":100},
					"child-wtxid":{"txid":"child-txid","error":"bad-txns-inputs-missingorspent"}
				}
			}}`,
				wantErr: []string{
					"submitpackage failed",
					"transaction failed",
					"child-wtxid",
					"bad-txns-inputs-missingorspent",
				},
			},
			{
				name: "multiple rejections",
				response: `{"error":null,"result":{
				"package_msg":"transaction failed",
				"tx-results":{
					"parent-wtxid":{"txid":"parent-txid","error":"non-BIP68-final"},
					"child-wtxid":{"txid":"child-txid","error":"bad-txns-inputs-missingorspent"}
				}
			}}`,
				wantErr: []string{
					"transaction failed",
					"parent-wtxid",
					"non-BIP68-final",
					"child-wtxid",
					"bad-txns-inputs-missingorspent",
				},
			},
			{
				name:     "package rejection without transaction results",
				response: `{"error":null,"result":{"package_msg":"package-not-sorted"}}`,
				wantErr:  []string{"submitpackage failed", "package-not-sorted"},
			},
			{
				name: "transaction error despite success message",
				response: `{"error":null,"result":{
				"package_msg":"success",
				"tx-results":{"child-wtxid":{"txid":"child-txid","error":"mempool min fee not met"}}
			}}`,
				wantErr: []string{"submitpackage failed", "child-wtxid", "mempool min fee not met"},
			},
			{
				name:     "missing package message",
				response: `{"error":null,"result":{"tx-results":{}}}`,
				wantErr:  []string{"submitpackage failed"},
			},
			{
				name:     "empty package message",
				response: `{"error":null,"result":{"package_msg":"","tx-results":{}}}`,
				wantErr:  []string{"submitpackage failed"},
			},
			{
				name:     "invalid result type",
				response: `{"error":null,"result":"success"}`,
				wantErr:  []string{"failed to unmarshal submitpackage result"},
			},
			{
				name:     "invalid transaction results",
				response: `{"error":null,"result":{"package_msg":"success","tx-results":[]}}`,
				wantErr:  []string{"failed to unmarshal submitpackage result"},
			},
			{
				name:     "nil result",
				response: `{"error":null,"result":null}`,
				wantErr:  []string{"RPC returned nil result"},
			},
			{
				name:     "RPC error",
				response: `{"error":{"code":-26,"message":"package policy failure"},"result":null}`,
				wantErr:  []string{"RPC error -26: package policy failure"},
			},
			{
				name:     "invalid JSON",
				response: `{"result":`,
				wantErr:  []string{"failed to unmarshal RPC response"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				txs := []string{"00", "01"}
				n := newService(t, tt.response, txs)
				result, err := n.BroadcastTransaction(t.Context(), txs...)
				require.Error(t, err)
				require.Empty(t, result)
				for _, message := range tt.wantErr {
					assert.ErrorContains(t, err, message)
				}
			})
		}
	})
}

func TestParseTxNotification(t *testing.T) {
	const (
		groupSource = "GROUP:MrFhJe5NUUqZ8jShUy"
		fundTxid    = "bc10984a0e9b11cc58f1bd68bcbe66ee34add8eac3598104da30f57cf71100ce"
		spendTxid   = "70add375cd633cd21c428ed5b4331b21726bf53caf1e3b53ae24be2d3b9bb9bf"
	)
	fundHash, err := chainhash.NewHashFromStr(fundTxid)
	require.NoError(t, err)
	watchedUtxo := ports.Utxo{
		OutPoint: wire.OutPoint{Hash: *fundHash, Index: 1},
		Value:    100000,
		Script:   "5120787740c75564eb59971554c55d9d43076353253e445209bab7587c71d1e515a6",
		Address:  "bcrt1p0pm5p364vn44n9c42nz4m82rqa34xff7g3fqnw4htp78r509zknqzwcxhc",
	}

	t.Run("unconfirmed tx creating a watched utxo", func(t *testing.T) {
		notification, err := parseTxNotification([]byte(fundMempoolEvent), groupSource)
		require.NoError(t, err)
		require.Equal(t, &ports.TxNotification{
			Txid:    fundTxid,
			Outputs: []ports.Utxo{watchedUtxo},
		}, notification)
	})

	t.Run("confirmed tx spending a watched utxo", func(t *testing.T) {
		notification, err := parseTxNotification([]byte(spendConfirmedEvent), groupSource)
		require.NoError(t, err)
		require.Equal(t, &ports.TxNotification{
			Txid:              spendTxid,
			Inputs:            []ports.Utxo{watchedUtxo},
			ConfirmedAtTime:   1791393787,
			ConfirmedAtHeight: 1782,
		}, notification)
	})

	t.Run("ignores events of other tracked sources", func(t *testing.T) {
		notification, err := parseTxNotification([]byte(fundMempoolEvent), "GROUP:other")
		require.NoError(t, err)
		require.Nil(t, notification)
	})

	t.Run("ignores events that are not transactions", func(t *testing.T) {
		notification, err := parseTxNotification([]byte(newBlockEvent), groupSource)
		require.NoError(t, err)
		require.Nil(t, notification)
	})
}

func TestStripNotifiedTx(t *testing.T) {
	utxo := ports.Utxo{OutPoint: wire.OutPoint{Index: 1}, Value: 1000, Script: "script"}
	unconfirmed := func(txid string) *ports.TxNotification {
		return &ports.TxNotification{Txid: txid, Inputs: []ports.Utxo{utxo}}
	}
	confirmed := func(txid string) *ports.TxNotification {
		return &ports.TxNotification{
			Txid: txid, Outputs: []ports.Utxo{utxo}, ConfirmedAtTime: 1, ConfirmedAtHeight: 100,
		}
	}

	t.Run(
		"confirmed tx notification does not carry ins and outs if unconfirmed was notified",
		func(t *testing.T) {
			unconfirmedTxs := make(map[string]struct{})
			first := unconfirmed("tx")
			stripNotifiedTx(unconfirmedTxs, first)
			require.Equal(t, unconfirmed("tx"), first)

			mined := confirmed("tx")
			stripNotifiedTx(unconfirmedTxs, mined)
			require.Equal(t, &ports.TxNotification{
				Txid: "tx", ConfirmedAtTime: 1, ConfirmedAtHeight: 100,
			}, mined)
			require.Empty(t, unconfirmedTxs)
		},
	)

	t.Run("tx first notified as mined is reported in full", func(t *testing.T) {
		unconfirmedTxs := make(map[string]struct{})
		mined := confirmed("tx")
		stripNotifiedTx(unconfirmedTxs, mined)
		require.Equal(t, confirmed("tx"), mined)
		require.Empty(t, unconfirmedTxs)
	})

	t.Run("txs are told apart", func(t *testing.T) {
		unconfirmedTxs := make(map[string]struct{})
		stripNotifiedTx(unconfirmedTxs, unconfirmed("txA"))
		mined := confirmed("txB")
		stripNotifiedTx(unconfirmedTxs, mined)
		require.Equal(t, confirmed("txB"), mined)
		require.Len(t, unconfirmedTxs, 1)
	})

	t.Run("the set is reset once full", func(t *testing.T) {
		unconfirmedTxs := make(map[string]struct{})
		for i := range maxUnconfirmedTxs {
			stripNotifiedTx(unconfirmedTxs, unconfirmed(fmt.Sprintf("tx%d", i)))
		}
		require.Len(t, unconfirmedTxs, maxUnconfirmedTxs)
		stripNotifiedTx(unconfirmedTxs, unconfirmed("one more"))
		require.Len(t, unconfirmedTxs, 1)
		// The pending txs are reported in full once mined.
		mined := confirmed("tx0")
		stripNotifiedTx(unconfirmedTxs, mined)
		require.Equal(t, confirmed("tx0"), mined)
	})
}

// Events captured from NBXplorer for an address watched in a group: a tx funding it, seen in
// the mempool, then a tx spending it, seen once mined.
const (
	fundMempoolEvent = `{"eventId":1760,"type":"newtransaction","data":{` +
		`"blockId":null,"trackedSource":"GROUP:MrFhJe5NUUqZ8jShUy",` +
		`"transactionData":{"confirmations":0,"blockId":null,` +
		`"transactionHash":"bc10984a0e9b11cc58f1bd68bcbe66ee34add8eac3598104da30f57cf71100ce",` +
		`"height":null,"timestamp":1791393781,"replacedBy":null},` +
		`"inputs":[],` +
		`"outputs":[{"scriptPubKey":"5120787740c75564eb59971554c55d9d43076353253e445209bab7587c71d1e515a6",` +
		`"index":1,"keyIndex":0,"feature":null,"value":100000,` +
		`"address":"bcrt1p0pm5p364vn44n9c42nz4m82rqa34xff7g3fqnw4htp78r509zknqzwcxhc"}],` +
		`"replacing":[],"cryptoCode":"BTC"}}`

	spendConfirmedEvent = `{"eventId":1768,"type":"newtransaction","data":{` +
		`"blockId":"12bc3e51d8a106690b54db2b2f617d9fda803518b3e1af6e10b168ce531c6747",` +
		`"trackedSource":"GROUP:MrFhJe5NUUqZ8jShUy",` +
		`"transactionData":{"confirmations":1,` +
		`"blockId":"12bc3e51d8a106690b54db2b2f617d9fda803518b3e1af6e10b168ce531c6747",` +
		`"transactionHash":"70add375cd633cd21c428ed5b4331b21726bf53caf1e3b53ae24be2d3b9bb9bf",` +
		`"height":1782,"timestamp":1791393787,"replacedBy":null},` +
		`"inputs":[{"inputIndex":0,` +
		`"transactionId":"bc10984a0e9b11cc58f1bd68bcbe66ee34add8eac3598104da30f57cf71100ce",` +
		`"scriptPubKey":"5120787740c75564eb59971554c55d9d43076353253e445209bab7587c71d1e515a6",` +
		`"index":1,"keyIndex":0,"feature":null,"value":100000,` +
		`"address":"bcrt1p0pm5p364vn44n9c42nz4m82rqa34xff7g3fqnw4htp78r509zknqzwcxhc"}],` +
		`"outputs":[],"replacing":[],"cryptoCode":"BTC"}}`

	newBlockEvent = `{"eventId":1767,"type":"newblock","data":{"height":1782,` +
		`"hash":"12bc3e51d8a106690b54db2b2f617d9fda803518b3e1af6e10b168ce531c6747",` +
		`"confirmations":0,"cryptoCode":"BTC"}}`
)
