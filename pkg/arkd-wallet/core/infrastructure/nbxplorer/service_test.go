package nbxplorer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
