package nbxplorer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/stretchr/testify/require"
)

const (
	testGroupID = "test-group-id"
	testTxID    = "0000000000000000000000000000000000000000000000000000000000000001"
)

func testScript() string {
	return "5120" + strings.Repeat("11", 32)
}

// newTransactionEventJSON builds a raw websocket "newtransaction" event message
// with the given tracked source, transaction id, confirmation count and outputs
// JSON array.
func newTransactionEventJSON(
	trackedSource, txid string, confirmations uint32, outputs string,
) []byte {
	return []byte(fmt.Sprintf(
		`{"type":"newtransaction","eventId":1,"data":{`+
			`"trackedSource":%q,"cryptoCode":"BTC",`+
			`"transactionData":{"transactionHash":%q,"confirmations":%d,"timestamp":1700000000},`+
			`"outputs":%s}}`,
		trackedSource, txid, confirmations, outputs,
	))
}

func output(script, address string, index, value uint64, keyPath string) string {
	kp := ""
	if keyPath != "" {
		kp = fmt.Sprintf(`"keyPath":%q,`, keyPath)
	}
	return fmt.Sprintf(
		`{%s"scriptPubKey":%q,"index":%d,"keyIndex":0,"value":%d,"address":%q}`,
		kp, script, index, value, address,
	)
}

func TestGroupTrackedSource(t *testing.T) {
	require.Equal(t, "GROUP:abc", groupTrackedSource("abc"))
}

func TestUtxosFromTransactionEvent(t *testing.T) {
	script := testScript()
	groupTS := groupTrackedSource(testGroupID)

	t.Run("group match single output", func(t *testing.T) {
		msg := newTransactionEventJSON(
			groupTS, testTxID, 3, "["+output(script, "bcrt1paddr", 1, 100000, "")+"]",
		)

		utxos, err := utxosFromTransactionEvent(msg, testGroupID)
		require.NoError(t, err)
		require.Len(t, utxos, 1)

		u := utxos[0]
		require.Equal(t, testTxID, u.OutPoint.Hash.String())
		require.Equal(t, uint32(1), u.OutPoint.Index)
		require.Equal(t, uint64(100000), u.Value)
		require.Equal(t, script, u.Script)
		require.Equal(t, "bcrt1paddr", u.Address)
		require.Equal(t, uint32(3), u.Confirmations)
		require.Empty(t, u.KeyPath)
	})

	t.Run("group match empty outputs", func(t *testing.T) {
		msg := newTransactionEventJSON(groupTS, testTxID, 0, "[]")

		utxos, err := utxosFromTransactionEvent(msg, testGroupID)
		require.NoError(t, err)
		require.Empty(t, utxos)
	})

	t.Run("group match multiple outputs", func(t *testing.T) {
		outputs := "[" +
			output(script, "addr0", 0, 1000, "") + "," +
			output(script, "addr1", 1, 2000, "") + "]"
		msg := newTransactionEventJSON(groupTS, testTxID, 0, outputs)

		utxos, err := utxosFromTransactionEvent(msg, testGroupID)
		require.NoError(t, err)
		require.Len(t, utxos, 2)
		require.Equal(t, uint32(0), utxos[0].OutPoint.Index)
		require.Equal(t, uint32(1), utxos[1].OutPoint.Index)
		require.Equal(t, uint64(1000), utxos[0].Value)
		require.Equal(t, uint64(2000), utxos[1].Value)
	})

	t.Run("keypath carried through", func(t *testing.T) {
		msg := newTransactionEventJSON(
			groupTS, testTxID, 0, "["+output(script, "addr", 0, 1000, "0/5")+"]",
		)

		utxos, err := utxosFromTransactionEvent(msg, testGroupID)
		require.NoError(t, err)
		require.Len(t, utxos, 1)
		require.Equal(t, "0/5", utxos[0].KeyPath)
	})

	t.Run("different group is ignored", func(t *testing.T) {
		msg := newTransactionEventJSON(
			"GROUP:some-other-group", testTxID, 0,
			"["+output(script, "addr", 0, 1000, "")+"]",
		)

		utxos, err := utxosFromTransactionEvent(msg, testGroupID)
		require.NoError(t, err)
		require.Empty(t, utxos)
	})

	t.Run("derivation scheme tracked source is ignored", func(t *testing.T) {
		msg := newTransactionEventJSON(
			"DERIVATIONSCHEME:xpub-[taproot]", testTxID, 0,
			"["+output(script, "addr", 0, 1000, "")+"]",
		)

		utxos, err := utxosFromTransactionEvent(msg, testGroupID)
		require.NoError(t, err)
		require.Empty(t, utxos)
	})

	t.Run("non-newtransaction event is ignored", func(t *testing.T) {
		msg := []byte(`{"type":"newblock","data":{"height":100,"hash":"abc"}}`)

		utxos, err := utxosFromTransactionEvent(msg, testGroupID)
		require.NoError(t, err)
		require.Empty(t, utxos)
	})

	t.Run("invalid json returns error", func(t *testing.T) {
		_, err := utxosFromTransactionEvent([]byte("not json"), testGroupID)
		require.Error(t, err)
	})

	t.Run("invalid transaction hash returns error", func(t *testing.T) {
		msg := newTransactionEventJSON(
			groupTS, "not-a-hash", 0, "["+output(script, "addr", 0, 1000, "")+"]",
		)

		_, err := utxosFromTransactionEvent(msg, testGroupID)
		require.Error(t, err)
	})
}

func TestCastUtxoCarriesKeyPath(t *testing.T) {
	u := utxoResponse{
		TransactionHash: testTxID,
		Index:           2,
		ScriptPubKey:    testScript(),
		Address:         "bcrt1paddr",
		Value:           5000,
		KeyPath:         "1/9",
		Confirmations:   3,
	}

	utxo, err := castUtxo(u)
	require.NoError(t, err)
	require.Equal(t, "1/9", utxo.KeyPath)
	require.Equal(t, uint32(2), utxo.OutPoint.Index)
	require.Equal(t, uint64(5000), utxo.Value)
	require.Equal(t, uint32(3), utxo.Confirmations)
}

// fetchAndFilterGroupUtxos replicates the previous (pre-optimization) behavior:
// on every event it fetched the whole group UTXO set over HTTP and filtered it
// client-side by transaction hash. It is kept here only as a benchmark baseline.
func fetchAndFilterGroupUtxos(client *http.Client, url, txHash string) ([]ports.Utxo, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var r utxosResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	utxos := make([]ports.Utxo, 0)
	for _, u := range r.Confirmed.UtxOs {
		if u.TransactionHash != txHash {
			continue
		}
		utxo, err := castUtxo(u)
		if err != nil {
			continue
		}
		utxos = append(utxos, utxo)
	}
	for _, u := range r.Unconfirmed.UtxOs {
		if u.TransactionHash != txHash {
			continue
		}
		utxo, err := castUtxo(u)
		if err != nil {
			continue
		}
		utxos = append(utxos, utxo)
	}
	return utxos, nil
}

func buildGroupUtxosBody(n int, matchTxHash string) []byte {
	var resp utxosResponse
	resp.Confirmed.UtxOs = make([]utxoResponse, 0, n)
	for i := 0; i < n; i++ {
		// offset by 2 so no filler hash collides with matchTxHash (which is 0x..01)
		resp.Confirmed.UtxOs = append(resp.Confirmed.UtxOs, utxoResponse{
			TransactionHash: fmt.Sprintf("%064x", i+2),
			Index:           0,
			ScriptPubKey:    testScript(),
			Address:         "bcrt1paddr",
			Value:           1000,
			Confirmations:   1,
		})
	}
	if n > 0 {
		resp.Confirmed.UtxOs[n-1].TransactionHash = matchTxHash
	}
	b, _ := json.Marshal(resp)
	return b
}

// BenchmarkNotificationProcessing compares the per-event work of the new
// event-payload parsing against the old approach of fetching and filtering the
// whole group UTXO set. The old approach scales with the group size; the new one
// does not depend on it and performs no network round trip.
func BenchmarkNotificationProcessing(b *testing.B) {
	eventMsg := newTransactionEventJSON(
		groupTrackedSource(testGroupID), testTxID, 0,
		"["+output(testScript(), "bcrt1paddr", 1, 100000, "")+"]",
	)

	b.Run("event-parse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			utxos, err := utxosFromTransactionEvent(eventMsg, testGroupID)
			if err != nil || len(utxos) != 1 {
				b.Fatalf("unexpected result: %v %v", utxos, err)
			}
		}
	})

	for _, n := range []int{10, 100, 1000, 10000} {
		body := buildGroupUtxosBody(n, testTxID)
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			},
		))
		client := srv.Client()

		b.Run(fmt.Sprintf("http-fetch-group-size-%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				utxos, err := fetchAndFilterGroupUtxos(client, srv.URL, testTxID)
				if err != nil || len(utxos) != 1 {
					b.Fatalf("unexpected result: %v %v", utxos, err)
				}
			}
		})

		srv.Close()
	}
}
