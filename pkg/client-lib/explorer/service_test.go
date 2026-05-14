package explorer_test

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	mempool "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

const wsTestAddr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

func TestGetTxHex(t *testing.T) {
	const txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handle(fmt.Sprintf("/tx/%s/hex", txid), ts.textResponse(http.StatusOK, "deadbeef"))

		svc := makeExplorer(t, ts.URL)

		got, err := svc.GetTxHex(txid)
		require.NoError(t, err)
		require.Equal(t, "deadbeef", got)
	})

	t.Run("invalid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handle(fmt.Sprintf("/tx/%s/hex", txid), ts.textResponse(
			http.StatusNotFound, "not found",
		))

		svc := makeExplorer(t, ts.URL)

		_, err := svc.GetTxHex(txid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get tx hex")
	})
}

func TestGetTxBlockTime(t *testing.T) {
	const txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handle(fmt.Sprintf("/tx/%s", txid), ts.jsonResponse(http.StatusOK, map[string]any{
			"status": map[string]any{
				"confirmed":  true,
				"block_time": int64(1700000000),
			},
		}))

		svc := makeExplorer(t, ts.URL)

		confirmed, blocktime, err := svc.GetTxBlockTime(txid)
		require.NoError(t, err)
		require.True(t, confirmed)
		require.Equal(t, int64(1700000000), blocktime)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("non-200", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/tx/%s", txid), ts.textResponse(
				http.StatusInternalServerError, "error",
			))

			svc := makeExplorer(t, ts.URL)

			_, _, err := svc.GetTxBlockTime(txid)
			require.Error(t, err)
		})

		t.Run("unconfirmed", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/tx/%s", txid), ts.jsonResponse(http.StatusOK, map[string]any{
				"status": map[string]any{"confirmed": false},
			}))

			svc := makeExplorer(t, ts.URL)

			confirmed, blocktime, err := svc.GetTxBlockTime(txid)
			require.NoError(t, err)
			require.False(t, confirmed)
			require.Equal(t, int64(-1), blocktime)
		})

		t.Run("malformed json", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/tx/%s", txid), ts.textResponse(http.StatusOK, "{not json}"))

			svc := makeExplorer(t, ts.URL)

			_, _, err := svc.GetTxBlockTime(txid)
			require.Error(t, err)
		})
	})
}

func TestGetTxOutspends(t *testing.T) {
	const txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handle(fmt.Sprintf("/tx/%s/outspends", txid), ts.jsonResponse(
			http.StatusOK, []map[string]any{
				{
					"spent": true,
					"txid":  "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				},
				{"spent": false},
			},
		))

		svc := makeExplorer(t, ts.URL)

		result, err := svc.GetTxOutspends(txid)
		require.NoError(t, err)
		require.Len(t, result, 2)
		require.True(t, result[0].Spent)
		require.Equal(
			t,
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			result[0].SpentBy,
		)
		require.False(t, result[1].Spent)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("non-200", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/tx/%s/outspends", txid), ts.textResponse(
				http.StatusNotFound, "not found",
			))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetTxOutspends(txid)
			require.Error(t, err)
		})

		t.Run("malformed json", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/tx/%s/outspends", txid), ts.textResponse(
				http.StatusOK, "[not json]",
			))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetTxOutspends(txid)
			require.Error(t, err)
		})
	})
}

func TestGetTxs(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handle(fmt.Sprintf("/address/%s/txs", addr), ts.jsonResponse(
			http.StatusOK, []map[string]any{
				{
					"txid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"vin":  []any{},
					"vout": []any{},
					"status": map[string]any{
						"confirmed":  true,
						"block_time": int64(1700000000),
					},
				},
			},
		))

		svc := makeExplorer(t, ts.URL)

		txs, err := svc.GetTxs(addr)
		require.NoError(t, err)
		require.Len(t, txs, 1)
		require.Equal(
			t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", txs[0].Txid,
		)
		require.True(t, txs[0].Status.Confirmed)
		require.Equal(t, int64(1700000000), txs[0].Status.BlockTime)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("non-200", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/address/%s/txs", addr), ts.textResponse(
				http.StatusInternalServerError, "internal error",
			))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetTxs(addr)
			require.Error(t, err)
		})

		t.Run("malformed json", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/address/%s/txs", addr), ts.textResponse(
				http.StatusOK, "[not json}",
			))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetTxs(addr)
			require.Error(t, err)
		})
	})
}

func TestGetUtxos(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handle(fmt.Sprintf("/address/%s/utxo", addr), ts.jsonResponse(
			http.StatusOK, []map[string]any{
				{
					"txid":  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					"vout":  0,
					"value": uint64(10000),
					"status": map[string]any{
						"confirmed":  true,
						"block_time": int64(1700000001),
					},
				},
			},
		))

		svc := makeExplorer(t, ts.URL)

		utxos, err := svc.GetUtxos([]string{addr})
		require.NoError(t, err)
		require.Len(t, utxos, 1)
		require.Equal(
			t, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", utxos[0].Txid,
		)
		require.Equal(t, int(10000), int(utxos[0].Amount))
		require.True(t, utxos[0].Status.Confirmed)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("empty addresses", func(t *testing.T) {
			ts := newTestServer(t)

			svc := makeExplorer(t, ts.URL)

			resp, err := svc.GetUtxos(nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "missing addresses")
			require.Nil(t, resp)
		})
		t.Run("invalid address", func(t *testing.T) {
			ts := newTestServer(t)

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetUtxos([]string{"not-a-valid-bitcoin-address"})
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid address")
		})

		t.Run("non-200", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/address/%s/utxo", addr), ts.textResponse(
				http.StatusInternalServerError, "error",
			))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetUtxos([]string{addr})
			require.Error(t, err)
		})

		t.Run("malformed json", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/address/%s/utxo", addr), ts.textResponse(
				http.StatusOK, "[not json}",
			))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetUtxos([]string{addr})
			require.Error(t, err)
		})
	})
}

func TestGetFeeRate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("populated map", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle("/fee-estimates", ts.jsonResponse(
				http.StatusOK, map[string]float64{"1": 5.5},
			))

			svc := makeExplorer(t, ts.URL)

			fee, err := svc.GetFeeRate()
			require.NoError(t, err)
			require.Equal(t, 5.5, fee)
		})

		t.Run("empty map returns 1", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle("/fee-estimates", ts.jsonResponse(http.StatusOK, map[string]float64{}))

			svc := makeExplorer(t, ts.URL)

			fee, err := svc.GetFeeRate()
			require.NoError(t, err)
			require.Equal(t, float64(1), fee)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("non-200", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle("/fee-estimates", ts.textResponse(http.StatusInternalServerError, "error"))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetFeeRate()
			require.Error(t, err)
		})

		t.Run("malformed json", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle("/fee-estimates", ts.textResponse(http.StatusOK, "not-json"))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.GetFeeRate()
			require.Error(t, err)
		})
	})
}

func TestGetRedeemedVtxosBalance(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	t.Run("valid", func(t *testing.T) {
		t.Run("confirmed utxo past delay goes to spendable", func(t *testing.T) {
			ts := newTestServer(t)
			// Block time far in the past — delay has long passed.
			pastTime := int64(1000000)
			ts.handle(fmt.Sprintf("/address/%s/utxo", addr), ts.jsonResponse(
				http.StatusOK, []map[string]any{
					{
						"txid":  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
						"vout":  0,
						"value": uint64(5000),
						"status": map[string]any{
							"confirmed":  true,
							"block_time": pastTime,
						},
					},
				},
			))

			svc := makeExplorer(t, ts.URL)

			delay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 1}
			spendable, locked, err := svc.GetRedeemedVtxosBalance(addr, delay)
			require.NoError(t, err)
			require.Equal(t, int(5000), int(spendable))
			require.Empty(t, locked)
		})

		t.Run("confirmed utxo within delay goes to locked", func(t *testing.T) {
			ts := newTestServer(t)
			// Block time far in the future — delay has NOT passed yet.
			nowTime := int64(9999999999)
			ts.handle(fmt.Sprintf("/address/%s/utxo", addr), ts.jsonResponse(
				http.StatusOK, []map[string]any{
					{
						"txid":  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
						"vout":  0,
						"value": uint64(3000),
						"status": map[string]any{
							"confirmed":  true,
							"block_time": nowTime,
						},
					},
				},
			))

			svc := makeExplorer(t, ts.URL)

			delay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
			spendable, locked, err := svc.GetRedeemedVtxosBalance(addr, delay)
			require.NoError(t, err)
			require.Equal(t, int(0), int(spendable))
			require.NotEmpty(t, locked)
			var totalLocked uint64
			for _, v := range locked {
				totalLocked += v
			}
			require.Equal(t, int(3000), int(totalLocked))
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("upstream utxo error", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle(fmt.Sprintf("/address/%s/utxo", addr), ts.textResponse(
				http.StatusInternalServerError, "error",
			))

			svc := makeExplorer(t, ts.URL)

			delay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 1}
			_, _, err := svc.GetRedeemedVtxosBalance(addr, delay)
			require.Error(t, err)
		})

		t.Run("invalid address", func(t *testing.T) {
			ts := newTestServer(t)

			svc := makeExplorer(t, ts.URL)

			delay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 1}
			_, _, err := svc.GetRedeemedVtxosBalance("not-an-address", delay)
			require.Error(t, err)
		})
	})
}

func TestBroadcast(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("single tx", func(t *testing.T) {
			ts := newTestServer(t)
			const expectedTxid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			ts.handle("/tx", ts.textResponse(http.StatusOK, expectedTxid))

			svc := makeExplorer(t, ts.URL)

			txHex := validTxHex(t)
			txid, err := svc.Broadcast(txHex)
			require.NoError(t, err)
			require.Equal(t, expectedTxid, txid)
		})

		t.Run("package", func(t *testing.T) {
			ts := newTestServer(t)
			const expectedTxid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			ts.handle("/txs/package", ts.textResponse(http.StatusOK, expectedTxid))

			svc := makeExplorer(t, ts.URL)

			txHex := validTxHex(t)
			txid, err := svc.Broadcast(txHex, txHex)
			require.NoError(t, err)
			require.Equal(t, expectedTxid, txid)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("no txs", func(t *testing.T) {
			ts := newTestServer(t)

			svc := makeExplorer(t, ts.URL)

			_, err := svc.Broadcast()
			require.Error(t, err)
			require.Contains(t, err.Error(), "no txs to broadcast")
		})

		t.Run("unparseable tx hex", func(t *testing.T) {
			ts := newTestServer(t)

			svc := makeExplorer(t, ts.URL)

			_, err := svc.Broadcast("zzznotahex")
			require.Error(t, err)
		})

		t.Run("server error on single", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle("/tx", ts.textResponse(http.StatusInternalServerError, "mempool full"))

			svc := makeExplorer(t, ts.URL)

			_, err := svc.Broadcast(validTxHex(t))
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to broadcast")
		})

		t.Run("server error on package", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handle("/txs/package", ts.textResponse(
				http.StatusInternalServerError, "package error",
			))

			svc := makeExplorer(t, ts.URL)

			txHex := validTxHex(t)
			_, err := svc.Broadcast(txHex, txHex)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to broadcast package")
		})
	})
}

func TestSubscribeForAddresses(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handleWS(keepAliveWS)

		svc := makeExplorer(t, ts.URL)
		svc.Start()
		t.Cleanup(svc.Stop)

		time.Sleep(50 * time.Millisecond)

		err := svc.SubscribeForAddresses([]string{wsTestAddr})
		require.NoError(t, err)

		require.True(t, svc.IsAddressSubscribed(wsTestAddr))
		require.Contains(t, svc.GetSubscribedAddresses(), wsTestAddr)
		require.GreaterOrEqual(t, svc.GetConnectionCount(), 1)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("duplicate address is deduplicated", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(keepAliveWS)

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)

			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))
			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))

			addrs := svc.GetSubscribedAddresses()
			count := 0
			for _, a := range addrs {
				if a == wsTestAddr {
					count++
				}
			}
			require.Equal(t, 1, count, "duplicate subscription should appear only once")
		})

		t.Run("empty list is a noop", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(keepAliveWS)

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)

			err := svc.SubscribeForAddresses([]string{})
			require.NoError(t, err)
			require.Empty(t, svc.GetSubscribedAddresses())
		})
	})
}

func TestUnsubscribeForAddresses(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handleWS(keepAliveWS)

		svc := makeExplorer(t, ts.URL)
		svc.Start()
		t.Cleanup(svc.Stop)

		time.Sleep(50 * time.Millisecond)

		require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))
		require.True(t, svc.IsAddressSubscribed(wsTestAddr))

		require.NoError(t, svc.UnsubscribeForAddresses([]string{wsTestAddr}))
		require.False(t, svc.IsAddressSubscribed(wsTestAddr))
		require.NotContains(t, svc.GetSubscribedAddresses(), wsTestAddr)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("unsubscribing non-subscribed address is a noop", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(keepAliveWS)

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)

			err := svc.UnsubscribeForAddresses(
				[]string{"bc1qnotsubscribed000000000000000000000000000"},
			)
			require.NoError(t, err, "unsubscribing unknown address must not error")
		})

		t.Run("empty list is a noop", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(keepAliveWS)

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)

			err := svc.UnsubscribeForAddresses([]string{})
			require.NoError(t, err)
		})
	})
}
func TestAddressEventReceived(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("mempool tx produces new utxo event", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				if connNum == 1 {
					time.Sleep(100 * time.Millisecond)
					payload := map[string]any{
						"multi-address-transactions": map[string]any{
							wsTestAddr: map[string]any{
								"mempool": []map[string]any{
									{
										"txid":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
										"version": 1,
										"vin":     []any{},
										"vout": []map[string]any{
											{
												"scriptpubkey_address": wsTestAddr,
												"value":                uint64(1000),
												"scriptpubkey":         "0014ee8f7d4fc3dc18a3e4fd22e0e43b90fce5e5d77d",
											},
										},
										"status": map[string]any{"confirmed": false},
									},
								},
							},
						},
					}
					_ = conn.WriteJSON(payload)
				}
				keepAliveWS(connNum, conn)
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)
			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))

			events := svc.GetAddressesEvents()
			select {
			case ev := <-events:
				require.NoError(t, ev.Error)
				require.Len(t, ev.NewUtxos, 1)
				require.Equal(
					t,
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					ev.NewUtxos[0].Outpoint.Txid,
				)
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for address event")
			}
		})

		t.Run("confirmed tx produces confirmed utxo event", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				if connNum == 1 {
					time.Sleep(100 * time.Millisecond)
					payload := map[string]any{
						"multi-address-transactions": map[string]any{
							wsTestAddr: map[string]any{
								"confirmed": []map[string]any{
									{
										"txid":    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
										"version": 1,
										"vin":     []any{},
										"vout": []map[string]any{
											{
												"scriptpubkey_address": wsTestAddr,
												"value":                uint64(2000),
												"scriptpubkey":         "0014ee8f7d4fc3dc18a3e4fd22e0e43b90fce5e5d77d",
											},
										},
										"status": map[string]any{"confirmed": true, "block_time": int64(1700000000)},
									},
								},
							},
						},
					}
					_ = conn.WriteJSON(payload)
				}
				keepAliveWS(connNum, conn)
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)
			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))

			events := svc.GetAddressesEvents()
			select {
			case ev := <-events:
				require.NoError(t, ev.Error)
				require.Len(t, ev.ConfirmedUtxos, 1)
				require.Equal(
					t,
					"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					ev.ConfirmedUtxos[0].Outpoint.Txid,
				)
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for confirmed utxo event")
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("track-addresses-error payload produces error event", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				if connNum == 1 {
					time.Sleep(100 * time.Millisecond)
					_ = conn.WriteJSON(map[string]any{
						"track-addresses-error": "address limit exceeded",
					})
				}
				keepAliveWS(connNum, conn)
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)
			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))

			events := svc.GetAddressesEvents()
			select {
			case ev := <-events:
				require.Error(t, ev.Error)
				require.Contains(t, ev.Error.Error(), "address limit exceeded")
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for error event")
			}
		})

		t.Run("unknown json payload is silently ignored", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				if connNum == 1 {
					time.Sleep(100 * time.Millisecond)
					_ = conn.WriteJSON(map[string]any{"some-unknown-key": "value"})
				}
				keepAliveWS(connNum, conn)
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(50 * time.Millisecond)
			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))

			events := svc.GetAddressesEvents()
			select {
			case ev := <-events:
				t.Fatalf("unexpected event received: %+v", ev)
			case <-time.After(500 * time.Millisecond):
				// No event within 500ms is the expected outcome.
			}
		})
	})
}

func TestReconnectionBehaviour(t *testing.T) {
	// Tests cover the three branches in trackWithWebsocket's read goroutine:
	//   1. isCloseError  → return silently (no reconnect)
	//   2. isTimeoutError → resetConnection (reconnect)
	//   3. else           → broadcast error, continue reading
	//
	// Some error types (ECONNRESET, ErrDeadlineExceeded, EPIPE) cannot be
	// reliably produced from server-side in an integration test. Their
	// classification is verified by the unit tests in utils_test.go
	// (TestIsCloseError, TestIsTimeoutError).

	t.Run("reconnectable errors (isTimeoutError)", func(t *testing.T) {
		t.Run("TCP drop without WS close frame (CloseAbnormalClosure)", func(t *testing.T) {
			subscribed := make(chan struct{}, 1)

			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				switch connNum {
				case 1:
					// Wait for the client to subscribe, then drop TCP.
					_, _, _ = conn.ReadMessage() // track-addresses
					select {
					case subscribed <- struct{}{}:
					default:
					}
					time.Sleep(20 * time.Millisecond)
					conn.UnderlyingConn().Close()
				case 2:
					// Spare connection created by addConnection — just keep alive.
					keepAliveWS(connNum, conn)
				case 3:
					// After reconnect the client resubscribes (pushAddress).
					// Read the resubscription message, then send an event to
					// prove the address was re-tracked.
					_, _, _ = conn.ReadMessage() // track-addresses (resubscription)
					time.Sleep(50 * time.Millisecond)
					payload := map[string]any{
						"multi-address-transactions": map[string]any{
							wsTestAddr: map[string]any{
								"mempool": []map[string]any{
									{
										"txid":    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
										"version": 1,
										"vin":     []any{},
										"vout": []map[string]any{
											{
												"scriptpubkey_address": wsTestAddr,
												"value":                uint64(3000),
												"scriptpubkey":         "0014ee8f7d4fc3dc18a3e4fd22e0e43b90fce5e5d77d",
											},
										},
										"status": map[string]any{"confirmed": false},
									},
								},
							},
						},
					}
					_ = conn.WriteJSON(payload)
					keepAliveWS(connNum, conn)
				default:
					keepAliveWS(connNum, conn)
				}
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			// Subscribe to an address so the connection has one when dropped.
			time.Sleep(50 * time.Millisecond)
			events := svc.GetAddressesEvents()
			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))

			// Wait for subscription to be acknowledged by server.
			select {
			case <-subscribed:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not receive subscription")
			}

			// After TCP drop + reconnect + resubscription, expect the event
			// sent by connNum==3, proving pushAddress re-tracked the address.
			select {
			case ev := <-events:
				require.NoError(t, ev.Error)
				require.Len(t, ev.NewUtxos, 1)
				require.Equal(
					t,
					"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
					ev.NewUtxos[0].Outpoint.Txid,
				)
			case <-time.After(5 * time.Second):
				t.Fatal("explorer did not receive event after reconnect + resubscription")
			}
		})

		// Note: ECONNRESET and ErrDeadlineExceeded also trigger reconnection
		// via isTimeoutError, but these cannot be reliably produced from the
		// server side in a cross-platform integration test.
		// Their classification is verified in TestIsTimeoutError (utils_test.go).
	})

	t.Run("non-reconnectable errors (isCloseError)", func(t *testing.T) {
		t.Run("CloseNormalClosure", func(t *testing.T) {
			var mu sync.Mutex
			connCount := 0

			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				mu.Lock()
				connCount++
				mu.Unlock()

				if connNum == 1 {
					time.Sleep(20 * time.Millisecond)
					_ = conn.WriteMessage(
						websocket.CloseMessage,
						websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shutting down"),
					)
					_ = conn.Close()
				}
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(500 * time.Millisecond)

			mu.Lock()
			final := connCount
			mu.Unlock()
			require.Equal(t, 1, final, "CloseNormalClosure must not trigger reconnect")
		})

		t.Run("CloseGoingAway", func(t *testing.T) {
			var mu sync.Mutex
			connCount := 0

			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				mu.Lock()
				connCount++
				mu.Unlock()

				if connNum == 1 {
					time.Sleep(20 * time.Millisecond)
					_ = conn.WriteMessage(
						websocket.CloseMessage,
						websocket.FormatCloseMessage(
							websocket.CloseGoingAway, "server shutting down",
						),
					)
					_ = conn.Close()
				}
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			time.Sleep(500 * time.Millisecond)

			mu.Lock()
			final := connCount
			mu.Unlock()
			require.Equal(t, 1, final, "CloseGoingAway must not trigger reconnect")
		})

		// Note: net.ErrClosed and context.Canceled also pass isCloseError, but
		// they occur when the client itself calls Stop() (locally-closed socket
		// and context cancellation). These are covered by TestStopClearsSubscriptions.
		//
		// EPIPE is handled in the ping goroutine (write path), not the read
		// goroutine, so it does not affect reconnection decisions.
		// Its classification is verified in TestIsCloseError (utils_test.go).
	})

	t.Run("unknown errors (else branch)", func(t *testing.T) {
		t.Run("malformed JSON broadcasts error but keeps reading", func(t *testing.T) {
			// Errors that don't match isCloseError or isTimeoutError land in
			// the else branch: the error is broadcast to listeners but the read
			// goroutine continues processing the next message. We verify this by:
			//   1. Server sends invalid JSON → ReadJSON returns a decode error.
			//   2. Client broadcasts an error event (decode error).
			//   3. Server then sends a valid event → client processes it normally.
			//   4. No reconnection occurs (connCount stays at 2 — one subscribed, one spare).
			var mu sync.Mutex
			connCount := 0

			ts := newTestServer(t)
			ts.handleWS(func(connNum int, conn *websocket.Conn) {
				mu.Lock()
				connCount++
				mu.Unlock()

				if connNum == 1 {
					// Wait long enough for the test to call SubscribeForAddresses
					// AND block on <-events, so the broadcast doesn't drop.
					time.Sleep(200 * time.Millisecond)

					// Send malformed JSON — ReadJSON will return a json.Decode error.
					_ = conn.WriteMessage(websocket.TextMessage, []byte("not valid json {{{"))

					// Then send a valid event to prove the goroutine kept reading.
					time.Sleep(50 * time.Millisecond)
					_ = conn.WriteJSON(map[string]any{
						"multi-address-transactions": map[string]any{
							wsTestAddr: map[string]any{
								"mempool": []map[string]any{
									{
										"txid":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
										"version": 1,
										"vin":     []any{},
										"vout": []map[string]any{
											{
												"scriptpubkey_address": wsTestAddr,
												"value":                uint64(1000),
												"scriptpubkey":         "0014abcd",
											},
										},
										"status": map[string]any{"confirmed": false},
									},
								},
							},
						},
					})
				}
				keepAliveWS(connNum, conn)
			})

			svc := makeExplorer(t, ts.URL)
			svc.Start()
			t.Cleanup(svc.Stop)

			// Register the listener BEFORE subscribing so we don't miss
			// events that are broadcast shortly after the connection is created.
			events := svc.GetAddressesEvents()

			time.Sleep(50 * time.Millisecond)
			require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))

			// First event: the error from malformed JSON.
			select {
			case ev := <-events:
				require.Error(t, ev.Error, "malformed JSON should produce an error event")
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for error event from malformed JSON")
			}

			// Second event: the valid address event, proving the goroutine continued.
			select {
			case ev := <-events:
				require.NoError(t, ev.Error)
				require.Len(t, ev.NewUtxos, 1)
			case <-time.After(3 * time.Second):
				t.Fatal(
					"timed out waiting for valid event after malformed JSON - " +
						"goroutine didn't continue",
				)
			}

			// Verify no reconnect happened.
			// connCount is 2 because SubscribeForAddresses creates a spare
			// connection after pushAddress (pool expansion, not reconnect).
			mu.Lock()
			final := connCount
			mu.Unlock()
			require.Equal(t, 2, final, "non-fatal error must not trigger reconnect")
		})
	})
}

func TestStopClearsSubscriptions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handleWS(keepAliveWS)

		svc := makeExplorer(t, ts.URL)
		svc.Start()

		time.Sleep(50 * time.Millisecond)
		require.NoError(t, svc.SubscribeForAddresses([]string{wsTestAddr}))
		require.True(t, svc.IsAddressSubscribed(wsTestAddr))

		svc.Stop()

		require.Empty(t, svc.GetSubscribedAddresses())
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("stop when already stopped is a noop", func(t *testing.T) {
			ts := newTestServer(t)
			ts.handleWS(keepAliveWS)

			svc := makeExplorer(t, ts.URL)
			svc.Start()

			time.Sleep(50 * time.Millisecond)
			svc.Stop()
			require.NotPanics(t, func() { svc.Stop() })
		})
	})
}

func TestStartIsIdempotent(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ts := newTestServer(t)
		ts.handleWS(keepAliveWS)

		svc := makeExplorer(t, ts.URL)

		svc.Start()
		t.Cleanup(svc.Stop)
		time.Sleep(50 * time.Millisecond)

		countAfterFirst := svc.GetConnectionCount()
		require.GreaterOrEqual(t, countAfterFirst, 1)

		svc.Start()
		time.Sleep(50 * time.Millisecond)

		require.Equal(t, countAfterFirst, svc.GetConnectionCount())
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("start when noTracking is set is always a noop", func(t *testing.T) {
			ts := newTestServer(t)

			svc, err := mempool.NewExplorer(ts.URL, arklib.Bitcoin, mempool.WithTracker(false))
			require.NoError(t, err)

			require.NotPanics(t, func() { svc.Start() })
			require.Equal(t, 0, svc.GetConnectionCount())
		})
	})
}
