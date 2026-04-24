package explorer_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// testServer wraps httptest.Server with a mutable mux so each test
// can register handlers before starting the explorer.
type testServer struct {
	*httptest.Server
	mux *http.ServeMux
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &testServer{Server: srv, mux: mux}
}

func (ts *testServer) handle(pattern string, handler http.HandlerFunc) {
	ts.mux.HandleFunc(pattern, handler)
}

// jsonResponse returns a handler that writes the given status code and JSON-encodes body.
func (ts *testServer) jsonResponse(status int, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// textResponse returns a handler that writes the given status code and plain text body.
func (ts *testServer) textResponse(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// handleWS registers a WebSocket handler at /v1/ws. The onConn callback is
// called with a monotonically increasing connection number (1-based) and the
// upgraded connection. The callback is responsible for draining incoming
// messages (use keepAliveWS for a simple drain-and-block pattern).
func (ts *testServer) handleWS(onConn func(connNum int, conn *websocket.Conn)) {
	var mu sync.Mutex
	var count int
	ts.handle("/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		mu.Lock()
		count++
		n := count
		mu.Unlock()

		onConn(n, conn)
	})
}

// validTxHex returns the hex of a minimal valid Bitcoin transaction (coinbase
// with a single OP_RETURN output) suitable for passing through parseBitcoinTx.
func validTxHex(t *testing.T) string {
	t.Helper()
	tx := wire.MsgTx{Version: 1, LockTime: 0}
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: []byte{0x6a}}) // OP_RETURN
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

// keepAliveWS is a convenience WS handler that blocks until the connection is
// closed. Use it when the test doesn't care what the server does.
func keepAliveWS(_ int, conn *websocket.Conn) {
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func makeExplorer(t *testing.T, url string) explorer.Explorer {
	t.Helper()

	svc, err := mempool_explorer.NewExplorer(url, arklib.Bitcoin)
	require.NoError(t, err)
	return svc
}
