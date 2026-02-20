package mempool_explorer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
)

func parseBitcoinTx(txStr string) (string, string, error) {
	var tx wire.MsgTx

	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txStr))); err != nil {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(txStr), true)
		if err != nil {
			return "", "", err
		}

		txFromPartial, err := psbt.Extract(ptx)
		if err != nil {
			return "", "", err
		}

		tx = *txFromPartial
	}

	var txBuf bytes.Buffer

	if err := tx.Serialize(&txBuf); err != nil {
		return "", "", err
	}

	txhex := hex.EncodeToString(txBuf.Bytes())
	txid := tx.TxHash().String()

	return txhex, txid, nil
}

func deriveWsURL(baseUrl string) (string, error) {
	var wsUrl string

	parsedUrl, err := url.Parse(baseUrl)
	if err != nil {
		return "", err
	}

	scheme := "ws"
	if parsedUrl.Scheme == "https" {
		scheme = "wss"
	}
	parsedUrl.Scheme = scheme
	wsUrl = strings.TrimRight(parsedUrl.String(), "/")

	wsUrl = fmt.Sprintf("%s/v1/ws", wsUrl)

	return wsUrl, nil
}

// isCloseError determines if an error indicates a permanent connection close.
// It returns true for websocket close codes, net.ErrClosed, and context cancellation.
func isCloseError(err error) bool {
	// Check for explicit websocket close errors
	if websocket.IsCloseError(
		err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseAbnormalClosure,
	) {
		return true
	}

	// Check for closed connection
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	// Check for context cancelation
	if errors.Is(err, context.Canceled) {
		return true
	}

	return false
}

// isTimeoutError determines if an error indicates a timeout.
func isTimeoutError(err error) bool {
	// Check for timeout/deadline errors (network disconnection)
	// First check with os.IsTimeout (doesn't unwrap)
	if os.IsTimeout(err) {
		return true
	}
	// Then check wrapped errors for timeout interface
	var timeoutErr interface{ Timeout() bool }
	if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// All other errors are potentially temporary (should retry with circuit breaker)
	return false
}
