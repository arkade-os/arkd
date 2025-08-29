package nbxplorer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

const (
	// Default cryptocode for Bitcoin
	btcCryptoCode = "BTC"
)

var ErrTransactionNotFound = errors.New("transaction not found")

type nbxplorer struct {
	url           string
	httpClient    *http.Client
	minRelayTxFee chainfee.SatPerKVByte

	// WebSocket connection for BlockchainScanner watch events
	wsConn   *websocket.Conn
	wsMutex  sync.RWMutex
	wsDialer websocket.Dialer

	// inmemory groupID of the blockchain scanner
	// all addresses watch by WatchAddress are grouped by this ID
	groupID string
}

func New(url string) (ports.Nbxplorer, error) {
	url = strings.TrimSuffix(url, "/")

	svc := &nbxplorer{
		url:        url,
		httpClient: &http.Client{},
		wsDialer:   websocket.Dialer{},
		wsMutex:    sync.RWMutex{},
		wsConn:     nil,
		groupID:    "",
	}

	status, err := svc.GetBitcoinStatus(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nbxplorer: %s", err)
	}

	svc.minRelayTxFee = status.MinRelayTxFee

	return svc, nil
}

// GetBitcoinStatus retrieves Bitcoin network status from /v1/cryptos/{cryptoCode}/status endpoint.
func (n *nbxplorer) GetBitcoinStatus(ctx context.Context) (*ports.BitcoinStatus, error) {
	data, err := n.makeRequest(ctx, "GET", fmt.Sprintf("/v1/cryptos/%s/status", btcCryptoCode), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get bitcoin status: %w", err)
	}

	var resp bitcoinStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bitcoin status: %w", err)
	}

	// use getblockchaininfo to get the tip timestamp
	rpcReq := rpcRequest{
		JSONRPC: "1.0",
		// #nosec G404
		ID:     rand.Intn(10_0000),
		Method: "getblockchaininfo",
		Params: []any{},
	}

	jsonBody, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	rpcData, err := n.makeRequest(ctx, "POST", fmt.Sprintf("/v1/cryptos/%s/rpc", btcCryptoCode), strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to call submitpackage RPC: %w", err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(rpcData, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal RPC response: %w", err)
	}

	blockchainInfoJSON, err := json.Marshal(rpcResp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RPC result: %w", err)
	}

	var blockchainInfo blockchainInfoResponse
	if err := json.Unmarshal(blockchainInfoJSON, &blockchainInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal blockchain info: %w", err)
	}

	return &ports.BitcoinStatus{
		ChainTipHeight: resp.BitcoinStatus.Blocks,
		ChainTipTime:   blockchainInfo.Mediantime,
		Synced:         resp.BitcoinStatus.IsSynced,
		MinRelayTxFee:  chainfee.SatPerKVByte(resp.BitcoinStatus.MinRelayTxFee * 1000),
	}, nil
}

// GetTransaction retrieves transaction details from /v1/cryptos/{cryptoCode}/transactions/{txId} endpoint.
func (n *nbxplorer) GetTransaction(ctx context.Context, txid string) (*ports.TransactionDetails, error) {
	if txid == "" {
		return nil, fmt.Errorf("transaction ID cannot be empty")
	}
	if _, err := chainhash.NewHashFromStr(txid); err != nil {
		return nil, fmt.Errorf("invalid txid format: %w", err)
	}

	data, err := n.makeRequest(ctx, "GET", fmt.Sprintf("/v1/cryptos/%s/transactions/%s", btcCryptoCode, txid), nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, ErrTransactionNotFound
		}
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	var resp transactionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	return &ports.TransactionDetails{
		TxID:          resp.TransactionId,
		Hex:           resp.Transaction,
		Height:        resp.Height,
		Timestamp:     resp.Timestamp,
		Confirmations: resp.Confirmations,
	}, nil
}

// ScanUtxoSet initiates UTXO set scan from /v1/cryptos/{cryptoCode}/derivations/{scheme}/utxos/scan endpoint.
func (n *nbxplorer) ScanUtxoSet(ctx context.Context, derivationScheme string, gapLimit int) <-chan ports.ScanUtxoSetProgress {
	progressChan := make(chan ports.ScanUtxoSetProgress)

	go func() {
		defer close(progressChan)

		if err := n.validateDerivationScheme(derivationScheme); err != nil {
			progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
			return
		}

		if gapLimit <= 0 {
			gapLimit = 10000
		}

		endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/utxos/scan?gapLimit=%d", btcCryptoCode, url.PathEscape(derivationScheme), gapLimit)

		_, err := n.makeRequest(ctx, "POST", endpoint, nil)
		if err != nil {
			progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
			return
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
				return
			case <-ticker.C:
				progressEndpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/utxos/scan/status", btcCryptoCode, url.PathEscape(derivationScheme))
				data, err := n.makeRequest(ctx, "GET", progressEndpoint, nil)
				if err != nil {
					progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
					return
				}

				var resp scanProgressResponse
				if err := json.Unmarshal(data, &resp); err != nil {
					progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
					return
				}

				var progress int
				var done bool
				switch resp.Status {
				case "Complete":
					progress = 100
					done = true
				case "Error":
					progress = 0
					done = true
				case "Pending":
					if resp.Progress != nil {
						progress = int(resp.Progress.OverallProgress)
					} else {
						progress = 0
					}
					done = false
				default:
					progress = 0
					done = false
				}

				select {
				case progressChan <- ports.ScanUtxoSetProgress{
					Progress: progress,
					Done:     done,
				}:
				case <-ctx.Done():
					return
				}

				if done {
					return
				}
			}
		}
	}()

	return progressChan
}

// Track starts monitoring a derivation scheme from /v1/cryptos/{cryptoCode}/derivations/{scheme} endpoint.
func (n *nbxplorer) Track(ctx context.Context, derivationScheme string) error {
	if err := n.validateDerivationScheme(derivationScheme); err != nil {
		return fmt.Errorf("invalid derivation scheme: %w", err)
	}

	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s", btcCryptoCode, url.PathEscape(derivationScheme))
	log.Debugf("Tracking derivation scheme: %s", endpoint)
	_, err := n.makeRequest(ctx, "POST", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to track derivation scheme: %w", err)
	}
	return nil
}

// GetUtxos retrieves UTXOs from /v1/cryptos/{cryptoCode}/derivations/{scheme}/utxos endpoint.
func (n *nbxplorer) GetUtxos(ctx context.Context, derivationScheme string) ([]ports.Utxo, error) {
	if err := n.validateDerivationScheme(derivationScheme); err != nil {
		return nil, fmt.Errorf("invalid derivation scheme: %w", err)
	}

	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/utxos", btcCryptoCode, url.PathEscape(derivationScheme))
	data, err := n.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get utxos: %w", err)
	}

	var resp utxosResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal utxos: %w", err)
	}

	spentOutpoints := make(map[string]bool)
	for _, outpoint := range resp.Confirmed.SpentOutpoints {
		spentOutpoints[outpoint] = true
	}
	for _, outpoint := range resp.Unconfirmed.SpentOutpoints {
		spentOutpoints[outpoint] = true
	}

	utxos := make([]ports.Utxo, 0, len(resp.Confirmed.UtxOs)+len(resp.Unconfirmed.UtxOs))

	for _, u := range resp.Confirmed.UtxOs {
		if spentOutpoints[u.Outpoint] {
			continue
		}

		utxo, err := castUtxo(u)
		if err != nil {
			log.Errorf("failed to cast UTXO: %s", err)
			continue
		}

		utxos = append(utxos, utxo)
	}

	for _, u := range resp.Unconfirmed.UtxOs {
		if spentOutpoints[u.Outpoint] {
			continue
		}

		utxo, err := castUtxo(u)
		if err != nil {
			log.Errorf("failed to cast UTXO: %s", err)
			continue
		}

		utxos = append(utxos, utxo)
	}

	return utxos, nil
}

// GetScriptPubKeyDetails retrieves key path from /v1/cryptos/{cryptoCode}/derivations/{scheme}/scripts/{script} endpoint.
func (n *nbxplorer) GetScriptPubKeyDetails(ctx context.Context, derivationScheme string, script string) (*ports.ScriptPubKeyDetails, error) {
	if err := n.validateDerivationScheme(derivationScheme); err != nil {
		return nil, fmt.Errorf("invalid derivation scheme: %w", err)
	}

	if script == "" {
		return nil, fmt.Errorf("script cannot be empty")
	}

	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/scripts/%s", btcCryptoCode, url.PathEscape(derivationScheme), url.PathEscape(script))
	data, err := n.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get script pubkey details: %w", err)
	}

	var resp scriptPubKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal script pubkey details: %w", err)
	}

	return &ports.ScriptPubKeyDetails{
		KeyPath: resp.KeyPath,
	}, nil
}

// GetNewUnusedAddress generates new address from /v1/cryptos/{cryptoCode}/derivations/{scheme}/addresses/unused endpoint.
func (n *nbxplorer) GetNewUnusedAddress(ctx context.Context, derivationScheme string, change bool, skip int) (string, error) {
	if err := n.validateDerivationScheme(derivationScheme); err != nil {
		return "", fmt.Errorf("invalid derivation scheme: %w", err)
	}

	if skip < 0 {
		skip = 0
	}

	params := url.Values{}
	if change {
		params.Set("feature", "Change")
	} else {
		params.Set("feature", "Deposit")
	}
	if skip > 0 {
		params.Set("skip", strconv.Itoa(skip))
	}

	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/addresses/unused", btcCryptoCode, url.PathEscape(derivationScheme))
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	data, err := n.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get new unused address: %w", err)
	}

	var resp addressResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("failed to unmarshal address: %w", err)
	}

	if resp.Address == "" {
		return "", fmt.Errorf("received empty address from API")
	}

	return resp.Address, nil
}

// EstimateFeeRate retrieves fee rate from /v1/cryptos/{cryptoCode}/fees/{blockCount} endpoint.
func (n *nbxplorer) EstimateFeeRate(ctx context.Context) (chainfee.SatPerKVByte, error) {
	blockCount := 1
	data, err := n.makeRequest(ctx, "GET", fmt.Sprintf("/v1/cryptos/%s/fees/%d", btcCryptoCode, blockCount), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate fee rate: %w", err)
	}

	var resp feeRateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, fmt.Errorf("failed to unmarshal fee rate: %w", err)
	}

	if resp.FeeRate <= 0 {
		return 0, fmt.Errorf("invalid fee rate received: %f", resp.FeeRate)
	}

	satPerKvB := chainfee.SatPerKVByte(resp.FeeRate * 1000)
	return max(satPerKvB, n.minRelayTxFee), nil
}

// IsSpent checks if an outpoint is spent by proxying the RPC "gettxout" to Bitcoin Core
func (n *nbxplorer) IsSpent(ctx context.Context, outpoint wire.OutPoint) (spent bool, err error) {
	// bitcoin core RPC request for gettxout
	rpcReq := rpcRequest{
		JSONRPC: "1.0",
		// #nosec G404
		ID:     rand.Intn(10_0000),
		Method: "gettxout",
		Params: []any{outpoint.Hash.String(), outpoint.Index},
	}

	jsonBody, err := json.Marshal(rpcReq)
	if err != nil {
		return false, fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	data, err := n.makeRequest(ctx, "POST", fmt.Sprintf("/v1/cryptos/%s/rpc", btcCryptoCode), strings.NewReader(string(jsonBody)))
	if err != nil {
		return false, fmt.Errorf("failed to call gettxout RPC: %w", err)
	}

	var resp rpcResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, fmt.Errorf("failed to unmarshal RPC response: %w", err)
	}

	if resp.Error != nil {
		return false, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return resp.Result == nil, nil
}

// BroadcastTransaction broadcasts transaction(s) via different methods based on count:
// - 1 transaction: use NBXplorer broadcast endpoint
// - 2 transactions: use Bitcoin Core submitpackage RPC via NBXplorer proxy
func (n *nbxplorer) BroadcastTransaction(ctx context.Context, txs ...string) (string, error) {
	txCount := len(txs)

	switch txCount {
	case 0:
		return "", fmt.Errorf("no transactions provided")
	case 1:
		return n.broadcastSingleTransaction(ctx, txs[0])
	case 2:
		return n.broadcastPackageTransactions(ctx, txs)
	default:
		return "", fmt.Errorf("unsupported transaction count: %d (only 1 or 2 transactions supported)", txCount)
	}
}

// broadcastSingleTransaction broadcasts a single transaction using NBXplorer's broadcast endpoint
func (n *nbxplorer) broadcastSingleTransaction(ctx context.Context, txHex string) (string, error) {
	if txHex == "" {
		return "", fmt.Errorf("transaction hex cannot be empty")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.url+fmt.Sprintf("/v1/cryptos/%s/transactions", btcCryptoCode), hex.NewDecoder(strings.NewReader(txHex)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var broadcastResult broadcastResult
	if err := json.Unmarshal(bodyBytes, &broadcastResult); err != nil {
		return "", fmt.Errorf("failed to unmarshal broadcast result: %w", err)
	}

	if !broadcastResult.Success {
		// Construct error message from RPC details
		errorMsg := "broadcast failed"
		if broadcastResult.RPCMessage != "" {
			errorMsg = broadcastResult.RPCMessage
		}
		if broadcastResult.RPCCodeMessage != "" {
			errorMsg = fmt.Sprintf("%s (code: %s)", errorMsg, broadcastResult.RPCCodeMessage)
		}
		if broadcastResult.RPCCode != nil {
			errorMsg = fmt.Sprintf("%s (RPC code: %d)", errorMsg, *broadcastResult.RPCCode)
		}
		return "", fmt.Errorf("%s", errorMsg)
	}

	// if success, parse the transaction to return the txid
	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))); err != nil {
		return "", fmt.Errorf("failed to deserialize transaction: %w", err)
	}
	return tx.TxHash().String(), nil
}

// broadcastPackageTransactions broadcasts a package of 2 transactions using Bitcoin Core submitpackage RPC
func (n *nbxplorer) broadcastPackageTransactions(ctx context.Context, txs []string) (string, error) {
	if len(txs) != 2 {
		return "", fmt.Errorf("expected exactly 2 transactions, got %d", len(txs))
	}

	for i, txHex := range txs {
		if txHex == "" {
			return "", fmt.Errorf("transaction hex at index %d cannot be empty", i)
		}
	}

	// bitcoin core RPC request for submitpackage
	rpcReq := rpcRequest{
		JSONRPC: "1.0",
		// #nosec G404
		ID:     rand.Intn(10_0000),
		Method: "submitpackage",
		Params: []any{txs},
	}

	jsonBody, err := json.Marshal(rpcReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	data, err := n.makeRequest(ctx, "POST", fmt.Sprintf("/v1/cryptos/%s/rpc", btcCryptoCode), strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", fmt.Errorf("failed to call submitpackage RPC: %w", err)
	}

	var resp rpcResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("failed to unmarshal RPC response: %w", err)
	}

	if resp.Error != nil {
		return "", fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	if resp.Result == nil {
		return "", fmt.Errorf("RPC returned nil result")
	}

	resultBytes, err := json.Marshal(resp.Result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal RPC result: %w", err)
	}

	return string(resultBytes), nil
}

// WatchAddresses adds addresses to group via /v1/cryptos/{cryptoCode}/groups/{groupID}/addresses endpoint.
func (n *nbxplorer) WatchAddresses(ctx context.Context, addresses ...string) error {
	if len(n.groupID) == 0 {
		if err := n.createEmptyGroup(ctx); err != nil {
			return fmt.Errorf("failed to create empty group: %w", err)
		}
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no addresses provided")
	}

	for _, addr := range addresses {
		if addr == "" {
			return fmt.Errorf("address cannot be empty")
		}
	}

	jsonBody, err := json.Marshal(addresses)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	endpoint := fmt.Sprintf("/v1/cryptos/%s/groups/%s/addresses", btcCryptoCode, url.PathEscape(n.groupID))
	_, err = n.makeRequest(ctx, "POST", endpoint, strings.NewReader(string(jsonBody)))
	if err != nil {
		return fmt.Errorf("failed to add addresses to group: %w", err)
	}
	return nil
}

// UnwatchAddresses removes addresses from group via DELETE /v1/groups/{groupID}/children/delete endpoint.
func (n *nbxplorer) UnwatchAddresses(ctx context.Context, addresses ...string) error {
	if len(n.groupID) == 0 {
		return fmt.Errorf("group ID is not set")
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no addresses provided")
	}

	if slices.Contains(addresses, "") {
		return fmt.Errorf("address cannot be empty")
	}

	trackedSources := make([]trackedSource, 0, len(addresses))
	for _, addr := range addresses {
		trackedSources = append(trackedSources, trackedSource{
			TrackedSource: fmt.Sprintf("ADDRESS:%s", addr),
			CryptoCode:    btcCryptoCode,
		})
	}

	jsonBody, err := json.Marshal(trackedSources)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	endpoint := fmt.Sprintf("/v1/groups/%s/children", url.PathEscape(n.groupID))
	_, err = n.makeRequest(ctx, "DELETE", endpoint, strings.NewReader(string(jsonBody)))
	if err != nil {
		return fmt.Errorf("failed to remove addresses from group: %w", err)
	}
	return nil
}

// GetGroupNotifications monitors group UTXOs using WebSocket events and triggers UTXO rescanning
// only when receiving "newtransaction" events. Returns only UTXOs from the specific new transaction.
func (n *nbxplorer) GetAddressNotifications(ctx context.Context) (<-chan []ports.Utxo, error) {
	if len(n.groupID) == 0 {
		if err := n.createEmptyGroup(ctx); err != nil {
			return nil, fmt.Errorf("failed to create empty group: %w", err)
		}
	}

	// buffered channel to prevent blocking
	notificationsChan := make(chan []ports.Utxo, 64)

	go func() {
		defer close(notificationsChan)

		if err := n.connectWebSocket(ctx); err != nil {
			log.Errorf("failed to connect to WebSocket: %s", err)
			return
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, message, err := n.wsConn.ReadMessage()
				if err != nil {
					// reconnect on error
					if err := n.connectWebSocket(ctx); err != nil {
						log.Errorf("failed to connect to WebSocket: %s", err)
						return
					}
					continue
				}

				var event event
				if err := json.Unmarshal(message, &event); err != nil {
					continue
				}

				if event.Type == "newtransaction" {
					var newTxEvent newTransactionEvent
					if eventDataBytes, err := json.Marshal(event.Data); err == nil {
						if err := json.Unmarshal(eventDataBytes, &newTxEvent); err == nil {
							newUtxos, err := n.searchNewUTXOs(ctx, newTxEvent.TransactionData.TransactionHash)
							if err != nil {
								continue
							}

							if len(newUtxos) > 0 {
								select {
								case notificationsChan <- newUtxos:
								case <-ctx.Done():
									return
								}
							}
						}
					}
				}
			}
		}
	}()

	return notificationsChan, nil
}

func (n *nbxplorer) Close() error {
	n.wsMutex.Lock()
	defer n.wsMutex.Unlock()

	if n.wsConn != nil {
		return n.wsConn.Close()
	}

	// delete the groupID
	if len(n.groupID) > 0 {
		_, err := n.makeRequest(context.Background(), "DELETE", fmt.Sprintf("/v1/groups/%s", url.PathEscape(n.groupID)), nil)
		if err != nil {
			return fmt.Errorf("failed to delete group: %w", err)
		}
	}

	return nil
}

func (n *nbxplorer) makeRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, n.url+endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return bodyBytes, nil
}

func (n *nbxplorer) validateDerivationScheme(derivationScheme string) error {
	if len(derivationScheme) == 0 {
		return fmt.Errorf("derivation scheme cannot be empty")
	}
	return nil
}

// createEmptyGroup creates address group via /v1/groups endpoint.
func (n *nbxplorer) createEmptyGroup(ctx context.Context) error {
	resp, err := n.makeRequest(ctx, "POST", "/v1/groups", nil)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	var groupResponse struct {
		GroupID string `json:"groupId"`
	}
	if err := json.Unmarshal(resp, &groupResponse); err != nil {
		return fmt.Errorf("failed to decode group response: %w", err)
	}

	n.groupID = groupResponse.GroupID
	return nil
}

// connectWebSocket establishes a WebSocket connection to NBXplorer for real-time events
func (n *nbxplorer) connectWebSocket(ctx context.Context) error {
	n.wsMutex.Lock()
	defer n.wsMutex.Unlock()

	if n.wsConn != nil {
		n.wsConn.Close()
	}

	wsURL := strings.Replace(n.url, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += "/v1/cryptos/connect"

	conn, _, err := n.wsDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	n.wsConn = conn
	return nil
}

// searchNewUTXOs rescans UTXOs for a specific group and returns only UTXOs from the specified transaction hash
func (n *nbxplorer) searchNewUTXOs(ctx context.Context, txHash string) ([]ports.Utxo, error) {
	if txHash == "" {
		return nil, fmt.Errorf("transaction hash is required")
	}

	cryptoCode := btcCryptoCode
	endpoint := fmt.Sprintf("/v1/cryptos/%s/groups/%s/utxos", cryptoCode, url.PathEscape(n.groupID))

	data, err := n.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get group UTXOs: %w", err)
	}

	var resp utxosResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal UTXO changes: %w", err)
	}

	utxos := make([]ports.Utxo, 0)

	for _, u := range resp.Confirmed.UtxOs {
		if u.TransactionHash != txHash {
			continue
		}

		utxo, err := castUtxo(u)
		if err != nil {
			log.Errorf("failed to cast UTXO: %s", err)
			continue
		}

		utxos = append(utxos, utxo)
	}

	for _, u := range resp.Unconfirmed.UtxOs {
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

func castUtxo(u utxoResponse) (ports.Utxo, error) {
	hash, err := chainhash.NewHashFromStr(u.TransactionHash)
	if err != nil {
		return ports.Utxo{}, fmt.Errorf("failed to convert transaction hash to chainhash: %w", err)
	}

	return ports.Utxo{
		OutPoint: wire.OutPoint{
			Hash:  *hash,
			Index: u.Index,
		},
		Value:         u.Value,
		Script:        u.ScriptPubKey,
		Address:       u.Address,
		Confirmations: u.Confirmations,
	}, nil
}
