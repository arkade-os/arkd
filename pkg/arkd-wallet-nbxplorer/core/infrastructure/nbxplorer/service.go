package nbxplorer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/sirupsen/logrus"
)

const (
	// Default cryptocurrency code for Bitcoin
	defaultCryptoCode = "BTC"
)

type nbxplorer struct {
	url        string
	httpClient *http.Client

	// WebSocket connection for real-time events
	wsConn   *websocket.Conn
	wsMutex  sync.RWMutex
	wsDialer websocket.Dialer

	// inmemory groupID
	groupID string
}

// New creates a new NBXplorer service client with the specified base URL.
func New(url string) ports.Nbxplorer {
	// Remove trailing slash if present
	url = strings.TrimSuffix(url, "/")

	return &nbxplorer{
		url:        url,
		httpClient: &http.Client{},
		wsDialer:   websocket.Dialer{},
	}
}

// makeRequest handles HTTP requests to the NBXplorer API with proper headers and error handling.
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
	if derivationScheme == "" {
		return fmt.Errorf("derivation scheme cannot be empty")
	}
	return nil
}

// GetBitcoinStatus retrieves Bitcoin network status from /v1/cryptos/{cryptoCode}/status endpoint.
func (n *nbxplorer) GetBitcoinStatus(ctx context.Context) (ports.BitcoinStatus, error) {
	// Use default crypto code
	cryptoCode := defaultCryptoCode
	data, err := n.makeRequest(ctx, "GET", fmt.Sprintf("/v1/cryptos/%s/status", cryptoCode), nil)
	if err != nil {
		return ports.BitcoinStatus{}, fmt.Errorf("failed to get bitcoin status: %w", err)
	}

	var resp bitcoinStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return ports.BitcoinStatus{}, fmt.Errorf("failed to unmarshal bitcoin status: %w", err)
	}

	return ports.BitcoinStatus{
		ChainTipHeight: resp.BitcoinStatus.Blocks,
		ChainTipTime:   int64(resp.BitcoinStatus.Headers), // Using headers as approximation
		Synched:        resp.BitcoinStatus.IsSynched,
	}, nil
}

// GetTransaction retrieves transaction details from /v1/cryptos/{cryptoCode}/transactions/{txId} endpoint.
func (n *nbxplorer) GetTransaction(ctx context.Context, txid string) (ports.TransactionDetails, error) {
	// Validate txid format
	if txid == "" {
		return ports.TransactionDetails{}, fmt.Errorf("transaction ID cannot be empty")
	}
	if _, err := chainhash.NewHashFromStr(txid); err != nil {
		return ports.TransactionDetails{}, fmt.Errorf("invalid txid format: %w", err)
	}

	// Use default crypto code
	cryptoCode := defaultCryptoCode
	data, err := n.makeRequest(ctx, "GET", fmt.Sprintf("/v1/cryptos/%s/transactions/%s", cryptoCode, txid), nil)
	if err != nil {
		return ports.TransactionDetails{}, fmt.Errorf("failed to get transaction: %w", err)
	}

	var resp transactionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return ports.TransactionDetails{}, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	return ports.TransactionDetails{
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

		// Validate input parameters
		if err := n.validateDerivationScheme(derivationScheme); err != nil {
			progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
			return
		}

		if gapLimit <= 0 {
			gapLimit = 10000 // Default gap limit
		}

		// Use default crypto code
		cryptoCode := defaultCryptoCode
		endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/utxos/scan?gapLimit=%d", cryptoCode, url.PathEscape(derivationScheme), gapLimit)

		// Start the scan
		_, err := n.makeRequest(ctx, "POST", endpoint, nil)
		if err != nil {
			progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
			return
		}

		// Poll for progress
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				progressChan <- ports.ScanUtxoSetProgress{Progress: 0, Done: true}
				return
			case <-ticker.C:
				progressEndpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/utxos/scan/status", cryptoCode, url.PathEscape(derivationScheme))
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

				// Map the status to progress with nil pointer protection
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

	// Use default crypto code
	cryptoCode := defaultCryptoCode
	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s", cryptoCode, url.PathEscape(derivationScheme))
	logrus.Debugf("Tracking derivation scheme: %s", endpoint)
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

	cryptoCode := defaultCryptoCode
	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/utxos", cryptoCode, url.PathEscape(derivationScheme))
	data, err := n.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get utxos: %w", err)
	}

	var resp utxosResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal utxos: %w", err)
	}

	utxos := make([]ports.Utxo, 0, len(resp.Confirmed.UtxOs)+len(resp.Unconfirmed.UtxOs))

	// Add confirmed UTXOs
	for _, u := range resp.Confirmed.UtxOs {
		txHash, err := chainhash.NewHashFromStr(u.TransactionHash)
		if err != nil {
			logrus.Warnf("failed to parse transaction hash: %s", err)
			continue
		}

		utxos = append(utxos, ports.Utxo{
			OutPoint: wire.OutPoint{
				Hash:  *txHash,
				Index: u.Index,
			},
			Value:         u.Value,
			Script:        u.ScriptPubKey,
			Address:       u.Address,
			Confirmations: u.Confirmations,
		})
	}

	for _, u := range resp.Unconfirmed.UtxOs {
		txHash, err := chainhash.NewHashFromStr(u.TransactionHash)
		if err != nil {
			logrus.Warnf("failed to parse transaction hash: %s", err)
			continue
		}

		utxos = append(utxos, ports.Utxo{
			OutPoint: wire.OutPoint{
				Hash:  *txHash,
				Index: u.Index,
			},
			Value:         u.Value,
			Script:        u.ScriptPubKey,
			Address:       u.Address,
			Confirmations: 0, // unconfirmed utxos always have 0 confirmations
		})
	}

	return utxos, nil
}

// GetScriptPubKeyDetails retrieves key path from /v1/cryptos/{cryptoCode}/derivations/{scheme}/scripts/{script} endpoint.
func (n *nbxplorer) GetScriptPubKeyDetails(ctx context.Context, derivationScheme string, script string) (ports.ScriptPubKeyDetails, error) {
	if err := n.validateDerivationScheme(derivationScheme); err != nil {
		return ports.ScriptPubKeyDetails{}, fmt.Errorf("invalid derivation scheme: %w", err)
	}

	if script == "" {
		return ports.ScriptPubKeyDetails{}, fmt.Errorf("script cannot be empty")
	}

	// Use default crypto code
	cryptoCode := defaultCryptoCode
	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/scripts/%s", cryptoCode, url.PathEscape(derivationScheme), url.PathEscape(script))
	data, err := n.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return ports.ScriptPubKeyDetails{}, fmt.Errorf("failed to get script pubkey details: %w", err)
	}

	var resp scriptPubKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return ports.ScriptPubKeyDetails{}, fmt.Errorf("failed to unmarshal script pubkey details: %w", err)
	}

	return ports.ScriptPubKeyDetails{
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

	// Use default crypto code
	cryptoCode := defaultCryptoCode
	params := url.Values{}
	if change {
		params.Set("feature", "Change")
	} else {
		params.Set("feature", "Deposit")
	}
	if skip > 0 {
		params.Set("skip", strconv.Itoa(skip))
	}

	endpoint := fmt.Sprintf("/v1/cryptos/%s/derivations/%s/addresses/unused", cryptoCode, url.PathEscape(derivationScheme))
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
	data, err := n.makeRequest(ctx, "GET", fmt.Sprintf("/v1/cryptos/%s/fees/%d", defaultCryptoCode, blockCount), nil)
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

	// Convert sat/vB to sat/kvB
	satPerKvB := chainfee.SatPerKVByte(resp.FeeRate * 1000)
	return satPerKvB, nil
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

	req, err := http.NewRequestWithContext(ctx, "POST", n.url+fmt.Sprintf("/v1/cryptos/%s/transactions", defaultCryptoCode), hex.NewDecoder(strings.NewReader(txHex)))
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

	var broadcastResult BroadcastResult
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
		ID:      1,
		Method:  "submitpackage",
		Params:  txs,
	}

	jsonBody, err := json.Marshal(rpcReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	data, err := n.makeRequest(ctx, "POST", fmt.Sprintf("/v1/cryptos/%s/rpc", defaultCryptoCode), strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", fmt.Errorf("failed to call submitpackage RPC: %w", err)
	}

	var resp rpcResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("failed to unmarshal RPC response: %w", err)
	}

	// Check for RPC errors
	if resp.Error != nil {
		return "", fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	// Parse the result
	if resp.Result == nil {
		return "", fmt.Errorf("RPC returned nil result")
	}

	// Convert result to JSON and then to our struct
	resultBytes, err := json.Marshal(resp.Result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal RPC result: %w", err)
	}

	var submitResult submitPackageResult
	if err := json.Unmarshal(resultBytes, &submitResult); err != nil {
		return "", fmt.Errorf("failed to unmarshal submitpackage result: %w", err)
	}

	// Return the first transaction ID from the results
	// In a package, we typically want to return the child transaction ID
	for _, txResult := range submitResult.TxResults {
		if txResult.TxID != "" {
			return txResult.TxID, nil
		}
	}

	return "", fmt.Errorf("no valid transaction ID found in submitpackage result")
}

// createEmptyGroup creates address group via /v1/groups endpoint.
func (n *nbxplorer) createEmptyGroup(ctx context.Context) error {
	resp, err := n.makeRequest(ctx, "POST", "/v1/groups", nil)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	// Parse response to get the groupID
	var groupResponse struct {
		GroupID string `json:"groupId"`
	}
	if err := json.Unmarshal(resp, &groupResponse); err != nil {
		return fmt.Errorf("failed to decode group response: %w", err)
	}

	n.groupID = groupResponse.GroupID
	return nil
}

// WatchAddress adds addresses to group via /v1/cryptos/{cryptoCode}/groups/{groupID}/addresses endpoint.
func (n *nbxplorer) WatchAddress(ctx context.Context, addresses ...string) error {
	if len(n.groupID) == 0 {
		if err := n.createEmptyGroup(ctx); err != nil {
			return fmt.Errorf("failed to create empty group: %w", err)
		}
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no addresses provided")
	}

	// Validate addresses
	for _, addr := range addresses {
		if addr == "" {
			return fmt.Errorf("address cannot be empty")
		}
	}

	// Use default crypto code
	cryptoCode := defaultCryptoCode

	// According to API spec, this endpoint expects an array of strings
	jsonBody, err := json.Marshal(addresses)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	endpoint := fmt.Sprintf("/v1/cryptos/%s/groups/%s/addresses", cryptoCode, url.PathEscape(n.groupID))
	_, err = n.makeRequest(ctx, "POST", endpoint, strings.NewReader(string(jsonBody)))
	if err != nil {
		return fmt.Errorf("failed to add addresses to group: %w", err)
	}
	return nil
}

// UnwatchAddress removes addresses from group via DELETE /v1/groups/{groupID}/children/delete endpoint.
func (n *nbxplorer) UnwatchAddress(ctx context.Context, addresses ...string) error {
	if len(n.groupID) == 0 {
		return fmt.Errorf("group ID is not set")
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no addresses provided")
	}

	// Validate addresses
	for _, addr := range addresses {
		if addr == "" {
			return fmt.Errorf("address cannot be empty")
		}
	}

	// According to API spec, we need to remove children from group
	// Convert addresses to tracked source format
	trackedSources := make([]map[string]string, len(addresses))
	for i, addr := range addresses {
		trackedSources[i] = map[string]string{
			"trackedSource": fmt.Sprintf("ADDRESS:%s", addr),
		}
	}

	jsonBody, err := json.Marshal(trackedSources)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	endpoint := fmt.Sprintf("/v1/groups/%s/children/delete", url.PathEscape(n.groupID))
	_, err = n.makeRequest(ctx, "POST", endpoint, strings.NewReader(string(jsonBody)))
	if err != nil {
		return fmt.Errorf("failed to remove addresses from group: %w", err)
	}
	return nil
}

// connectWebSocket establishes a WebSocket connection to NBXplorer for real-time events
func (n *nbxplorer) connectWebSocket(ctx context.Context) error {
	n.wsMutex.Lock()
	defer n.wsMutex.Unlock()

	// Close existing connection if any
	if n.wsConn != nil {
		n.wsConn.Close()
	}

	// Convert HTTP URL to WebSocket URL
	wsURL := strings.Replace(n.url, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += "/v1/cryptos/connect"

	// Establish WebSocket connection
	conn, _, err := n.wsDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	n.wsConn = conn
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

	notificationsChan := make(chan []ports.Utxo, 10) // Buffered channel to prevent blocking

	go func() {
		defer close(notificationsChan)

		// Establish WebSocket connection
		if err := n.connectWebSocket(ctx); err != nil {
			// If WebSocket connection fails, return error
			select {
			case notificationsChan <- nil:
			case <-ctx.Done():
			}
			return
		}

		// Listen for WebSocket events
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Read message from WebSocket
				_, message, err := n.wsConn.ReadMessage()
				if err != nil {
					// Reconnect on error
					if err := n.connectWebSocket(ctx); err != nil {
						// If reconnection fails, return error
						select {
						case notificationsChan <- nil:
						case <-ctx.Done():
						}
						return
					}
					continue
				}

				// Parse event
				var event Event
				if err := json.Unmarshal(message, &event); err != nil {
					continue
				}

				// Only process "newtransaction" events
				if event.Type == "newtransaction" {
					// Parse the new transaction event data to get the transaction hash
					var newTxEvent NewTransactionEvent
					if eventDataBytes, err := json.Marshal(event.Data); err == nil {
						if err := json.Unmarshal(eventDataBytes, &newTxEvent); err == nil {
							// Trigger UTXO rescanning for the group, filtering by the new transaction hash
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

// searchNewUTXOs rescans UTXOs for a specific group and returns only UTXOs from the specified transaction hash
func (n *nbxplorer) searchNewUTXOs(ctx context.Context, txHash string) ([]ports.Utxo, error) {
	if txHash == "" {
		return nil, fmt.Errorf("transaction hash is required")
	}

	cryptoCode := defaultCryptoCode
	endpoint := fmt.Sprintf("/v1/cryptos/%s/groups/%s/utxos", cryptoCode, url.PathEscape(n.groupID))

	data, err := n.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get group UTXOs: %w", err)
	}

	// Parse the NBXplorer API response structure
	var resp utxosResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal UTXO changes: %w", err)
	}

	// Convert UTXOs to ports.Utxo format, filtering by transaction hash
	utxos := make([]ports.Utxo, 0)

	// Check confirmed UTXOs
	for _, u := range resp.Confirmed.UtxOs {
		// Only include UTXOs from the specified transaction
		if u.TransactionHash != txHash {
			continue
		}

		hash, err := chainhash.NewHashFromStr(u.TransactionHash)
		if err != nil {
			continue
		}

		utxos = append(utxos, ports.Utxo{
			OutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: u.Index,
			},
			Value:         u.Value,
			Script:        u.ScriptPubKey,
			Address:       u.Address,
			Confirmations: u.Confirmations,
		})
	}

	// Check unconfirmed UTXOs
	for _, u := range resp.Unconfirmed.UtxOs {
		// Only include UTXOs from the specified transaction
		if u.TransactionHash != txHash {
			continue
		}

		hash, err := chainhash.NewHashFromStr(u.TransactionHash)
		if err != nil {
			continue
		}

		utxos = append(utxos, ports.Utxo{
			OutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: u.Index,
			},
			Value:         u.Value,
			Script:        u.ScriptPubKey,
			Address:       u.Address,
			Confirmations: u.Confirmations,
		})
	}

	return utxos, nil
}

// Close closes the WebSocket connection and cleans up resources
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
