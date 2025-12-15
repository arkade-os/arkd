// Package explorer provides an explorer client with support for multiple concurrent WebSocket
// connections for addresses tracking.
//
// # Architecture
//
//   - Multiple concurrent WebSocket connections
//   - Hash-based address distribution for consistent routing
//   - Automatic fallback to polling if WebSocket connections fails
//
// # Usage
//
// Basic usage with default settings:
//
//	svc, err := explorer.NewExplorer("", arklib.Bitcoin, explorer.WithTracker(true))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer svc.Stop()
//
//
//	Subscribe to addresses:
//
//	addresses := []string{"bc1q...", "bc1p...", ...}
//	if err := svc.SubscribeForAddresses(addresses); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Listen for events
//	for event := range svc.GetAddressesEvents() {
//	    fmt.Printf("New UTXOs: %d, Spent: %d\n", len(event.NewUtxos), len(event.SpentUtxos))
//	}
//
// # Thread Safety
//
// All public methods are thread-safe and can be called concurrently.
package mempool_explorer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	BitcoinExplorer = "bitcoin"
	pongInterval    = 60 * time.Second
	pingInterval    = (pongInterval * 9) / 10
)

var (
	defaultExplorerUrls = utils.SupportedType[string]{
		arklib.Bitcoin.Name:        "https://mempool.space/api",
		arklib.BitcoinTestNet.Name: "https://mempool.space/testnet/api",
		//arklib.BitcoinTestNet4.Name: "https://mempool.space/testnet4/api", //TODO uncomment once supported
		arklib.BitcoinSigNet.Name:    "https://mempool.space/signet/api",
		arklib.BitcoinMutinyNet.Name: "https://mutinynet.com/api",
		arklib.BitcoinRegTest.Name:   "http://127.0.0.1:3000",
	}
)

type explorerSvc struct {
	cache         *utils.Cache[string]
	baseUrl       string
	net           arklib.Network
	connPool      *connectionPool
	connPoolMu    sync.RWMutex
	subscribedMu  *sync.RWMutex
	subscribedMap map[string]addressData
	stopTracking  func()
	pollInterval  time.Duration
	noTracking    bool
	listeners     *listeners
}

// NewExplorer creates a new Explorer instance for the specified network.
// If baseUrl is empty, it uses the default explorer URL for the network.
//
// The explorer supports:
//   - Multiple concurrent WebSocket connections for scalability
//   - Automatic fallback to polling if WebSocket connections fail
//
// Example:
//
// svc, err := explorer.NewExplorer("https://mempool.space/api", arklib.Bitcoin, explorer.WithTracker(true))
func NewExplorer(baseUrl string, net arklib.Network, opts ...Option) (explorer.Explorer, error) {
	if len(baseUrl) == 0 {
		baseUrl, ok := defaultExplorerUrls[net.Name]
		if !ok {
			return nil, fmt.Errorf(
				"cannot find default explorer url associated with network %s",
				net.Name,
			)
		}
		return NewExplorer(baseUrl, net, opts...)
	}

	if _, err := deriveWsURL(baseUrl); err != nil {
		return nil, fmt.Errorf("invalid base url: %s", err)
	}

	svcOpts := &explorerSvc{}
	for _, opt := range opts {
		opt(svcOpts)
	}

	if svcOpts.noTracking {
		return &explorerSvc{
			cache:      utils.NewCache[string](),
			baseUrl:    baseUrl,
			net:        net,
			noTracking: svcOpts.noTracking,
		}, nil
	}

	svc := &explorerSvc{
		cache:         utils.NewCache[string](),
		baseUrl:       baseUrl,
		net:           net,
		subscribedMu:  &sync.RWMutex{},
		subscribedMap: make(map[string]addressData),
		pollInterval:  svcOpts.pollInterval,
		noTracking:    svcOpts.noTracking,
	}

	return svc, nil
}

func (e *explorerSvc) Start() {
	// Nothing to do if tracking disabled.
	if e.noTracking {
		return
	}

	// Nothing to do if service already started.
	if e.stopTracking != nil {
		return
	}

	// nolint
	wsURL, _ := deriveWsURL(e.baseUrl)
	ctx, cancel := context.WithCancel(context.Background())

	connPool, err := newConnectionPool(ctx, wsURL)
	if err != nil {
		log.WithError(err).WithField("wsURL", wsURL).Debugf(
			"explorer: failed to create connection pool,sfalling back to polling with interval %s",
			e.pollInterval,
		)
	}
	e.connPoolMu.Lock()
	e.connPool = connPool
	e.connPoolMu.Unlock()

	e.listeners = newListeners()
	e.stopTracking = cancel
	go e.startTracking(ctx)
	log.Debug("explorer: started with address tracking")
}

func (e *explorerSvc) Stop() {
	// Nothing to do is tracking disabled.
	if e.noTracking {
		return
	}

	// Nothing to do if service already stopped.
	if e.stopTracking == nil {
		return
	}

	e.stopTracking()

	// Close all connections in the pool
	e.connPoolMu.RLock()
	connPool := e.connPool
	e.connPoolMu.RUnlock()
	if connPool != nil {
		connPool.mu.Lock()
		for _, wsConn := range connPool.connections {
			if wsConn.conn != nil {
				if err := wsConn.conn.Close(); err != nil {
					log.WithError(err).Warn("explorer: failed to close ws connection")
				}
			}
		}
		connPool.mu.Unlock()
	}
	log.Debug("explorer: closed all connections")

	// Clear subscribed addresses map
	e.subscribedMu.Lock()
	e.subscribedMap = make(map[string]addressData)
	e.subscribedMu.Unlock()
	e.listeners.clear()

	e.stopTracking = nil
	log.Debug("explorer: stopped")
}

func (e *explorerSvc) BaseUrl() string {
	return e.baseUrl
}

func (e *explorerSvc) GetNetwork() arklib.Network {
	return e.net
}

func (e *explorerSvc) GetFeeRate() (float64, error) {
	endpoint, err := url.JoinPath(e.baseUrl, "fee-estimates")
	if err != nil {
		return 0, err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return 0, err
	}
	// nolint:all
	defer resp.Body.Close()

	var response map[string]float64

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get fee rate: %s", resp.Status)
	}

	if len(response) == 0 {
		return 1, nil
	}

	return response["1"], nil
}

func (e *explorerSvc) GetConnectionCount() int {
	e.connPoolMu.RLock()
	defer e.connPoolMu.RUnlock()
	if e.connPool == nil {
		return 0
	}
	return e.connPool.getConnectionCount()
}

func (e *explorerSvc) GetSubscribedAddresses() []string {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	return slices.Collect(maps.Keys(e.subscribedMap))
}

func (e *explorerSvc) IsAddressSubscribed(address string) bool {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	_, exists := e.subscribedMap[address]
	return exists
}

func (e *explorerSvc) GetAddressesEvents() <-chan types.OnchainAddressEvent {
	ch := make(chan types.OnchainAddressEvent)
	e.listeners.add(ch)
	return ch
}

func (e *explorerSvc) GetTxHex(txid string) (string, error) {
	if hex, ok := e.cache.Get(txid); ok {
		return hex, nil
	}

	txHex, err := e.getTxHex(txid)
	if err != nil {
		return "", err
	}

	e.cache.Set(txid, txHex)

	return txHex, nil
}

func (e *explorerSvc) Broadcast(txs ...string) (string, error) {
	if len(txs) == 0 {
		return "", fmt.Errorf("no txs to broadcast")
	}

	for _, tx := range txs {
		txStr, txid, err := parseBitcoinTx(tx)
		if err != nil {
			return "", err
		}

		e.cache.Set(txid, txStr)
	}

	if len(txs) == 1 {
		txid, err := e.broadcast(txs[0])
		if err != nil {
			if strings.Contains(
				strings.ToLower(err.Error()), "transaction already in block chain",
			) {
				return txid, nil
			}

			return "", err
		}

		return txid, nil
	}

	// package
	return e.broadcastPackage(txs...)
}

func (e *explorerSvc) GetTxs(addr string) ([]explorer.Tx, error) {
	resp, err := http.Get(fmt.Sprintf("%s/address/%s/txs", e.baseUrl, addr))
	if err != nil {
		return nil, err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}
	payload := txs{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload.toList(), nil
}

func (e *explorerSvc) SubscribeForAddresses(addresses []string) error {
	if e.noTracking {
		return nil
	}

	e.subscribedMu.Lock()
	defer e.subscribedMu.Unlock()

	addressesToSubscribe := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if _, ok := e.subscribedMap[addr]; ok {
			continue
		}
		addressesToSubscribe = append(addressesToSubscribe, addr)
	}

	// Nothing to do if no addresses to subscribe.
	if len(addressesToSubscribe) == 0 {
		return nil
	}

	var numAddressesLeftToSubscribe int
	e.connPoolMu.RLock()
	connPool := e.connPool
	e.connPoolMu.RUnlock()
	if connPool != nil && connPool.getConnectionCount() > 0 {
		if connPool.noMoreConnections {
			return fmt.Errorf(
				"can't subscribe for any more addresses (max=%d)",
				len(e.subscribedMap),
			)
		}

		for i, addr := range addressesToSubscribe {
			connId, err := connPool.pushAddress(addr)
			if err != nil {
				log.WithError(err).Warnf("failed to subscribe for address %s", addr)
				numAddressesLeftToSubscribe = len(addressesToSubscribe[i:])
				addressesToSubscribe = addressesToSubscribe[:i]
				break
			}
			log.Debugf("explorer: subscribed for new address on connection %d", connId)
			// nolint
			connPool.addConnection()
			time.Sleep(time.Millisecond)
		}
	}

	// Add new addresses to the subscribed map
	for _, addr := range addressesToSubscribe {
		e.subscribedMap[addr] = addressData{}
	}

	if numAddressesLeftToSubscribe > 0 {
		return fmt.Errorf(
			"can't subscribe for any more addresses (max=%d) (left=%d)",
			len(e.subscribedMap), numAddressesLeftToSubscribe,
		)
	}
	return nil
}

func (e *explorerSvc) UnsubscribeForAddresses(addresses []string) error {
	if e.noTracking {
		return nil
	}

	e.subscribedMu.Lock()
	defer e.subscribedMu.Unlock()

	addressesToUnsubscribe := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if _, ok := e.subscribedMap[addr]; !ok {
			continue
		}
		addressesToUnsubscribe = append(addressesToUnsubscribe, addr)
	}

	// Nothing to do if no addresses to unsubscribe.
	if len(addressesToUnsubscribe) == 0 {
		return nil
	}

	e.connPoolMu.RLock()
	connPool := e.connPool
	e.connPoolMu.RUnlock()
	if connPool != nil && connPool.getConnectionCount() > 0 {
		for _, addr := range addressesToUnsubscribe {
			_, found := connPool.getConnectionForAddress(addr)
			if !found {
				continue
			}
			connPool.popAddress(addr)
		}
	}

	for _, addr := range addresses {
		delete(e.subscribedMap, addr)
	}

	return nil
}

func (e *explorerSvc) GetTxOutspends(txid string) ([]explorer.SpentStatus, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/outspends", e.baseUrl, txid))
	if err != nil {
		return nil, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}

	res := make([]spentStatus, 0)
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	spentStatuses := make([]explorer.SpentStatus, 0, len(res))
	for _, s := range res {
		spentStatuses = append(spentStatuses, explorer.SpentStatus{
			Spent:   s.Spent,
			SpentBy: s.SpentBy,
		})
	}
	return spentStatuses, nil
}

func (e *explorerSvc) GetUtxos(addr string) ([]explorer.Utxo, error) {
	utxos, err := e.getUtxos(addr)
	if err != nil {
		return nil, err
	}
	return utxos.toUtxoList(), nil
}

func (e *explorerSvc) GetRedeemedVtxosBalance(
	addr string, unilateralExitDelay arklib.RelativeLocktime,
) (spendableBalance uint64, lockedBalance map[int64]uint64, err error) {
	utxos, err := e.GetUtxos(addr)
	if err != nil {
		return
	}

	lockedBalance = make(map[int64]uint64, 0)
	now := time.Now()
	for _, utxo := range utxos {
		blocktime := now
		if utxo.Status.Confirmed {
			blocktime = time.Unix(utxo.Status.BlockTime, 0)
		}

		delay := time.Duration(unilateralExitDelay.Seconds()) * time.Second
		availableAt := blocktime.Add(delay)
		if availableAt.After(now) {
			if _, ok := lockedBalance[availableAt.Unix()]; !ok {
				lockedBalance[availableAt.Unix()] = 0
			}

			lockedBalance[availableAt.Unix()] += utxo.Amount
		} else {
			spendableBalance += utxo.Amount
		}
	}

	return
}

func (e *explorerSvc) GetTxBlockTime(
	txid string,
) (confirmed bool, blocktime int64, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s", e.baseUrl, txid))
	if err != nil {
		return false, 0, err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("failed to get block time: %s", string(body))
	}

	var tx struct {
		Status struct {
			Confirmed bool  `json:"confirmed"`
			Blocktime int64 `json:"block_time"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &tx); err != nil {
		return false, 0, err
	}

	if !tx.Status.Confirmed {
		return false, -1, nil
	}

	return true, tx.Status.Blocktime, nil
}

func (e *explorerSvc) startTracking(ctx context.Context) {
	// If the ws endpoint is available (mempool.space url), read from websocket and eventually
	// send notifications and periodically send a ping message to keep the connection alive.
	e.connPoolMu.RLock()
	connPool := e.connPool
	e.connPoolMu.RUnlock()
	if connPool != nil && connPool.getConnectionCount() > 0 {
		// Start a listener and ping routine for each connection in the pool
		e.trackWithWebsocket(ctx, connPool)
	} else {
		// Otherwise (esplora url), poll the explorer every 10s and manually send notifications of
		// spent, new and confirmed utxos.
		e.trackWithPolling(ctx)
	}

}

func (e *explorerSvc) trackWithWebsocket(ctx context.Context, connPool *connectionPool) {
	for {
		select {
		case <-ctx.Done():
			return
		case wsConn := <-connPool.getNewConnections():
			// Go routine to listen for addresses updates from websocket.
			go func(ctx context.Context, wsConn *websocketConnection) {
				if err := wsConn.conn.SetReadDeadline(time.Now().Add(pongInterval)); err != nil {
					if !isCloseError(err) {
						go e.listeners.broadcast(types.OnchainAddressEvent{Error: fmt.Errorf(
							"connection for address %s dropped, please resubscribe: %w",
							wsConn.address.get(), err,
						)})
					}
					return
				}
				wsConn.conn.SetPongHandler(func(string) error {
					return wsConn.conn.SetReadDeadline(time.Now().Add(pongInterval))
				})
				for {
					var payload addressNotification
					if err := wsConn.conn.ReadJSON(&payload); err != nil {
						// The connection was closed, nothing to do but return
						if isCloseError(err) {
							return
						}
						// Connection issues, try to reconnect:
						// If this happens all active connections will arrive to this point.
						// Since resetConnection makes use of a lock, its inner reconnection logic
						// is executed to only one connection and once it is restored and the lock
						// is released, all others will be restored as well
						if isTimeoutError(err) {
							log.Debugf(
								"explorer: connection %d dropped, reconnecting...", wsConn.id,
							)

							addr := wsConn.address.get()

							if err := connPool.resetConnection(wsConn); err != nil {
								go e.listeners.broadcast(types.OnchainAddressEvent{
									Error: fmt.Errorf(
										"failed to reset connection for address %s and "+
											"resubscription is required: %w", addr, err,
									)})
								return
							}

							if len(addr) > 0 {
								if _, err := connPool.pushAddress(addr); err != nil {
									go e.listeners.broadcast(types.OnchainAddressEvent{
										Error: fmt.Errorf(
											"failed to resubscribe for address %s and "+
												"resubscription is required: %w", addr, err,
										)})
									return
								}
							}
							log.Debugf("explorer: connection %d restored", wsConn.id)
							// Get rid of this go routine
							return
						}

						go e.listeners.broadcast(types.OnchainAddressEvent{Error: fmt.Errorf(
							"failed to read message for address %s: %w",
							wsConn.address.get(), err,
						)})
						continue
					}

					go e.sendAddressEventFromWs(payload)
				}
			}(ctx, wsConn)

			// Go routine to periodically send ping messages and keep the connection alive.
			go func(ctx context.Context, wsConn *websocketConnection) {
				ticker := time.NewTicker(pingInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						deadline := time.Now().Add(10 * time.Second)
						if err := wsConn.conn.WriteControl(
							websocket.PingMessage, nil, deadline,
						); err != nil {
							if !isCloseError(err) {
								go e.listeners.broadcast(types.OnchainAddressEvent{
									Error: fmt.Errorf(
										"failed to ping explorer for address %s: %s",
										wsConn.address.get(), err,
									),
								})
							}
							return
						}
					}
				}
			}(ctx, wsConn)
		}
	}
}

func (e *explorerSvc) trackWithPolling(ctx context.Context) {
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.subscribedMu.RLock()
			// make a snapshot copy of the map to avoid race conditions
			subscribedMap := make(map[string]addressData, len(e.subscribedMap))
			for addr, data := range e.subscribedMap {
				hashCopy := make([]byte, len(data.hash))
				copy(hashCopy, data.hash)
				utxosCopy := make([]utxo, len(data.utxos))
				copy(utxosCopy, data.utxos)

				subscribedMap[addr] = addressData{
					hash:  hashCopy,
					utxos: utxosCopy,
				}
			}
			e.subscribedMu.RUnlock()

			if len(subscribedMap) == 0 {
				continue
			}
			for addr, oldUtxos := range subscribedMap {
				newUtxos, err := e.getUtxos(addr)
				if err != nil {
					log.WithError(err).Error("explorer: failed to poll explorer")
					go e.listeners.broadcast(types.OnchainAddressEvent{
						Error: fmt.Errorf("failed to poll explorer: %s", err),
					})
					continue
				}
				hashedResp := newUtxos.hash()
				if !bytes.Equal(oldUtxos.hash, hashedResp) {
					go e.sendAddressEventFromPolling(oldUtxos.utxos, newUtxos)
					e.subscribedMu.Lock()
					e.subscribedMap[addr] = addressData{
						hash:  hashedResp,
						utxos: newUtxos,
					}
					e.subscribedMu.Unlock()
				}

			}
		}
	}
}

func (e *explorerSvc) getUtxos(addr string) (utxos, error) {
	decoded, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}

	outputScript, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}

	resp, err := http.Get(fmt.Sprintf("%s/address/%s/utxo", e.baseUrl, addr))
	if err != nil {
		return nil, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get utxos: %s", string(body))
	}
	utxos := []utxo{}
	if err := json.Unmarshal(body, &utxos); err != nil {
		return nil, err
	}

	for i := range utxos {
		utxos[i].Script = hex.EncodeToString(outputScript)
	}

	return utxos, nil
}

func (e *explorerSvc) sendAddressEventFromWs(payload addressNotification) {
	// Forward the error if we received one.
	if len(payload.Error) > 0 {
		e.listeners.broadcast(types.OnchainAddressEvent{
			Error: fmt.Errorf("%s", payload.Error),
		})
		return
	}
	// Nothing to do if it's not the message we're looking for.
	if payload.MultiAddrTx == nil {
		return
	}

	// Parse the message and send the event.
	spentUtxos := make([]types.OnchainOutput, 0)
	newUtxos := make([]types.OnchainOutput, 0)
	confirmedUtxos := make([]types.OnchainOutput, 0)
	replacements := make(map[string]string)
	for addr, data := range payload.MultiAddrTx {
		if len(data.Removed) > 0 {
			for _, tx := range data.Removed {
				if len(data.Mempool) > 0 {
					replacementTxid := data.Mempool[0].Txid
					replacements[tx.Txid] = replacementTxid
				}
			}
			continue
		}
		if len(data.Mempool) > 0 {
			for _, tx := range data.Mempool {
				for _, in := range tx.Inputs {
					if in.Prevout.Address == addr {
						spentUtxos = append(spentUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: in.Txid,
								VOut: uint32(in.Vout),
							},
							SpentBy: tx.Txid,
							Spent:   true,
						})
					}
				}
				for i, out := range tx.Outputs {
					if out.Address == addr {
						var createdAt time.Time
						if tx.Status.Confirmed {
							createdAt = time.Unix(tx.Status.BlockTime, 0)
						}
						newUtxos = append(newUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: tx.Txid,
								VOut: uint32(i),
							},
							Script:    out.Script,
							Amount:    out.Amount,
							CreatedAt: createdAt,
						})
					}
				}
			}
		}
		if len(data.Confirmed) > 0 {
			for _, tx := range data.Confirmed {
				for i, out := range tx.Outputs {
					if out.Address == addr {
						confirmedUtxos = append(confirmedUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: tx.Txid,
								VOut: uint32(i),
							},
							Script:    out.Script,
							Amount:    out.Amount,
							CreatedAt: time.Unix(tx.Status.BlockTime, 0),
						})
					}
				}
			}
		}
	}

	e.listeners.broadcast(types.OnchainAddressEvent{
		NewUtxos:       newUtxos,
		SpentUtxos:     spentUtxos,
		ConfirmedUtxos: confirmedUtxos,
		Replacements:   replacements,
	})
}

func (e *explorerSvc) sendAddressEventFromPolling(oldUtxos, newUtxos []utxo) {
	indexedOldUtxos := make(map[string]utxo, 0)
	indexedNewUtxos := make(map[string]utxo, 0)
	for _, oldUtxo := range oldUtxos {
		indexedOldUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)] = oldUtxo
	}
	for _, newUtxo := range newUtxos {
		indexedNewUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)] = newUtxo
	}
	spentUtxos := make([]types.OnchainOutput, 0)
	for _, oldUtxo := range oldUtxos {
		if _, ok := indexedNewUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)]; !ok {
			var spentBy string
			spentStatus, _ := e.GetTxOutspends(oldUtxo.Txid)
			if len(spentStatus) > int(oldUtxo.Vout) {
				spentBy = spentStatus[oldUtxo.Vout].SpentBy
			}
			spentUtxos = append(spentUtxos, types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: oldUtxo.Txid,
					VOut: oldUtxo.Vout,
				},
				SpentBy: spentBy,
				Spent:   true,
			})
		}
	}
	receivedUtxos := make([]types.OnchainOutput, 0)
	confirmedUtxos := make([]types.OnchainOutput, 0)
	for _, newUtxo := range newUtxos {
		oldUtxo, ok := indexedOldUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)]
		if !ok {
			utxo := types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: newUtxo.Txid,
					VOut: newUtxo.Vout,
				},
				Script: newUtxo.Script,
				Amount: newUtxo.Amount,
			}

			if newUtxo.Status.Confirmed {
				utxo.CreatedAt = time.Unix(newUtxo.Status.BlockTime, 0)
			}

			receivedUtxos = append(receivedUtxos, utxo)
			continue
		}

		if !oldUtxo.Status.Confirmed && newUtxo.Status.Confirmed {
			confirmedUtxos = append(confirmedUtxos, types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: newUtxo.Txid,
					VOut: newUtxo.Vout,
				},
				Script:    newUtxo.Script,
				Amount:    newUtxo.Amount,
				CreatedAt: time.Unix(newUtxo.Status.BlockTime, 0),
			})
		}
	}

	if len(spentUtxos) > 0 || len(receivedUtxos) > 0 || len(confirmedUtxos) > 0 {
		go e.listeners.broadcast(types.OnchainAddressEvent{
			SpentUtxos:     spentUtxos,
			NewUtxos:       receivedUtxos,
			ConfirmedUtxos: confirmedUtxos,
		})
	}
}

func (e *explorerSvc) getTxHex(txid string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/hex", e.baseUrl, txid))
	if err != nil {
		return "", err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get tx hex: %s", string(body))
	}

	hex := string(body)
	e.cache.Set(txid, hex)
	return hex, nil
}

func (e *explorerSvc) broadcast(txHex string) (string, error) {
	body := bytes.NewBuffer([]byte(txHex))

	resp, err := http.Post(fmt.Sprintf("%s/tx", e.baseUrl), "text/plain", body)
	if err != nil {
		return "", err
	}
	// nolint:all
	defer resp.Body.Close()
	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to broadcast: %s", string(bodyResponse))
	}

	return string(bodyResponse), nil
}

func (e *explorerSvc) broadcastPackage(txs ...string) (string, error) {
	url := fmt.Sprintf("%s/txs/package", e.baseUrl)

	// body is a json array of txs hex
	body := bytes.NewBuffer(nil)
	if err := json.NewEncoder(body).Encode(txs); err != nil {
		return "", err
	}

	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return "", err
	}
	// nolint
	defer resp.Body.Close()

	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to broadcast package: %s", string(bodyResponse))
	}

	return string(bodyResponse), nil
}
