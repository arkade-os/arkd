package mempool_explorer

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// websocketConnection represents a single WebSocket connection with its subscribed addresses.
type websocketConnection struct {
	id      int
	conn    *websocket.Conn
	address *addressStore
	mu      *sync.RWMutex
}

// connectionPool manages multiple WebSocket connections for load distribution.
// Addresses are distributed across connections using consistent hash-based routing.
type connectionPool struct {
	connectionsByAddress map[string]int               // map address => connection index
	connections          map[int]*websocketConnection // pool of connections
	newConnectionCh      chan *websocketConnection
	mu                   *sync.RWMutex
	wsURL                string
	ctx                  context.Context
	noMoreConnections    bool
}

func newConnectionPool(ctx context.Context, wsURL string) (*connectionPool, error) {
	pool := &connectionPool{
		connectionsByAddress: make(map[string]int),
		connections:          make(map[int]*websocketConnection, 0),
		newConnectionCh:      make(chan *websocketConnection),
		mu:                   &sync.RWMutex{},
		wsURL:                wsURL,
		ctx:                  ctx,
	}

	if err := pool.addConnection(); err != nil {
		return nil, err
	}

	return pool, nil
}

func (cp *connectionPool) getNewConnections() <-chan *websocketConnection {
	return cp.newConnectionCh
}

func (cp *connectionPool) getConnectionCount() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.connections)
}

func (cp *connectionPool) addConnection() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.noMoreConnections {
		return fmt.Errorf("no more connections available")
	}

	// Exponential backoff parameters
	delay := 5 * time.Second
	multiplier := 2.0
	attempt := 0
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}

	// Retry connection until successful or context is done
	var conn *websocket.Conn
	connId := len(cp.connections)
	for {
		attempt++
		var err error
		conn, _, err = dialer.DialContext(cp.ctx, cp.wsURL, nil)
		if err != nil {
			if dnsErr := new(net.DNSError); errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				log.Debugf(
					"explorer: attempt %d to establish connection %d failed, retrying in %s...",
					attempt, connId, delay,
				)
				select {
				case <-cp.ctx.Done():
					return cp.ctx.Err()
				case <-time.After(delay):
					delay = min(time.Duration(float64(delay)*multiplier), time.Minute)
					continue
				}
			}
			cp.noMoreConnections = true
			return err
		}
		break
	}

	wsConn := &websocketConnection{
		id:      connId,
		conn:    conn,
		address: newAddressStore(),
		mu:      &sync.RWMutex{},
	}

	cp.connections[connId] = wsConn
	go func() { cp.newConnectionCh <- wsConn }()

	return nil
}

// resetConnection closes and removes the given connection from the pool, and adds a new one
func (cp *connectionPool) resetConnection(wsConn *websocketConnection) error {
	cp.mu.Lock()
	// nolint
	wsConn.conn.Close()
	delete(cp.connections, wsConn.id)
	delete(cp.connectionsByAddress, wsConn.address.get())
	cp.noMoreConnections = false
	cp.mu.Unlock()

	return cp.addConnection()
}

// pushAddress picks an available connection and uses it to subscribe for the given address.
// Returns the id of the selected connection.
func (cp *connectionPool) pushAddress(address string) (int, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if len(cp.connections) == 0 {
		return -1, fmt.Errorf("no connections available")
	}

	// Select the first available connection without an address assigned
	conns := slices.Collect(maps.Values(cp.connections))
	idx := slices.IndexFunc(conns, func(c *websocketConnection) bool {
		return c.address.get() == ""
	})
	// If connections are all taken, reject the request
	if idx < 0 {
		return -1, fmt.Errorf("no more connections available")
	}

	connId := conns[idx].id
	conn := cp.connections[connId]

	// Subscribe for the address
	payload := map[string][]string{"track-addresses": {address}}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if err := conn.conn.WriteJSON(payload); err != nil {
		return -1, fmt.Errorf(
			"failed to subscribe for %s on connection %d: %s",
			address, conn.id, err,
		)
	}

	cp.connectionsByAddress[address] = connId
	cp.connections[connId].address.set(address)

	return connId, nil
}

// popAddress removes the given address from its assigned connection in the pool.
// It also frees the connection by unsubscribing from the given address and makes it available
// for another one
func (cp *connectionPool) popAddress(address string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	connId, ok := cp.connectionsByAddress[address]
	if !ok {
		return
	}

	// Unsubscribe from the address
	conn := cp.connections[connId]
	payload := map[string][]string{"track-addresses": {}}
	conn.mu.Lock()
	// nolint
	conn.conn.WriteJSON(payload)
	conn.mu.Unlock()

	// Remove the address from the connection pool
	delete(cp.connectionsByAddress, address)
	cp.connections[connId].address.remove(address)
}

func (cp *connectionPool) getConnectionForAddress(address string) (*websocketConnection, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	connId, ok := cp.connectionsByAddress[address]
	if !ok {
		return nil, false
	}
	return cp.connections[connId], true
}

type addressStore struct {
	mu      *sync.RWMutex
	address string
}

func newAddressStore() *addressStore {
	return &addressStore{
		mu: &sync.RWMutex{},
	}
}

func (l *addressStore) set(address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.address = address
}

func (l *addressStore) remove(_ string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.address = ""
}

func (l *addressStore) get() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.address
}
