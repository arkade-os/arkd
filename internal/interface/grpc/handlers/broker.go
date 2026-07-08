package handlers

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/interface/grpc/handlers/txfilter"
	"github.com/btcsuite/btcd/wire"
)

// MaxTxFiltersPerListener bounds the number of compiled CEL programs a single
// subscription can hold, preventing memory exhaustion via repeated
// UpdateSubscription calls.
const MaxTxFiltersPerListener = 64

// ErrSubscriptionNotFound is returned by broker operations targeting a
// subscription id that has no live listener.
var ErrSubscriptionNotFound = errors.New("subscription not found")

// ErrTxFiltersLimitExceeded is returned when an add or overwrite would push
// the listener's tx filter count above MaxTxFiltersPerListener.
var ErrTxFiltersLimitExceeded = fmt.Errorf(
	"tx filters per subscription limit (%d) exceeded", MaxTxFiltersPerListener,
)

type listener[T any] struct {
	id           string
	topics       map[string]struct{}
	txFilters    map[string]txfilter.Filter
	ch           chan T
	done         chan struct{}
	closeDoneMux sync.Once
	timeoutTimer *time.Timer
	// attached tracks the stream currently consuming ch, if any. Like
	// timeoutTimer it is guarded by the owning broker's lock.
	attached *attachment
	lock     *sync.RWMutex
}

// attachment represents a stream's exclusive hold on a listener. It is
// created by attach and released by detach; a newer attach displaces the
// previous holder by closing its displaced channel.
type attachment struct {
	displaced chan struct{}
}

func newListener[T any](id string, topics []string) *listener[T] {
	topicsMap := make(map[string]struct{})
	for _, topic := range topics {
		topicsMap[formatTopic(topic)] = struct{}{}
	}
	return &listener[T]{
		id:        id,
		topics:    topicsMap,
		txFilters: make(map[string]txfilter.Filter),
		ch:        make(chan T, 100),
		done:      make(chan struct{}),
		lock:      &sync.RWMutex{},
	}
}

func (l *listener[T]) closeDone() {
	l.closeDoneMux.Do(func() {
		close(l.done)
	})
}

func (l *listener[T]) includesAny(topics []string) bool {
	l.lock.RLock()
	defer l.lock.RUnlock()
	if len(topics) == 0 {
		return true
	}

	for _, topic := range topics {
		formattedTopic := formatTopic(topic)
		if _, ok := l.topics[formattedTopic]; ok {
			return true
		}
	}
	return false
}

func (l *listener[T]) addTopics(topics []string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.topics == nil {
		l.topics = make(map[string]struct{}, len(topics))
	}
	for _, topic := range topics {
		l.topics[formatTopic(topic)] = struct{}{}
	}
}

func (l *listener[T]) removeTopics(topics []string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.topics == nil {
		return
	}
	for _, topic := range topics {
		delete(l.topics, formatTopic(topic))
	}
}

func (l *listener[T]) overwriteTopics(topics []string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	newTopics := make(map[string]struct{}, len(topics))
	for _, topic := range topics {
		newTopics[formatTopic(topic)] = struct{}{}
	}
	l.topics = newTopics
}

func (l *listener[T]) getTopics() []string {
	l.lock.RLock()
	defer l.lock.RUnlock()
	out := make([]string, 0, len(l.topics))
	for t := range l.topics {
		out = append(out, t)
	}
	return out
}

func (l *listener[T]) setTxFilters(filters map[string]txfilter.Filter) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.txFilters = make(map[string]txfilter.Filter, len(filters))
	for expr, f := range filters {
		l.txFilters[expr] = f
	}
}

func (l *listener[T]) getTxFilters() []string {
	l.lock.RLock()
	defer l.lock.RUnlock()
	out := make([]string, 0, len(l.txFilters))
	for expr := range l.txFilters {
		out = append(out, expr)
	}
	return out
}

// matchesTx evaluates the listener's tx filters against the tx produced by
// getTx. Returns true if any filter evaluates to true. Evaluation errors are
// skipped, not propagated.
//
// getTx is invoked lazily, only after we confirm the listener has at least
// one tx filter set, so listeners without tx filters do not pay any decoding
// cost. The tx envelope is built once per call and reused across all filters
// so the OP_RETURN extension is parsed at most once per (event, listener)
// pair.
func (l *listener[T]) matchesTx(getTx func() *wire.MsgTx) bool {
	l.lock.RLock()
	if len(l.txFilters) == 0 {
		l.lock.RUnlock()
		return false
	}
	filters := make([]txfilter.Filter, 0, len(l.txFilters))
	for _, f := range l.txFilters {
		filters = append(filters, f)
	}
	l.lock.RUnlock()
	rawTx := getTx()
	if rawTx == nil {
		return false
	}
	tx, err := txfilter.NewTx(rawTx)
	if err != nil {
		return false
	}
	for _, f := range filters {
		ok, err := f.Eval(tx)
		if err == nil && ok {
			return true
		}
	}
	return false
}

// broker is a simple utility struct to manage subscriptions.
// it is used to send events to multiple listeners.
// it is thread safe and can be used to send events to multiple listeners.
type broker[T any] struct {
	lock      *sync.RWMutex
	listeners map[string]*listener[T]
}

func newBroker[T any]() *broker[T] {
	return &broker[T]{
		lock:      &sync.RWMutex{},
		listeners: make(map[string]*listener[T], 0),
	}
}

func (h *broker[T]) pushListener(l *listener[T]) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.listeners[l.id] = l
}

func (h *broker[T]) removeListener(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	listener, ok := h.listeners[id]
	if !ok {
		return
	}
	if listener.timeoutTimer != nil {
		listener.timeoutTimer.Stop()
	}
	listener.closeDone()
	delete(h.listeners, id)
}

// attach registers the calling stream as the listener's sole consumer and
// cancels any pending removal timeout. If another stream is already attached
// it is displaced: its attachment's displaced channel is closed and ownership
// of the listener's lifecycle moves to the new attachment.
func (h *broker[T]) attach(id string) (*listener[T], *attachment, error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	l, ok := h.listeners[id]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	if l.timeoutTimer != nil {
		l.timeoutTimer.Stop()
		l.timeoutTimer = nil
	}
	if l.attached != nil {
		close(l.attached.displaced)
	}
	l.attached = &attachment{displaced: make(chan struct{})}
	return l, l.attached, nil
}

// release ends att's hold on the listener and settles its lifecycle atomically:
// kept for reconnectWindow if it still has filters, removed otherwise. Returns
// false if att was displaced — the successor owns the lifecycle.
func (h *broker[T]) release(id string, att *attachment, reconnectWindow time.Duration) bool {
	h.lock.Lock()
	defer h.lock.Unlock()

	l, ok := h.listeners[id]
	if !ok || l.attached != att {
		return false
	}
	l.attached = nil

	l.lock.RLock()
	hasFilters := len(l.topics) > 0 || len(l.txFilters) > 0
	l.lock.RUnlock()
	if reconnectWindow > 0 && hasFilters {
		h.scheduleExpiryLocked(l, reconnectWindow)
		return true
	}
	l.closeDone()
	delete(h.listeners, id)
	return true
}

func (h *broker[T]) getTopics(id string) []string {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return nil
	}
	return listener.getTopics()
}

func (h *broker[T]) addTopics(id string, topics []string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	listener.addTopics(topics)
	return nil
}

func (h *broker[T]) removeTopics(id string, topics []string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	listener.removeTopics(topics)
	return nil
}

func (h *broker[T]) removeAllTopics(id string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	listener.overwriteTopics([]string{})
	return nil
}

func (h *broker[T]) overwriteTopics(id string, topics []string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	listener.overwriteTopics(topics)
	return nil
}

func (h *broker[T]) getTxFilters(id string) []string {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return nil
	}
	return listener.getTxFilters()
}

// installTxFilters atomically replaces the listener's tx filter set with
// pre-compiled filters. Enforces MaxTxFiltersPerListener; the caller
// compiles upfront so that compile-time CEL errors can be raised
// alongside other input validation before any mutation.
func (h *broker[T]) installTxFilters(id string, filters map[string]txfilter.Filter) error {
	if len(filters) > MaxTxFiltersPerListener {
		return ErrTxFiltersLimitExceeded
	}
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	listener.setTxFilters(filters)
	return nil
}

func compileTxFilters(exprs []string) (map[string]txfilter.Filter, error) {
	filters := make(map[string]txfilter.Filter, len(exprs))
	for _, expr := range exprs {
		f, err := txfilter.Parse(expr)
		if err != nil {
			return nil, err
		}
		filters[expr] = *f
	}
	return filters, nil
}

func (h *broker[T]) startTimeout(id string, timeout time.Duration) {
	h.lock.Lock()
	defer h.lock.Unlock()

	l, ok := h.listeners[id]
	if !ok {
		return
	}
	// The timeout reaps a listener no stream is consuming; while one is
	// attached it must not be armed (attach cancels it on takeover).
	if l.attached != nil {
		return
	}
	h.scheduleExpiryLocked(l, timeout)
}

// scheduleExpiryLocked (re)arms the expiry timer on l; broker lock must be held, and only the current timer may remove the listener.
func (h *broker[T]) scheduleExpiryLocked(l *listener[T], timeout time.Duration) {
	if l.timeoutTimer != nil {
		l.timeoutTimer.Stop()
	}
	var timer *time.Timer
	timer = time.AfterFunc(timeout, func() {
		h.lock.Lock()
		defer h.lock.Unlock()

		listener, ok := h.listeners[l.id]
		if !ok || listener.timeoutTimer != timer {
			return
		}
		listener.closeDone()
		delete(h.listeners, l.id)
	})
	l.timeoutTimer = timer
}

func (h *broker[T]) getListenersCopy() map[string]*listener[T] {
	h.lock.RLock()
	defer h.lock.RUnlock()

	listenersCopy := make(map[string]*listener[T], len(h.listeners))
	maps.Copy(listenersCopy, h.listeners)
	return listenersCopy
}

func (h *broker[T]) hasListeners() bool {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return len(h.listeners) > 0
}

func formatTopic(topic string) string {
	return strings.Trim(strings.ToLower(topic), " ")
}
