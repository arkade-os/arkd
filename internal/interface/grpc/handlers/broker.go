package handlers

import (
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/indexer/celenv"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/cel-go/cel"
)

type listener[T any] struct {
	id           string
	topics       map[string]struct{}
	txFilters    map[string]cel.Program
	ch           chan T
	done         chan struct{}
	closeDoneMux sync.Once
	timeoutTimer *time.Timer
	lock         *sync.RWMutex
}

func newListener[T any](id string, topics []string) *listener[T] {
	topicsMap := make(map[string]struct{})
	for _, topic := range topics {
		topicsMap[formatTopic(topic)] = struct{}{}
	}
	return &listener[T]{
		id:        id,
		topics:    topicsMap,
		txFilters: make(map[string]cel.Program),
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

func (l *listener[T]) addTxFilters(programs map[string]cel.Program) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.txFilters == nil {
		l.txFilters = make(map[string]cel.Program, len(programs))
	}
	for expr, prg := range programs {
		l.txFilters[expr] = prg
	}
}

func (l *listener[T]) removeTxFilters(exprs []string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.txFilters == nil {
		return
	}
	for _, expr := range exprs {
		delete(l.txFilters, expr)
	}
}

func (l *listener[T]) overwriteTxFilters(programs map[string]cel.Program) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.txFilters = make(map[string]cel.Program, len(programs))
	for expr, prg := range programs {
		l.txFilters[expr] = prg
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
// getTx. Returns true if any program evaluates to true. Evaluation errors are
// skipped, not propagated.
//
// getTx is invoked lazily, only after we confirm the listener has at least
// one tx filter set, so listeners without tx filters do not pay any decoding
// cost.
func (l *listener[T]) matchesTx(getTx func() *wire.MsgTx) bool {
	l.lock.RLock()
	if len(l.txFilters) == 0 {
		l.lock.RUnlock()
		return false
	}
	programs := make([]cel.Program, 0, len(l.txFilters))
	for _, prg := range l.txFilters {
		programs = append(programs, prg)
	}
	l.lock.RUnlock()
	tx := getTx()
	if tx == nil {
		return false
	}
	for _, prg := range programs {
		ok, err := celenv.Eval(prg, tx)
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

func (h *broker[T]) getListenerChannel(id string) (chan T, error) {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return nil, fmt.Errorf("subscription %s not found", id)
	}
	return listener.ch, nil
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
		return fmt.Errorf("subscription %s not found", id)
	}
	listener.addTopics(topics)
	return nil
}

func (h *broker[T]) removeTopics(id string, topics []string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}
	listener.removeTopics(topics)
	return nil
}

func (h *broker[T]) removeAllTopics(id string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}
	listener.overwriteTopics([]string{})
	return nil
}

func (h *broker[T]) overwriteTopics(id string, topics []string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
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

func (h *broker[T]) addTxFilters(id string, exprs []string) error {
	programs, err := compileTxFilters(exprs)
	if err != nil {
		return err
	}
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}
	listener.addTxFilters(programs)
	return nil
}

func (h *broker[T]) removeTxFilters(id string, exprs []string) error {
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}
	listener.removeTxFilters(exprs)
	return nil
}

func (h *broker[T]) overwriteTxFilters(id string, exprs []string) error {
	programs, err := compileTxFilters(exprs)
	if err != nil {
		return err
	}
	h.lock.RLock()
	listener, ok := h.listeners[id]
	h.lock.RUnlock()
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}
	listener.overwriteTxFilters(programs)
	return nil
}

func compileTxFilters(exprs []string) (map[string]cel.Program, error) {
	programs := make(map[string]cel.Program, len(exprs))
	for _, expr := range exprs {
		prg, err := celenv.Compile(expr)
		if err != nil {
			return nil, err
		}
		programs[expr] = prg
	}
	return programs, nil
}

func (h *broker[T]) startTimeout(id string, timeout time.Duration) {
	// stop any existing timeout on this listener
	h.stopTimeout(id)

	h.lock.Lock()
	defer h.lock.Unlock()
	_, ok := h.listeners[id]
	if !ok {
		return
	}

	h.listeners[id].timeoutTimer = time.AfterFunc(timeout, func() {
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
	})
}

func (h *broker[T]) stopTimeout(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return
	}

	if h.listeners[id].timeoutTimer != nil {
		h.listeners[id].timeoutTimer.Stop()
		h.listeners[id].timeoutTimer = nil
	}
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
