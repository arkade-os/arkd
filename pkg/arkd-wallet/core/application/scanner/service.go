package scanner

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

const (
	defaultInitialBackoff = time.Second
	defaultMaxBackoff     = 30 * time.Second
)

type scanner struct {
	ctx         context.Context
	cancel      context.CancelFunc
	nbxplorer   ports.Nbxplorer
	chainParams *chaincfg.Params

	lock                  sync.RWMutex
	notificationListeners []chan map[string][]application.Utxo
	spendListeners        []chan []application.Spend
	initialBackoff        time.Duration
	maxBackoff            time.Duration
}

// New creates a new BlockchainScanner service
func New(nbxplorer ports.Nbxplorer, network string) (application.BlockchainScanner, error) {
	ctx, cancel := context.WithCancel(context.Background())

	svc := &scanner{
		ctx:                   ctx,
		cancel:                cancel,
		nbxplorer:             nbxplorer,
		lock:                  sync.RWMutex{},
		notificationListeners: make([]chan map[string][]application.Utxo, 0),
		spendListeners:        make([]chan []application.Spend, 0),
		chainParams:           application.NetworkToChainParams(network),
		initialBackoff:        defaultInitialBackoff,
		maxBackoff:            defaultMaxBackoff,
	}

	if err := svc.start(ctx); err != nil {
		return nil, err
	}

	return svc, nil
}

func (s *scanner) start(ctx context.Context) error {
	notificationCh, err := s.nbxplorer.GetAddressNotifications(ctx)
	if err != nil {
		return err
	}

	go func() {
		backoff := s.initialBackoff

		connected := true

		for {
			select {
			case <-ctx.Done():
				return
			case notification, ok := <-notificationCh:
				if !ok {
					if connected {
						log.Warn("nbxplorer disconnected")
						connected = false
					}

					log.WithFields(log.Fields{"backoff": backoff}).Info("reconnecting to nbxplorer")
					timer := time.NewTimer(backoff)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}

					nextCh, err := s.nbxplorer.GetAddressNotifications(ctx)
					if err == nil {
						log.Info("reconnected to nbxplorer")
						connected = true
						backoff = s.initialBackoff
						notificationCh = nextCh
						continue
					}

					backoff *= 2
					if backoff > s.maxBackoff {
						backoff = s.maxBackoff
					}
					continue
				}

				notificationsMap := make(map[string][]application.Utxo)
				for _, utxo := range notification.Utxos {
					notificationsMap[utxo.Script] = append(notificationsMap[utxo.Script], application.Utxo{
						Txid:   utxo.OutPoint.Hash.String(),
						Index:  utxo.OutPoint.Index,
						Script: utxo.Script,
						Value:  utxo.Value,
					})
				}

				spends := castSpends(notification.Spends)

				s.lock.RLock()
				if len(notificationsMap) > 0 {
					for _, listener := range s.notificationListeners {
						go func(listener chan map[string][]application.Utxo) {
							select {
							case <-ctx.Done():
								return
							case listener <- notificationsMap:
							}
						}(listener)
					}
				}
				if len(spends) > 0 {
					for _, listener := range s.spendListeners {
						go func(listener chan []application.Spend) {
							select {
							case <-ctx.Done():
								return
							case listener <- spends:
							}
						}(listener)
					}
				}
				s.lock.RUnlock()
			}
		}
	}()

	return nil
}

func (s *scanner) WatchScripts(ctx context.Context, scripts []string) error {
	addresses, err := scriptsToAddresses(scripts, s.chainParams)
	if err != nil {
		return err
	}

	return s.nbxplorer.WatchAddresses(ctx, addresses...)
}

func (s *scanner) UnwatchScripts(ctx context.Context, scripts []string) error {
	addresses, err := scriptsToAddresses(scripts, s.chainParams)
	if err != nil {
		return err
	}

	return s.nbxplorer.UnwatchAddresses(ctx, addresses...)
}

func (s *scanner) RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error {
	return s.nbxplorer.RescanUtxos(ctx, outpoints)
}

func (s *scanner) GetNotificationChannel(ctx context.Context) <-chan map[string][]application.Utxo {
	ch := make(chan map[string][]application.Utxo, 128)
	s.lock.Lock()
	s.notificationListeners = append(s.notificationListeners, ch)
	s.lock.Unlock()

	go func() {
		// remove the listener if the context is canceled
		<-ctx.Done()
		s.lock.Lock()
		defer s.lock.Unlock()
		for i, listener := range s.notificationListeners {
			if listener == ch {
				s.notificationListeners = append(
					s.notificationListeners[:i], s.notificationListeners[i+1:]...,
				)
				return
			}
		}
	}()

	return ch
}

func (s *scanner) GetSpendNotificationChannel(ctx context.Context) <-chan []application.Spend {
	ch := make(chan []application.Spend, 128)
	s.lock.Lock()
	s.spendListeners = append(s.spendListeners, ch)
	s.lock.Unlock()

	go func() {
		// remove the listener if the context is canceled
		<-ctx.Done()
		s.lock.Lock()
		defer s.lock.Unlock()
		for i, listener := range s.spendListeners {
			if listener == ch {
				s.spendListeners = append(
					s.spendListeners[:i], s.spendListeners[i+1:]...,
				)
				return
			}
		}
	}()

	return ch
}

func (s *scanner) GetSpends(
	ctx context.Context, from *time.Time,
) ([]application.Spend, error) {
	spends, err := s.nbxplorer.GetSpends(ctx, from)
	if err != nil {
		return nil, err
	}
	return castSpends(spends), nil
}

func (s *scanner) GetUnspentOutpoints(
	ctx context.Context,
) (map[wire.OutPoint]struct{}, error) {
	return s.nbxplorer.GetUnspentOutpoints(ctx)
}

func castSpends(spends []ports.Spend) []application.Spend {
	out := make([]application.Spend, 0, len(spends))
	for _, spend := range spends {
		out = append(out, application.Spend{
			Txid:          spend.OutPoint.Hash.String(),
			Index:         spend.OutPoint.Index,
			SpendingTxid:  spend.SpendingTxid,
			Confirmations: spend.Confirmations,
		})
	}
	return out
}

func (s *scanner) IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blockHeight int64, blockTime int64, err error) {
	details, err := s.nbxplorer.GetTransaction(ctx, txid)
	if err != nil {
		return false, -1, -1, err
	}
	if details == nil {
		return false, -1, -1, nil
	}

	return details.Confirmations > 0, int64(details.Height), details.Timestamp, nil
}

func (s *scanner) GetOutpointStatus(ctx context.Context, outpoint wire.OutPoint) (spent bool, err error) {
	spent, err = s.nbxplorer.IsSpent(ctx, outpoint)
	if err != nil {
		return false, err
	}
	return spent, nil
}

func (s *scanner) Close() {
	s.cancel()
	s.lock.Lock()
	for _, listener := range s.notificationListeners {
		close(listener)
	}
	s.notificationListeners = make([]chan map[string][]application.Utxo, 0)
	for _, listener := range s.spendListeners {
		close(listener)
	}
	s.spendListeners = make([]chan []application.Spend, 0)
	s.lock.Unlock()
}

func scriptsToAddresses(scripts []string, chainParams *chaincfg.Params) ([]string, error) {
	addresses := make([]string, 0, len(scripts))
	for _, script := range scripts {
		address, err := scriptToAddress(script, chainParams)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func scriptToAddress(script string, chainParams *chaincfg.Params) (string, error) {
	scriptBytes, err := hex.DecodeString(script)
	if err != nil {
		return "", err
	}

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(scriptBytes, chainParams)
	if err != nil {
		return "", err
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("invalid script %s", script)
	}

	return addrs[0].EncodeAddress(), nil
}
