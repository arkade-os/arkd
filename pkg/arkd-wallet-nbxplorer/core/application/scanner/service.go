package scanner

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type scanner struct {
	ctx         context.Context
	cancel      context.CancelFunc
	nbxplorer   ports.Nbxplorer
	chainParams *chaincfg.Params

	mu            sync.Mutex
	notifications []chan map[string][]application.Utxo
}

// New creates a new BlockchainScanner service
func New(nbxplorer ports.Nbxplorer, network string) (application.BlockchainScanner, error) {
	ctx, cancel := context.WithCancel(context.Background())

	svc := &scanner{
		ctx:           ctx,
		cancel:        cancel,
		nbxplorer:     nbxplorer,
		mu:            sync.Mutex{},
		notifications: make([]chan map[string][]application.Utxo, 0),
		chainParams:   application.NetworkToChainParams(network),
	}

	if err := svc.start(ctx); err != nil {
		return nil, err
	}

	return svc, nil
}

func (s *scanner) start(ctx context.Context) error {
	groupNotifications, err := s.nbxplorer.GetAddressNotifications(ctx)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case utxos := <-groupNotifications:
				if len(s.notifications) == 0 {
					continue
				}

				notificationsMap := make(map[string][]application.Utxo)
				for _, utxo := range utxos {
					if _, ok := notificationsMap[utxo.Script]; !ok {
						notificationsMap[utxo.Script] = make([]application.Utxo, 0)
					}
					notificationsMap[utxo.Script] = append(notificationsMap[utxo.Script], application.Utxo{
						Txid:   utxo.OutPoint.Hash.String(),
						Index:  utxo.OutPoint.Index,
						Script: utxo.Script,
						Value:  utxo.Value,
					})
				}

				s.mu.Lock()
				for _, listener := range s.notifications {
					go func(listener chan map[string][]application.Utxo) {
						select {
						case <-ctx.Done():
							return
						case listener <- notificationsMap:
						}
					}(listener)
				}
				s.mu.Unlock()
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

	return s.nbxplorer.WatchAddress(ctx, addresses...)
}

func (s *scanner) UnwatchScripts(ctx context.Context, scripts []string) error {
	addresses, err := scriptsToAddresses(scripts, s.chainParams)
	if err != nil {
		return err
	}

	return s.nbxplorer.UnwatchAddress(ctx, addresses...)
}

func (s *scanner) GetNotificationChannel(ctx context.Context) <-chan map[string][]application.Utxo {
	ch := make(chan map[string][]application.Utxo, 128)
	s.mu.Lock()
	s.notifications = append(s.notifications, ch)
	s.mu.Unlock()
	return ch
}

func (s *scanner) IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blocknumber int64, blocktime int64, err error) {
	details, err := s.nbxplorer.GetTransaction(ctx, txid)
	if err != nil {
		return false, 0, 0, err
	}

	return details.Confirmations > 0, int64(details.Height), details.Timestamp, nil
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
