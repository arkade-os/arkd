package application

import (
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type WalletOption func(*service) error

// add additional chain API not supported by the chain.Interface type
type extraChainAPI interface {
	getTx(txid string) (*wire.MsgTx, error)
	getTxStatus(txid string) (isConfirmed bool, blockHeight, blocktime int64, err error)
	IsSpent(outpoint wire.OutPoint) (spent bool, err error)
	broadcast(txs ...string) error
}

// WithNeutrino creates a start a neutrino node using the provided service datadir
func WithNeutrino(initialPeer string, esploraURL string) WalletOption {
	return func(s *service) error {
		if s.cfg.Network.Name == arklib.BitcoinRegTest.Name && len(initialPeer) == 0 {
			return fmt.Errorf("initial neutrino peer required for regtest network, set NEUTRINO_PEER env var")
		}

		db, err := createOrOpenWalletDB(s.cfg.Datadir + "/neutrino.db")
		if err != nil {
			return err
		}

		netParams := s.cfg.chainParams()

		config := neutrino.Config{
			DataDir:     s.cfg.Datadir,
			ChainParams: *netParams,
			Database:    db,
		}

		if len(initialPeer) > 0 {
			config.AddPeers = []string{initialPeer}
		}

		neutrino.UseLogger(logger("neutrino"))
		btcwallet.UseLogger(logger("btcwallet"))

		neutrinoSvc, err := neutrino.NewChainService(config)
		if err != nil {
			return err
		}

		chainSrc := chain.NewNeutrinoClient(netParams, neutrinoSvc)
		scanner := chain.NewNeutrinoClient(netParams, neutrinoSvc)

		esploraClient := &esploraClient{url: esploraURL}
		estimator, err := chainfee.NewWebAPIEstimator(esploraClient, true, 5*time.Minute, 20*time.Minute)
		if err != nil {
			return err
		}

		if err := withExtraAPI(esploraClient)(s); err != nil {
			return err
		}

		if err := withFeeEstimator(estimator)(s); err != nil {
			return err
		}

		if err := withChainSource(chainSrc)(s); err != nil {
			return err
		}
		return withScanner(scanner)(s)
	}
}

func WithPollingBitcoind(host, user, pass string) WalletOption {
	return func(s *service) error {
		netParams := s.cfg.chainParams()
		// Create a new bitcoind configuration
		bitcoindConfig := &chain.BitcoindConfig{
			ChainParams: netParams,
			Host:        host,
			User:        user,
			Pass:        pass,
			PollingConfig: &chain.PollingConfig{
				BlockPollingInterval:    10 * time.Second,
				TxPollingInterval:       5 * time.Second,
				TxPollingIntervalJitter: 0.1,
				RPCBatchSize:            20,
				RPCBatchInterval:        1 * time.Second,
			},
		}

		btcwallet.UseLogger(logger("btcwallet"))

		// Create the BitcoindConn first
		bitcoindConn, err := chain.NewBitcoindConn(bitcoindConfig)
		if err != nil {
			return fmt.Errorf("failed to create bitcoind connection: %w", err)
		}

		// Start the bitcoind connection
		if err := bitcoindConn.Start(); err != nil {
			return fmt.Errorf("failed to start bitcoind connection: %w", err)
		}

		// Now create the BitcoindClient using the connection
		chainClient := bitcoindConn.NewBitcoindClient()

		// Start the chain client
		if err := chainClient.Start(); err != nil {
			bitcoindConn.Stop()
			return fmt.Errorf("failed to start bitcoind client: %w", err)
		}

		// wait for bitcoind to sync
		for !chainClient.IsCurrent() {
			time.Sleep(1 * time.Second)
		}

		estimator, err := chainfee.NewBitcoindEstimator(
			rpcclient.ConnConfig{
				Host: bitcoindConfig.Host,
				User: bitcoindConfig.User,
				Pass: bitcoindConfig.Pass,
			},
			"ECONOMICAL",
			chainfee.AbsoluteFeePerKwFloor,
		)
		if err != nil {
			return fmt.Errorf("failed to create bitcoind fee estimator: %w", err)
		}

		if err := withExtraAPI(&bitcoindRPCClient{chainClient})(s); err != nil {
			return err
		}

		if err := withFeeEstimator(estimator)(s); err != nil {
			return err
		}

		// Set up the wallet as chain source and scanner
		if err := withChainSource(chainClient)(s); err != nil {
			chainClient.Stop()
			bitcoindConn.Stop()
			return fmt.Errorf("failed to set chain source: %w", err)
		}

		if err := withScanner(chainClient)(s); err != nil {
			chainClient.Stop()
			bitcoindConn.Stop()
			return fmt.Errorf("failed to set scanner: %w", err)
		}

		return nil
	}
}

func WithBitcoindZMQ(block, tx string, host, user, pass string) WalletOption {
	return func(s *service) error {
		if s.chainSource != nil {
			return fmt.Errorf("chain source already set")
		}

		bitcoindConfig := &chain.BitcoindConfig{
			ChainParams: s.cfg.chainParams(),
			Host:        host,
			User:        user,
			Pass:        pass,
			ZMQConfig: &chain.ZMQConfig{
				ZMQBlockHost:    block,
				ZMQTxHost:       tx,
				ZMQReadDeadline: 5 * time.Second,
			},
		}

		btcwallet.UseLogger(logger("btcwallet"))

		bitcoindConn, err := chain.NewBitcoindConn(bitcoindConfig)
		if err != nil {
			return fmt.Errorf("failed to create bitcoind connection: %w", err)
		}

		if err := bitcoindConn.Start(); err != nil {
			return fmt.Errorf("failed to start bitcoind connection: %w", err)
		}

		chainClient := bitcoindConn.NewBitcoindClient()

		if err := chainClient.Start(); err != nil {
			bitcoindConn.Stop()
			return fmt.Errorf("failed to start bitcoind client: %w", err)
		}

		for !chainClient.IsCurrent() {
			time.Sleep(1 * time.Second)
		}

		estimator, err := chainfee.NewBitcoindEstimator(
			rpcclient.ConnConfig{
				Host: bitcoindConfig.Host,
				User: bitcoindConfig.User,
				Pass: bitcoindConfig.Pass,
			},
			"ECONOMICAL",
			chainfee.AbsoluteFeePerKwFloor,
		)
		if err != nil {
			return fmt.Errorf("failed to create bitcoind fee estimator: %w", err)
		}

		if err := withExtraAPI(&bitcoindRPCClient{chainClient})(s); err != nil {
			return err
		}

		if err := withFeeEstimator(estimator)(s); err != nil {
			return err
		}

		if err := withChainSource(chainClient)(s); err != nil {
			chainClient.Stop()
			bitcoindConn.Stop()
			return fmt.Errorf("failed to set chain source: %w", err)
		}

		if err := withScanner(chainClient)(s); err != nil {
			chainClient.Stop()
			bitcoindConn.Stop()
			return fmt.Errorf("failed to set scanner: %w", err)
		}

		return nil
	}
}

func withChainSource(chainSource chain.Interface) WalletOption {
	return func(s *service) error {
		if s.chainSource != nil {
			return fmt.Errorf("chain source already set")
		}

		s.chainSource = chainSource
		return nil
	}
}

func withScanner(chainSource chain.Interface) WalletOption {
	return func(s *service) error {
		if s.scanner != nil {
			return fmt.Errorf("scanner already set")
		}
		if err := chainSource.Start(); err != nil {
			return fmt.Errorf("failed to start scanner: %s", err)
		}
		s.scanner = chainSource
		return nil
	}
}

func withExtraAPI(api extraChainAPI) WalletOption {
	return func(s *service) error {
		if s.extraAPI != nil {
			return fmt.Errorf("extra chain API already set")
		}
		s.extraAPI = api
		return nil
	}
}

func withFeeEstimator(estimator chainfee.Estimator) WalletOption {
	return func(s *service) error {
		if s.feeEstimator != nil {
			return fmt.Errorf("fee estimator already set")
		}

		if err := estimator.Start(); err != nil {
			return fmt.Errorf("failed to start fee estimator: %s", err)
		}

		s.feeEstimator = estimator
		return nil
	}
}
