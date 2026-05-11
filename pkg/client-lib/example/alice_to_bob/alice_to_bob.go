package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	wallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/store"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
)

var (
	serverUrl    = "127.0.0.1:7070"
	explorerUrl  = "http://127.0.0.1:3000"
	password     = "password"
	identityType = wallet.SingleKeyIdentity
)

func main() {
	var (
		ctx = context.Background()
		err error

		alice wallet.Wallet
		bob   wallet.Wallet
	)
	defer func() {
		if alice != nil {
			alice.Stop()
		}

		if bob != nil {
			bob.Stop()
		}
	}()

	log.Info("alice is setting up her wallet...")

	alice, err = setupArkClient()
	if err != nil {
		log.Fatal(err)
	}

	if err := alice.Unlock(ctx, password); err != nil {
		log.Fatal(err)
	}
	//nolint:all
	defer alice.Lock(ctx)

	log.Info("alice is acquiring onchain funds...")
	_, _, boardingAddr, err := alice.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := runCommand("nigiri", "faucet", boardingAddr.Address); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	onboardAmount := uint64(1_0000_0000) // 1 BTC
	log.Infof("alice is onboarding with %d sats offchain...", onboardAmount)

	aliceBalance, err := alice.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	log.Infof("alice is settling the onboard funds...")
	res, err := alice.Settle(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice settled the onboard funds in commitment tx %s", res.CommitmentTxid)

	fmt.Println("")
	log.Info("bob is setting up his wallet...")
	bob, err = setupArkClient()
	if err != nil {
		log.Fatal(err)
	}

	if err := bob.Unlock(ctx, password); err != nil {
		log.Fatal(err)
	}
	//nolint:all
	defer bob.Lock(ctx)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	bobBalance, err := bob.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob onchain balance: %d", bobBalance.OnchainBalance.SpendableAmount)
	log.Infof("bob offchain balance: %d", bobBalance.OffchainBalance.Total)

	amount := uint64(1000)
	receivers := []types.Receiver{{To: bobOffchainAddr.Address, Amount: amount}}

	fmt.Println("")
	log.Infof("alice is sending %d sats to bob offchain...", amount)

	if _, err = alice.SendOffChain(ctx, receivers); err != nil {
		log.Fatal(err)
	}

	log.Info("transaction completed")

	if err := generateBlock(); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	aliceBalance, err = alice.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	log.Infof("alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	bobBalance, err = bob.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob onchain balance: %d", bobBalance.OnchainBalance.SpendableAmount)
	log.Infof("bob offchain balance: %d", bobBalance.OffchainBalance.Total)

	fmt.Println("")
	log.Info("bob is settling the received funds...")
	res, err = bob.Settle(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob settled the received funds in commitment tx %s", res.CommitmentTxid)
}

func setupArkClient() (wallet.Wallet, error) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to setup app data store: %s", err)
	}

	client, err := wallet.NewWallet(appDataStore, wallet.WithVerbose())
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), wallet.InitArgs{
		ServerUrl:   serverUrl,
		Password:    password,
		ExplorerURL: explorerUrl,
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize wallet: %s", err)
	}

	return client, nil
}

func runCommand(name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := newCommand(name, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}
	output := new(strings.Builder)
	errorb := new(strings.Builder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(output, stdout); err != nil {
			fmt.Fprintf(errb, "error reading stdout: %s", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(errorb, stderr); err != nil {
			fmt.Fprintf(errb, "error reading stderr: %s", err)
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if errMsg := errorb.String(); len(errMsg) > 0 {
			return "", fmt.Errorf("%s", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("%s", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("%s", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}

func generateBlock() error {
	if _, err := runCommand("nigiri", "rpc", "generatetoaddress", "1", "bcrt1qgqsguk6wax7ynvav4zys5x290xftk49h5agg0l"); err != nil {
		return err
	}

	time.Sleep(6 * time.Second)
	return nil
}
