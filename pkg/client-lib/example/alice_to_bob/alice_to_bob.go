package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	arksdk "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/store"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
)

var (
	serverUrl  = "127.0.0.1:7070"
	clientType = arksdk.GrpcClient
	password   = "password"
	walletType = arksdk.SingleKeyWallet
)

func main() {
	var (
		ctx = context.Background()
		err error

		aliceArkClient arksdk.ArkClient
		bobArkClient   arksdk.ArkClient
	)
	defer func() {
		if aliceArkClient != nil {
			aliceArkClient.Stop()
		}

		if bobArkClient != nil {
			bobArkClient.Stop()
		}
	}()

	log.Info("alice is setting up her ark wallet...")

	aliceArkClient, err = setupArkClient()
	if err != nil {
		log.Fatal(err)
	}

	if err := aliceArkClient.Unlock(ctx, password); err != nil {
		log.Fatal(err)
	}
	//nolint:all
	defer aliceArkClient.Lock(ctx)

	log.Info("alice is acquiring onchain funds...")
	_, _, boardingAddress, err := aliceArkClient.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := runCommand("nigiri", "faucet", boardingAddress); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	onboardAmount := uint64(1_0000_0000) // 1 BTC
	log.Infof("alice is onboarding with %d sats offchain...", onboardAmount)

	aliceBalance, err := aliceArkClient.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	log.Infof("alice is settling the onboard funds...")
	txid, err := aliceArkClient.Settle(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice settled the onboard funds in commitment tx %s", txid)

	fmt.Println("")
	log.Info("bob is setting up his ark wallet...")
	bobArkClient, err = setupArkClient()
	if err != nil {
		log.Fatal(err)
	}

	if err := bobArkClient.Unlock(ctx, password); err != nil {
		log.Fatal(err)
	}
	//nolint:all
	defer bobArkClient.Lock(ctx)

	_, bobOffchainAddr, _, err := bobArkClient.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	bobBalance, err := bobArkClient.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob onchain balance: %d", bobBalance.OnchainBalance.SpendableAmount)
	log.Infof("bob offchain balance: %d", bobBalance.OffchainBalance.Total)

	amount := uint64(1000)
	receivers := []types.Receiver{{To: bobOffchainAddr, Amount: amount}}

	fmt.Println("")
	log.Infof("alice is sending %d sats to bob offchain...", amount)

	if _, err = aliceArkClient.SendOffChain(ctx, receivers); err != nil {
		log.Fatal(err)
	}

	log.Info("transaction completed")

	if err := generateBlock(); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	aliceBalance, err = aliceArkClient.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	log.Infof("alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	bobBalance, err = bobArkClient.Balance(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob onchain balance: %d", bobBalance.OnchainBalance.SpendableAmount)
	log.Infof("bob offchain balance: %d", bobBalance.OffchainBalance.Total)

	fmt.Println("")
	log.Info("bob is settling the received funds...")
	commitmentTxid, err := bobArkClient.Settle(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob settled the received funds in commitment tx %s", commitmentTxid)

	time.Sleep(500 * time.Second)
}

func setupArkClient() (arksdk.ArkClient, error) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to setup app data store: %s", err)
	}

	client, err := arksdk.NewArkClient(appDataStore)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), arksdk.InitArgs{
		WalletType: walletType,
		ClientType: clientType,
		ServerUrl:  serverUrl,
		Password:   password,
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
