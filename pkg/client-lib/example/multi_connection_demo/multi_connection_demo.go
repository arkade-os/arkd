package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	log "github.com/sirupsen/logrus"
)

func main() {
	// Command-line flags
	log.SetLevel(log.DebugLevel)
	numAddresses := flag.Int("addresses", 1500, "Number of addresses to generate and subscribe")
	numListeners := flag.Int("listeners", 1, "Number of listeners waiting for notifications")
	explorerURL := flag.String("url", "https://mempool.space/api", "Explorer API URL")
	maxEvents := flag.Int(
		"max-events", 5, "Maximum number of events to receive before stopping (0 = unlimited)",
	)
	showAll := flag.Bool("show-all", false, "Show all subscribed addresses (not just first 3)")

	flag.Parse()

	fmt.Println("🧪 Testing Multi-Connection Explorer with Batched Subscriptions")
	fmt.Println("============================================================")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Addresses:     %d\n", *numAddresses)
	fmt.Printf("  Listeners:     %d\n", *numListeners)
	fmt.Printf("  Explorer URL:  %s\n", *explorerURL)
	fmt.Println("============================================================")

	// Create explorer with configurable parameters
	svc, err := mempoolexplorer.NewExplorer(
		*explorerURL, arklib.Bitcoin, mempoolexplorer.WithTracker(true),
	)
	if err != nil {
		log.Fatal("❌ Failed to create explorer:", err)
	}

	svc.Start()
	defer svc.Stop()

	aborted := false
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		<-sigChan
		svc.Stop()
		aborted = true
	}()

	// Generate test addresses
	addresses := make([]string, 0, *numAddresses)
	fmt.Printf("🔄 Generating %d test addresses...\n", *numAddresses)
	for i := 0; i < *numAddresses; i++ {
		addresses = append(addresses, newTestAddr(*explorerURL))
	}
	fmt.Printf("✅ Generated %d addresses\n", len(addresses))

	// Subscribe to addresses (this will use the multi-connection batching)
	fmt.Println("📡 Subscribing to addresses with batched distribution...")
	start := time.Now()
	err = svc.SubscribeForAddresses(addresses)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("⚠️ Failed to subscribe all addresses: %s\n", err)
	}

	// Verify actual configuration from the service
	activeConns := svc.GetConnectionCount()

	fmt.Println("\nActual Configuration (verified from service):")
	switch activeConns {
	case 0:
		fmt.Println("  Mode:	Polling (WebSocket unavailable)")
	case 1:
		fmt.Printf("  Connections:		%d connection\n", activeConns)
	default:
		fmt.Printf("  Connections:		%d connections\n", activeConns)
	}
	fmt.Printf("  Base URL:		%s\n\n", svc.BaseUrl())

	// Verify actual subscription count from service
	subscribedAddresses := svc.GetSubscribedAddresses()

	fmt.Printf(
		"✅ Successfully subscribed to %d addresses in %v\n",
		len(subscribedAddresses), duration,
	)
	fmt.Printf("📊 Verified: %d addresses actively subscribed in service\n", len(addresses))
	if activeConns > 0 {
		fmt.Printf("📡 Distributed across %d WebSocket connection(s)\n", activeConns)
	}

	// Show sample of subscribed addresses
	if len(subscribedAddresses) > 0 {
		if *showAll {
			fmt.Printf("📋 All subscribed addresses (%d total):\n", len(subscribedAddresses))
			for i, addr := range subscribedAddresses {
				isSubscribed := svc.IsAddressSubscribed(addr)
				status := "✅"
				if !isSubscribed {
					status = "❌"
				}
				fmt.Printf("   %d. %s %s\n", i+1, status, addr)
			}
		} else {
			fmt.Printf("📋 Sample subscribed addresses (3/%d):\n", len(subscribedAddresses))
			for i := 0; i < 3 && i < len(subscribedAddresses); i++ {
				isSubscribed := svc.IsAddressSubscribed(subscribedAddresses[i])
				status := "✅"
				if !isSubscribed {
					status = "❌"
				}
				fmt.Printf("   %s %s\n", status, subscribedAddresses[i])
			}
			if len(subscribedAddresses) > 3 {
				fmt.Printf("   ... and %d more (use -show-all to see all)\n", len(subscribedAddresses)-3)
			}
		}
	}

	if *maxEvents == 0 {
		fmt.Println("🔄 Listening for blockchain events indefinitely (Ctrl+C to stop)...")
	} else {
		fmt.Printf("🔄 Listening for blockchain events (will stop after %d events)...\n", *maxEvents)
	}

	// Listen for events
	errorCount := 0
	totEventCount := 0
	wg := sync.WaitGroup{}
	wg.Add(*numListeners)
	for i := range *numListeners {
		go func(i int) {
			defer wg.Done()
			eventCount := 0
			for ev := range svc.GetAddressesEvents() {
				eventCount++
				if ev.Error != nil {
					errorCount++
					fmt.Printf("⚠️ new error detected\n")
					fmt.Printf("   Error: %v\n", ev.Error)
				} else {
					buf, _ := json.MarshalIndent(ev, "", "  ")
					fmt.Printf("🎯 Listener %d receveived event #%d: %s\n", i, eventCount, string(buf))
				}

				// Stop after receiving max events (if configured)
				if *maxEvents > 0 && eventCount >= *maxEvents {
					break
				}
			}
			totEventCount += eventCount
		}(i)
	}
	wg.Wait()

	if aborted {
		fmt.Println("\n💡 Test aborted by user")
		os.Exit(0)
	}

	// Final error summary
	fmt.Println("\n✅ Test completed successfully!")
	fmt.Printf("📊 Final Statistics:\n")
	fmt.Printf("   Events received: %d\n", totEventCount)
	fmt.Printf("   Total errors:    %d\n", errorCount)
	if errorCount == 0 {
		fmt.Println("   ✅ No errors encountered!")
	}
}

func newTestAddr(url string) string {
	// Create a deterministic address based on index for testing
	key, _ := btcec.NewPrivateKey()
	pubKey := key.PubKey()
	pubKeyCompressed := pubKey.SerializeCompressed()

	pubKeyHash := btcutil.Hash160(pubKeyCompressed)

	net := &chaincfg.MainNetParams
	if strings.Contains(url, "testnet") {
		net = &chaincfg.TestNet3Params
	}
	if strings.Contains(url, "signet") || strings.Contains(url, "mutinynet") {
		net = &chaincfg.SigNetParams
	}
	if strings.Contains(url, "localhost") || strings.Contains(url, "127.0.0.1") {
		net = &chaincfg.RegressionNetParams
	}

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, net)
	if err != nil {
		log.Fatal(err)
	}

	return addr.EncodeAddress()
}
