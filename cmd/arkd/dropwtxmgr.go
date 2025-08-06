/*
This is a copy of the dropwtxmgr tool from the btcwallet repo.
(https://github.com/btcsuite/btcwallet/blob/master/cmd/dropwtxmgr/main.go)
It is used to drop the wtxmgr database in case you want to force a rescan.

You can run it with:
	arkd wallet dropwtxmgr --datadir /path/to/arkd/data/wallet.db

Once Tx history is deleted, the rescan will automatically start on the next unlock.

See: https://github.com/btcsuite/btcwallet/blob/master/docs/force_rescans.md
*/

package main

import (
	"fmt"
	"os"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

func dropWtxmgr(dbPath string) int {
	fmt.Println("Database path:", dbPath)
	_, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		fmt.Println("Database file does not exist")
		return 1
	}

	db, err := walletdb.Open("bdb", dbPath, true, wallet.DefaultDBTimeout)
	if err != nil {
		fmt.Println("Failed to open database:", err)
		return 1
	}
	// nolint:errcheck
	defer db.Close()

	fmt.Println("Dropping btcwallet transaction history")

	err = wallet.DropTransactionHistory(db, true)
	if err != nil {
		fmt.Println("Failed to drop and re-create namespace:", err)
		return 1
	}

	return 0
}
