package grpcservice

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/arkade-os/arkd/internal/interface/grpc/permissions"
	"github.com/arkade-os/arkd/pkg/macaroons"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	adminMacaroonFile   = "admin.macaroon"
	walletMacaroonFile  = "wallet.macaroon"
	managerMacaroonFile = "manager.macaroon"
	roMacaroonFile      = "readonly.macaroon"

	macFiles = map[string][]bakery.Op{
		adminMacaroonFile:   permissions.AdminPermissions(),
		walletMacaroonFile:  permissions.WalletPermissions(),
		managerMacaroonFile: permissions.ManagerPermissions(),
		roMacaroonFile:      permissions.ReadOnlyPermissions(),
	}
)

// genMacaroons generates four macaroon files; one admin-level, one for
// updating the strategy of a market, one for updating its price  and one
// read-only. Admin and read-only can also be used to generate more granular
// macaroons.
func genMacaroons(
	ctx context.Context, svc *macaroons.Service, datadir string,
) (bool, error) {
	adminMacFile := filepath.Join(datadir, adminMacaroonFile)
	walletMacFile := filepath.Join(datadir, walletMacaroonFile)
	managerMacFile := filepath.Join(datadir, managerMacaroonFile)
	roMacFile := filepath.Join(datadir, roMacaroonFile)
	if pathExists(adminMacFile) || pathExists(walletMacFile) ||
		pathExists(managerMacFile) || pathExists(roMacFile) {
		return false, nil
	}

	// Let's create the datadir if it doesn't exist.
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return false, err
	}

	for macFilename, macPermissions := range macFiles {
		mktMacBytes, err := svc.BakeMacaroon(ctx, macPermissions)
		if err != nil {
			return false, err
		}
		macFile := filepath.Join(datadir, macFilename)
		perms := fs.FileMode(0644)
		if macFilename == adminMacaroonFile {
			perms = 0600
		}
		if err := os.WriteFile(macFile, mktMacBytes, perms); err != nil {
			// nolint:all
			os.Remove(macFile)
			return false, err
		}
	}

	return true, nil
}

func makeDirectoryIfNotExists(path string) error {
	if pathExists(path) {
		return nil
	}
	return os.MkdirAll(path, os.ModeDir|0755)
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
