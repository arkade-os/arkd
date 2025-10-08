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
	superAdminMacaroonFile = "superadmin.macaroon"
	adminMacaroonFile      = "admin.macaroon"
	operatorMacaroonFile   = "operator.macaroon"
	unlockerMacaroonFile   = "unlocker.macaroon"
	roMacaroonFile         = "readonly.macaroon"

	macFiles = map[string][]bakery.Op{
		superAdminMacaroonFile: permissions.SuperAdminPermissions(),
		adminMacaroonFile:      permissions.AdminPermissions(),
		operatorMacaroonFile:   permissions.OperatorPermissions(),
		unlockerMacaroonFile:   permissions.UnlockerPermissions(),
		roMacaroonFile:         permissions.ReadOnlyPermissions(),
	}
)

// genMacaroons generates the macaroon files if they don't already exist.
func genMacaroons(
	ctx context.Context, svc *macaroons.Service, datadir string,
) (bool, error) {
	// Check the macaroons to (re-)generate.
	macaroonsToGenerate := make(map[string][]bakery.Op)
	for filename, ops := range macFiles {
		if pathExists(filepath.Join(datadir, filename)) {
			continue
		}
		macaroonsToGenerate[filename] = ops
	}

	// Don't do anything if all macaroons already exist.
	if len(macaroonsToGenerate) == 0 {
		return false, nil
	}

	// Create the datadir if it doesn't exist.
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return false, err
	}

	// Create the macaroon files.
	for macFilename, macPermissions := range macaroonsToGenerate {
		mktMacBytes, err := svc.BakeMacaroon(ctx, macPermissions, macFilename)
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
